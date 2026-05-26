package com.kafkaoauth;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.kafkaoauth.authorizer.ClaimStore;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerExtensionsValidatorCallback;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerValidatorCallback;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.net.URL;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.stream.Collectors;

/**
 * Kafka SASL/OAUTHBEARER validator callback handler.
 *
 * <p>Validates incoming JWT bearer tokens from Kafka clients by:
 * <ol>
 *   <li>Fetching the JWKS (JSON Web Key Set) from the Keycloak JWKS endpoint.</li>
 *   <li>Verifying the JWT signature using the appropriate public key.</li>
 *   <li>Checking token expiry, issuer and audience claims.</li>
 *   <li>Extracting tenant claims and storing them in {@link ClaimStore} for the authorizer.</li>
 * </ol>
 *
 * <p>JAAS options:
 * <ul>
 *   <li>{@code oauth.jwks.endpoint.uri} - Keycloak JWKS endpoint URL</li>
 *   <li>{@code oauth.valid.issuer.uri} - Expected token issuer (must match {@code iss} claim)</li>
 *   <li>{@code oauth.username.claim} - Claim used as Kafka principal name (default: {@code sub})</li>
 * </ul>
 */
public class OAuthBearerValidatorCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthBearerValidatorCallbackHandler.class);

    private static final String OPTION_JWKS_ENDPOINT = "oauth.jwks.endpoint.uri";
    private static final String OPTION_VALID_ISSUER = "oauth.valid.issuer.uri";
    private static final String OPTION_USERNAME_CLAIM = "oauth.username.claim";

    private static final String DEFAULT_USERNAME_CLAIM = "sub";
    private static final String EXPECTED_AUDIENCE = "kafka-broker";
    private static final long JWKS_REFRESH_INTERVAL_MINUTES = 5L;

    private String jwksEndpointUri;
    private String validIssuerUri;
    private String usernameClaim;

    /** Cached JWK set, protected by {@link #jwksLock}. */
    private JWKSet jwkSet;
    private long jwkSetLastLoadedMs = 0L;

    private final ReadWriteLock jwksLock = new ReentrantReadWriteLock();
    private ScheduledExecutorService jwksRefreshExecutor;
    private ScheduledFuture<?> jwksRefreshFuture;

    // -------------------------------------------------------------------------
    // AuthenticateCallbackHandler lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void configure(Map<String, ?> configs,
                          String saslMechanism,
                          List<AppConfigurationEntry> jaasConfigEntries) {
        if (jaasConfigEntries == null || jaasConfigEntries.isEmpty()) {
            throw new IllegalArgumentException(
                    "OAuthBearerValidatorCallbackHandler requires at least one JAAS config entry");
        }

        Map<String, ?> options = jaasConfigEntries.stream()
                .flatMap(e -> e.getOptions().entrySet().stream())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> b));

        jwksEndpointUri = requiredOption(options, OPTION_JWKS_ENDPOINT);
        validIssuerUri = requiredOption(options, OPTION_VALID_ISSUER);
        usernameClaim = optionalOption(options, OPTION_USERNAME_CLAIM, DEFAULT_USERNAME_CLAIM);

        // Perform initial JWKS load eagerly so we fail fast on misconfiguration
        try {
            refreshJwkSet();
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load JWKS from " + jwksEndpointUri + " during startup", e);
        }

        // Schedule background JWKS refresh
        jwksRefreshExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "kafka-jwks-refresh");
            t.setDaemon(true);
            return t;
        });
        jwksRefreshFuture = jwksRefreshExecutor.scheduleAtFixedRate(
                this::refreshJwkSetQuietly,
                JWKS_REFRESH_INTERVAL_MINUTES,
                JWKS_REFRESH_INTERVAL_MINUTES,
                TimeUnit.MINUTES);

        log.info("OAuthBearerValidatorCallbackHandler configured: jwksUri={}, validIssuer={}, usernameClaim={}",
                jwksEndpointUri, validIssuerUri, usernameClaim);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerValidatorCallback validatorCallback) {
                handleValidatorCallback(validatorCallback);
            } else if (callback instanceof OAuthBearerExtensionsValidatorCallback) {
                // Extensions are not used; no-op (Kafka skips validation when nothing is marked invalid)
            } else {
                throw new UnsupportedCallbackException(callback,
                        "Unsupported callback type: " + callback.getClass().getName());
            }
        }
    }

    @Override
    public void close() {
        if (jwksRefreshFuture != null) {
            jwksRefreshFuture.cancel(false);
        }
        if (jwksRefreshExecutor != null) {
            jwksRefreshExecutor.shutdown();
            try {
                if (!jwksRefreshExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    jwksRefreshExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                jwksRefreshExecutor.shutdownNow();
            }
        }
        log.info("OAuthBearerValidatorCallbackHandler closed");
    }

    // -------------------------------------------------------------------------
    // Validation logic
    // -------------------------------------------------------------------------

    private void handleValidatorCallback(OAuthBearerValidatorCallback callback) {
        String tokenValue = callback.tokenValue();
        if (tokenValue == null || tokenValue.isBlank()) {
            callback.error("invalid_token", "Empty token value", null);
            return;
        }

        try {
            ValidatedToken validated = validateToken(tokenValue);
            callback.token(validated.oauthToken);
            log.debug("Token validation succeeded for principal={}", validated.oauthToken.principalName());
        } catch (TokenValidationException e) {
            log.warn("Token validation failed: {}", e.getMessage());
            callback.error(e.errorCode, e.getMessage(), null);
        } catch (Exception e) {
            log.error("Unexpected error during token validation", e);
            callback.error("server_error", "Internal validation error: " + e.getMessage(), null);
        }
    }

    /**
     * Validates the raw JWT string and returns a {@link ValidatedToken} on success.
     *
     * @param tokenValue raw JWT string
     * @return validated token with parsed claims
     * @throws TokenValidationException if validation fails for any reason
     */
    private ValidatedToken validateToken(String tokenValue) throws TokenValidationException {
        // 1. Parse as signed JWT
        SignedJWT signedJWT;
        try {
            signedJWT = SignedJWT.parse(tokenValue);
        } catch (ParseException e) {
            throw new TokenValidationException("invalid_token",
                    "Failed to parse JWT: " + e.getMessage());
        }

        // 2. Verify signature using cached JWKS
        verifySignature(signedJWT);

        // 3. Extract and validate claims
        JWTClaimsSet claims;
        try {
            claims = signedJWT.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new TokenValidationException("invalid_token",
                    "Failed to parse JWT claims: " + e.getMessage());
        }

        validateClaims(claims);

        // 4. Extract principal from configured claim
        String principal = extractStringClaim(claims, usernameClaim);
        if (principal == null || principal.isBlank()) {
            throw new TokenValidationException("invalid_token",
                    "JWT missing required claim: " + usernameClaim);
        }

        // 5. Build scope set from "scope" claim
        String scopeStr = extractStringClaim(claims, "scope");
        Set<String> scopes = (scopeStr != null && !scopeStr.isBlank())
                ? Set.of(scopeStr.split("\\s+"))
                : Collections.emptySet();

        long lifetimeMs = claims.getExpirationTime().getTime();
        Date issuedAt = claims.getIssueTime();
        long startTimeMs = (issuedAt != null) ? issuedAt.getTime() : System.currentTimeMillis();

        OAuthBearerLoginCallbackHandler.KafkaOAuthBearerToken oauthToken =
                new OAuthBearerLoginCallbackHandler.KafkaOAuthBearerToken(
                        tokenValue, principal, lifetimeMs, scopes, startTimeMs);

        // 6. Extract and store extended claims for the authorizer
        Map<String, Object> claimMap = extractClaimsForAuthorizer(claims, principal);
        ClaimStore.put(principal, claimMap);

        return new ValidatedToken(oauthToken, claimMap);
    }

    /**
     * Verifies the JWT signature against all keys in the cached JWK set.
     * Falls back to a fresh JWK set fetch if no matching key is found.
     */
    private void verifySignature(SignedJWT signedJWT) throws TokenValidationException {
        String keyId = signedJWT.getHeader().getKeyID();
        List<JWK> candidates = getCandidateKeys(keyId, false);

        if (!tryVerify(signedJWT, candidates)) {
            // JWKS might be stale; force a refresh and try again
            log.debug("Signature verification failed with cached JWKS, attempting refresh");
            try {
                refreshJwkSet();
            } catch (Exception e) {
                throw new TokenValidationException("invalid_token",
                        "Signature verification failed and JWKS refresh failed: " + e.getMessage());
            }
            candidates = getCandidateKeys(keyId, true);
            if (!tryVerify(signedJWT, candidates)) {
                throw new TokenValidationException("invalid_token",
                        "JWT signature verification failed – no matching key found in JWKS");
            }
        }
    }

    private List<JWK> getCandidateKeys(String keyId, boolean forceWrite) {
        jwksLock.readLock().lock();
        try {
            if (jwkSet == null) {
                return Collections.emptyList();
            }
            if (keyId != null) {
                JWK specific = jwkSet.getKeyByKeyId(keyId);
                return specific != null ? List.of(specific) : Collections.emptyList();
            }
            return new ArrayList<>(jwkSet.getKeys());
        } finally {
            jwksLock.readLock().unlock();
        }
    }

    private boolean tryVerify(SignedJWT signedJWT, List<JWK> candidates) {
        for (JWK jwk : candidates) {
            try {
                JWSVerifier verifier = buildVerifier(jwk);
                if (verifier != null && signedJWT.verify(verifier)) {
                    log.debug("JWT signature verified with key id={}", jwk.getKeyID());
                    return true;
                }
            } catch (Exception e) {
                log.trace("Failed to verify with key id={}: {}", jwk.getKeyID(), e.getMessage());
            }
        }
        return false;
    }

    private JWSVerifier buildVerifier(JWK jwk) throws Exception {
        if (jwk.getKeyType() == KeyType.RSA) {
            RSAPublicKey rsaPublicKey = ((RSAKey) jwk).toRSAPublicKey();
            return new RSASSAVerifier(rsaPublicKey);
        } else if (jwk.getKeyType() == KeyType.EC) {
            ECPublicKey ecPublicKey = ((ECKey) jwk).toECPublicKey();
            return new ECDSAVerifier(ecPublicKey);
        }
        log.warn("Unsupported JWK key type: {}", jwk.getKeyType());
        return null;
    }

    /**
     * Validates the standard JWT claims: expiry, issuer, and audience.
     */
    private void validateClaims(JWTClaimsSet claims) throws TokenValidationException {
        // Check expiry
        Date expiry = claims.getExpirationTime();
        if (expiry == null) {
            throw new TokenValidationException("invalid_token", "JWT missing 'exp' claim");
        }
        if (expiry.before(new Date())) {
            throw new TokenValidationException("invalid_token",
                    "JWT has expired at " + expiry);
        }

        // Check issuer
        String issuer = claims.getIssuer();
        if (issuer == null || !issuer.equals(validIssuerUri)) {
            throw new TokenValidationException("invalid_token",
                    String.format("JWT issuer mismatch: expected='%s', actual='%s'",
                            validIssuerUri, issuer));
        }

        // Check audience contains "kafka-broker"
        List<String> audience = claims.getAudience();
        if (audience == null || !audience.contains(EXPECTED_AUDIENCE)) {
            throw new TokenValidationException("invalid_token",
                    String.format("JWT audience does not contain '%s': %s",
                            EXPECTED_AUDIENCE, audience));
        }
    }

    /**
     * Extracts all claims relevant to the authorizer into a plain map.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> extractClaimsForAuthorizer(JWTClaimsSet claims, String principal) {
        Map<String, Object> claimMap = new HashMap<>();
        claimMap.put("sub", principal);

        // tenant_id
        String tenantId = extractStringClaim(claims, "tenant_id");
        if (tenantId != null) {
            claimMap.put("tenant_id", tenantId);
        }

        // roles (array of strings)
        Object rolesObj = claims.getClaim("roles");
        if (rolesObj instanceof List<?> rolesList) {
            claimMap.put("roles", rolesList.stream()
                    .filter(r -> r instanceof String)
                    .map(Object::toString)
                    .collect(Collectors.toList()));
        } else {
            claimMap.put("roles", Collections.emptyList());
        }

        // kafka_scopes (array of strings)
        Object scopesObj = claims.getClaim("kafka_scopes");
        if (scopesObj instanceof List<?> scopesList) {
            claimMap.put("kafka_scopes", scopesList.stream()
                    .filter(s -> s instanceof String)
                    .map(Object::toString)
                    .collect(Collectors.toList()));
        } else {
            claimMap.put("kafka_scopes", Collections.emptyList());
        }

        // Preserve issuer and audience for audit/debug
        claimMap.put("iss", claims.getIssuer());
        if (claims.getExpirationTime() != null) {
            claimMap.put("exp", claims.getExpirationTime().getTime());
        }

        return Collections.unmodifiableMap(claimMap);
    }

    private String extractStringClaim(JWTClaimsSet claims, String claimName) {
        Object value = claims.getClaim(claimName);
        return (value instanceof String s) ? s : null;
    }

    // -------------------------------------------------------------------------
    // JWKS management
    // -------------------------------------------------------------------------

    private void refreshJwkSet() throws Exception {
        log.debug("Refreshing JWKS from {}", jwksEndpointUri);
        JWKSet fresh = JWKSet.load(new URL(jwksEndpointUri));

        jwksLock.writeLock().lock();
        try {
            jwkSet = fresh;
            jwkSetLastLoadedMs = System.currentTimeMillis();
        } finally {
            jwksLock.writeLock().unlock();
        }
        log.info("JWKS refreshed successfully, keyCount={}", fresh.getKeys().size());
    }

    private void refreshJwkSetQuietly() {
        try {
            refreshJwkSet();
        } catch (Exception e) {
            log.warn("Background JWKS refresh failed (will retry in {} min): {}",
                    JWKS_REFRESH_INTERVAL_MINUTES, e.getMessage());
        }
    }

    // -------------------------------------------------------------------------
    // Utility
    // -------------------------------------------------------------------------

    private static String requiredOption(Map<String, ?> options, String key) {
        Object value = options.get(key);
        if (value == null || value.toString().isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required JAAS config option: " + key);
        }
        return value.toString().trim();
    }

    private static String optionalOption(Map<String, ?> options, String key, String defaultValue) {
        Object value = options.get(key);
        return (value != null && !value.toString().isBlank()) ? value.toString().trim() : defaultValue;
    }

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /** Wrapper pairing a ready-to-use {@link OAuthBearerToken} with its raw claim map. */
    private record ValidatedToken(OAuthBearerLoginCallbackHandler.KafkaOAuthBearerToken oauthToken,
                                  Map<String, Object> claims) {}

    /** Checked exception carrying an OAuth2 error code alongside the human-readable message. */
    private static final class TokenValidationException extends Exception {
        final String errorCode;

        TokenValidationException(String errorCode, String message) {
            super(message);
            this.errorCode = Objects.requireNonNull(errorCode);
        }
    }
}
