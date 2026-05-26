package com.kafkaoauth;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.kafka.common.security.auth.AuthenticateCallbackHandler;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerToken;
import org.apache.kafka.common.security.oauthbearer.OAuthBearerTokenCallback;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.AppConfigurationEntry;
import java.io.IOException;
import java.text.ParseException;
import java.time.Duration;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

/**
 * Kafka SASL/OAUTHBEARER login callback handler that fetches OAuth2 tokens
 * from Keycloak using the client credentials grant flow.
 *
 * <p>Used for inter-broker authentication. Configured via JAAS options:
 * <ul>
 *   <li>{@code oauth.token.endpoint.uri} - Keycloak token endpoint URL</li>
 *   <li>{@code oauth.client.id} - OAuth2 client identifier</li>
 *   <li>{@code oauth.client.secret} - OAuth2 client secret</li>
 * </ul>
 *
 * <p>Tokens are cached and automatically refreshed 30 seconds before expiry.
 */
public class OAuthBearerLoginCallbackHandler implements AuthenticateCallbackHandler {

    private static final Logger log = LoggerFactory.getLogger(OAuthBearerLoginCallbackHandler.class);

    private static final String OPTION_TOKEN_ENDPOINT = "oauth.token.endpoint.uri";
    private static final String OPTION_CLIENT_ID = "oauth.client.id";
    private static final String OPTION_CLIENT_SECRET = "oauth.client.secret";

    /** Refresh the token this many seconds before actual expiry to avoid clock skew issues. */
    private static final long TOKEN_REFRESH_BUFFER_SECONDS = 30L;

    private String tokenEndpointUri;
    private String clientId;
    private String clientSecret;

    private OkHttpClient httpClient;

    /**
     * Cached token container holding the raw JWT string and its parsed representation.
     */
    private final AtomicReference<CachedToken> cachedToken = new AtomicReference<>();

    // -------------------------------------------------------------------------
    // AuthenticateCallbackHandler lifecycle
    // -------------------------------------------------------------------------

    @Override
    public void configure(Map<String, ?> configs,
                          String saslMechanism,
                          List<AppConfigurationEntry> jaasConfigEntries) {
        if (jaasConfigEntries == null || jaasConfigEntries.isEmpty()) {
            throw new IllegalArgumentException(
                    "OAuthBearerLoginCallbackHandler requires at least one JAAS config entry");
        }

        // Collect all JAAS options from all entries (last value wins for duplicates)
        Map<String, ?> options = jaasConfigEntries.stream()
                .flatMap(e -> e.getOptions().entrySet().stream())
                .collect(Collectors.toMap(
                        Map.Entry::getKey,
                        Map.Entry::getValue,
                        (a, b) -> b));

        tokenEndpointUri = requiredOption(options, OPTION_TOKEN_ENDPOINT);
        clientId = requiredOption(options, OPTION_CLIENT_ID);
        clientSecret = requiredOption(options, OPTION_CLIENT_SECRET);

        httpClient = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(15, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build();

        log.info("OAuthBearerLoginCallbackHandler configured: tokenEndpoint={}, clientId={}",
                tokenEndpointUri, clientId);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof OAuthBearerTokenCallback oauthCallback) {
                handleTokenCallback(oauthCallback);
            } else {
                throw new UnsupportedCallbackException(callback,
                        "Unsupported callback type: " + callback.getClass().getName());
            }
        }
    }

    @Override
    public void close() {
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        cachedToken.set(null);
        log.info("OAuthBearerLoginCallbackHandler closed");
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private void handleTokenCallback(OAuthBearerTokenCallback callback) throws IOException {
        OAuthBearerToken token = getOrRefreshToken();
        callback.token(token);
        log.debug("Provided OAuth bearer token for principal={}", token.principalName());
    }

    /**
     * Returns a valid cached token or fetches a fresh one from Keycloak.
     *
     * @return a valid {@link OAuthBearerToken}
     * @throws IOException if the token endpoint cannot be reached or returns an error
     */
    private OAuthBearerToken getOrRefreshToken() throws IOException {
        CachedToken current = cachedToken.get();
        long nowMs = System.currentTimeMillis();

        // Use cached token if it is still valid (with buffer)
        if (current != null && current.isValid(nowMs)) {
            log.debug("Using cached token, expires in {}s",
                    (current.expiryMs - nowMs) / 1000);
            return current.token;
        }

        log.info("Fetching new OAuth token from {}", tokenEndpointUri);
        KafkaOAuthBearerToken freshToken = fetchToken();

        CachedToken newCached = new CachedToken(freshToken,
                freshToken.lifetimeMs() - (TOKEN_REFRESH_BUFFER_SECONDS * 1000));
        cachedToken.set(newCached);

        log.info("Obtained new OAuth token for principal={}, expiresAt={}",
                freshToken.principalName(), new Date(freshToken.lifetimeMs()));
        return freshToken;
    }

    /**
     * Performs the client credentials grant HTTP request to the Keycloak token endpoint.
     */
    private KafkaOAuthBearerToken fetchToken() throws IOException {
        RequestBody body = new FormBody.Builder()
                .add("grant_type", "client_credentials")
                .add("client_id", clientId)
                .add("client_secret", clientSecret)
                .add("scope", "kafka-access")
                .build();

        Request request = new Request.Builder()
                .url(tokenEndpointUri)
                .post(body)
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                throw new IOException(String.format(
                        "Token endpoint returned HTTP %d for clientId=%s",
                        response.code(), clientId));
            }

            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                throw new IOException("Empty response body from token endpoint");
            }

            String responseJson = responseBody.string();
            return parseTokenResponse(responseJson);
        }
    }

    /**
     * Parses the token endpoint JSON response and extracts the access token.
     */
    private KafkaOAuthBearerToken parseTokenResponse(String responseJson) throws IOException {
        try {
            JSONObject json = new JSONObject(responseJson);

            if (json.has("error")) {
                throw new IOException(String.format(
                        "Token endpoint returned error: %s - %s",
                        json.optString("error"), json.optString("error_description")));
            }

            String accessToken = json.getString("access_token");
            return parseJwtToken(accessToken);

        } catch (org.json.JSONException e) {
            throw new IOException("Failed to parse token endpoint response as JSON", e);
        }
    }

    /**
     * Parses a raw JWT string and extracts claims to build a {@link KafkaOAuthBearerToken}.
     */
    private KafkaOAuthBearerToken parseJwtToken(String rawToken) throws IOException {
        try {
            JWT jwt = JWTParser.parse(rawToken);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            String sub = claims.getSubject();
            if (sub == null || sub.isBlank()) {
                throw new IOException("JWT is missing required 'sub' claim");
            }

            Date expirationTime = claims.getExpirationTime();
            if (expirationTime == null) {
                throw new IOException("JWT is missing required 'exp' claim");
            }

            Date issuedAt = claims.getIssueTime();
            long startTimeMs = (issuedAt != null) ? issuedAt.getTime() : System.currentTimeMillis();

            // Build scope set from "scope" claim (space-separated string) or empty
            String scopeClaim = (String) claims.getClaim("scope");
            Set<String> scopes = (scopeClaim != null && !scopeClaim.isBlank())
                    ? Set.of(scopeClaim.split("\\s+"))
                    : Collections.emptySet();

            return new KafkaOAuthBearerToken(rawToken, sub, expirationTime.getTime(),
                    scopes, startTimeMs);

        } catch (ParseException e) {
            throw new IOException("Failed to parse JWT token: " + e.getMessage(), e);
        }
    }

    private static String requiredOption(Map<String, ?> options, String key) {
        Object value = options.get(key);
        if (value == null || value.toString().isBlank()) {
            throw new IllegalArgumentException(
                    "Missing required JAAS config option: " + key);
        }
        return value.toString().trim();
    }

    // -------------------------------------------------------------------------
    // Inner classes
    // -------------------------------------------------------------------------

    /**
     * Internal holder that pairs a token with its effective expiry (including the refresh buffer).
     */
    private static final class CachedToken {
        final KafkaOAuthBearerToken token;
        /** Effective expiry in epoch-ms after applying the refresh buffer. */
        final long expiryMs;

        CachedToken(KafkaOAuthBearerToken token, long expiryMs) {
            this.token = token;
            this.expiryMs = expiryMs;
        }

        boolean isValid(long nowMs) {
            return nowMs < expiryMs;
        }
    }

    /**
     * Immutable implementation of {@link OAuthBearerToken} built from validated JWT claims.
     */
    public static final class KafkaOAuthBearerToken implements OAuthBearerToken {

        private final String value;
        private final String principalName;
        private final long lifetimeMs;
        private final Set<String> scope;
        private final Long startTimeMs;

        KafkaOAuthBearerToken(String value, String principalName,
                              long lifetimeMs, Set<String> scope, long startTimeMs) {
            this.value = Objects.requireNonNull(value, "value must not be null");
            this.principalName = Objects.requireNonNull(principalName, "principalName must not be null");
            this.lifetimeMs = lifetimeMs;
            this.scope = Collections.unmodifiableSet(scope);
            this.startTimeMs = startTimeMs;
        }

        /** The raw JWT string, transmitted in the SASL exchange. */
        @Override
        public String value() {
            return value;
        }

        /** The {@code sub} claim value, used as the Kafka principal name. */
        @Override
        public String principalName() {
            return principalName;
        }

        /** Token expiry in epoch milliseconds derived from the {@code exp} claim. */
        @Override
        public long lifetimeMs() {
            return lifetimeMs;
        }

        /**
         * OAuth2 scope set derived from the space-separated {@code scope} claim.
         * Returns an empty set when the claim is absent.
         */
        @Override
        public Set<String> scope() {
            return scope;
        }

        /** Token issue time in epoch milliseconds derived from the {@code iat} claim. */
        @Override
        public Long startTimeMs() {
            return startTimeMs;
        }

        @Override
        public String toString() {
            return String.format("KafkaOAuthBearerToken{principal='%s', expiresAt=%s}",
                    principalName, new Date(lifetimeMs));
        }
    }
}
