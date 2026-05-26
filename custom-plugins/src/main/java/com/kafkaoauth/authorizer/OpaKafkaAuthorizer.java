package com.kafkaoauth.authorizer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.ResourceType;
import org.apache.kafka.common.security.auth.KafkaPrincipal;
import org.apache.kafka.server.authorizer.AclCreateResult;
import org.apache.kafka.server.authorizer.AclDeleteResult;
import org.apache.kafka.server.authorizer.Action;
import org.apache.kafka.server.authorizer.AuthorizableRequestContext;
import org.apache.kafka.server.authorizer.AuthorizationResult;
import org.apache.kafka.server.authorizer.Authorizer;
import org.apache.kafka.server.authorizer.AuthorizerServerInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * Kafka authorizer that delegates every authorization decision to an Open Policy Agent (OPA)
 * instance via its HTTP REST API.
 *
 * <h2>OPA request format</h2>
 * <pre>{@code
 * POST /v1/data/kafka/authz/allow
 * {
 *   "input": {
 *     "principal":     "service-account-broker",
 *     "tenant_id":     "tenant-a",
 *     "roles":         ["kafka-producer"],
 *     "resource_type": "TOPIC",
 *     "resource_name": "tenant-a-orders",
 *     "operation":     "WRITE"
 *   }
 * }
 * }</pre>
 *
 * <h2>OPA response format</h2>
 * <pre>{@code
 * { "result": true }
 * }</pre>
 *
 * <h2>Configuration (broker properties)</h2>
 * <ul>
 *   <li>{@code AUTHORIZER_OPA_URL} environment variable or
 *       {@code authorizer.opa.url} broker config key – full URL to the OPA policy
 *       endpoint (e.g. {@code http://opa:8181/v1/data/kafka/authz/allow})</li>
 *   <li>{@code authorizer.opa.timeout.ms} – HTTP request timeout in milliseconds
 *       (default: 500)</li>
 *   <li>{@code authorizer.super.users} – space/comma-separated super-user list</li>
 * </ul>
 */
public class OpaKafkaAuthorizer implements Authorizer {

    private static final Logger log = LoggerFactory.getLogger(OpaKafkaAuthorizer.class);
    private static final Logger auditLog = LoggerFactory.getLogger("kafka.authorizer.audit");

    private static final MediaType JSON = MediaType.get("application/json; charset=utf-8");

    private static final String CONFIG_OPA_URL = "authorizer.opa.url";
    private static final String ENV_OPA_URL = "AUTHORIZER_OPA_URL";
    private static final String CONFIG_OPA_TIMEOUT_MS = "authorizer.opa.timeout.ms";
    private static final long DEFAULT_OPA_TIMEOUT_MS = 500L;

    private String opaUrl;
    private OkHttpClient httpClient;
    private Set<String> superUsers = Collections.emptySet();

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // =========================================================================
    // Authorizer lifecycle
    // =========================================================================

    @Override
    public void configure(Map<String, ?> configs) {
        // Resolve OPA URL from config or environment
        Object configUrl = configs.get(CONFIG_OPA_URL);
        if (configUrl != null && !configUrl.toString().isBlank()) {
            opaUrl = configUrl.toString().trim();
        } else {
            opaUrl = System.getenv(ENV_OPA_URL);
        }

        if (opaUrl == null || opaUrl.isBlank()) {
            throw new IllegalStateException(
                    "OPA URL not configured. Set broker property '" + CONFIG_OPA_URL
                    + "' or environment variable '" + ENV_OPA_URL + "'");
        }

        // HTTP timeout
        long timeoutMs = DEFAULT_OPA_TIMEOUT_MS;
        Object timeoutConfig = configs.get(CONFIG_OPA_TIMEOUT_MS);
        if (timeoutConfig != null) {
            try {
                timeoutMs = Long.parseLong(timeoutConfig.toString().trim());
            } catch (NumberFormatException e) {
                log.warn("Invalid value for '{}': '{}', using default {}ms",
                        CONFIG_OPA_TIMEOUT_MS, timeoutConfig, DEFAULT_OPA_TIMEOUT_MS);
            }
        }

        httpClient = new OkHttpClient.Builder()
                .connectTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .readTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .writeTimeout(timeoutMs, TimeUnit.MILLISECONDS)
                .retryOnConnectionFailure(false)
                .build();

        // Parse super users
        Object superUsersConfig = configs.get("authorizer.super.users");
        if (superUsersConfig instanceof String raw && !raw.isBlank()) {
            superUsers = Set.of(raw.split("[,\\s]+"));
        }

        log.info("OpaKafkaAuthorizer configured: opaUrl={}, timeoutMs={}, superUsers={}",
                opaUrl, timeoutMs, superUsers);
    }

    @Override
    public Map<Endpoint, ? extends CompletionStage<Void>> start(AuthorizerServerInfo serverInfo) {
        log.info("OpaKafkaAuthorizer started on broker {}", serverInfo.brokerId());
        return serverInfo.endpoints().stream()
                .collect(Collectors.toMap(
                        ep -> ep,
                        ep -> CompletableFuture.completedFuture(null)));
    }

    @Override
    public void close() throws IOException {
        if (httpClient != null) {
            httpClient.dispatcher().executorService().shutdown();
            httpClient.connectionPool().evictAll();
        }
        log.info("OpaKafkaAuthorizer closed");
    }

    // =========================================================================
    // Authorization
    // =========================================================================

    @Override
    public List<AuthorizationResult> authorize(AuthorizableRequestContext requestContext,
                                               List<Action> actions) {
        KafkaPrincipal principal = requestContext.principal();
        String principalName = principal.getName();

        // Fast path: super users bypass OPA
        if (isSuperUser(principalName)) {
            logAuditBatch(principalName, actions, AuthorizationResult.ALLOWED, "SUPERUSER");
            return Collections.nCopies(actions.size(), AuthorizationResult.ALLOWED);
        }

        // Retrieve JWT claims from the shared store
        Map<String, Object> claims = ClaimStore.get(principalName);
        if (claims.isEmpty()) {
            log.warn("No JWT claims found for principal='{}', denying all {} action(s)",
                    principalName, actions.size());
            logAuditBatch(principalName, actions, AuthorizationResult.DENIED, "NO_CLAIMS");
            return Collections.nCopies(actions.size(), AuthorizationResult.DENIED);
        }

        return actions.stream()
                .map(action -> {
                    AuthorizationResult result = queryOpa(principalName, claims, action);
                    auditLog.info(
                            "result={} principal='{}' resourceType={} resourceName='{}' operation={}",
                            result.name(),
                            principalName,
                            action.resourcePattern().resourceType(),
                            action.resourcePattern().name(),
                            action.operation());
                    return result;
                })
                .collect(Collectors.toList());
    }

    // =========================================================================
    // OPA integration
    // =========================================================================

    /**
     * Builds the OPA request, sends it over HTTP, and returns the authorization result.
     * Returns {@link AuthorizationResult#DENIED} on any I/O or parsing error.
     */
    private AuthorizationResult queryOpa(String principalName,
                                         Map<String, Object> claims,
                                         Action action) {
        String requestJson;
        try {
            requestJson = buildOpaRequest(principalName, claims, action);
        } catch (Exception e) {
            log.error("Failed to build OPA request for principal='{}': {}", principalName, e.getMessage());
            return AuthorizationResult.DENIED;
        }

        try {
            return sendOpaRequest(requestJson);
        } catch (Exception e) {
            log.warn("OPA request failed for principal='{}', resource='{}', operation={}: {}",
                    principalName,
                    action.resourcePattern().name(),
                    action.operation(),
                    e.getMessage());
            return AuthorizationResult.DENIED;
        }
    }

    /**
     * Serializes the authorization request to the OPA input format.
     */
    @SuppressWarnings("unchecked")
    private String buildOpaRequest(String principalName,
                                   Map<String, Object> claims,
                                   Action action) throws Exception {
        ObjectNode input = MAPPER.createObjectNode();
        input.put("principal", principalName);

        String tenantId = (String) claims.get("tenant_id");
        if (tenantId != null) {
            input.put("tenant_id", tenantId);
        }

        List<String> roles = (List<String>) claims.getOrDefault("roles", Collections.emptyList());
        input.set("roles", MAPPER.valueToTree(roles));

        List<String> kafkaScopes = (List<String>) claims.getOrDefault("kafka_scopes", Collections.emptyList());
        input.set("kafka_scopes", MAPPER.valueToTree(kafkaScopes));

        ResourceType resourceType = action.resourcePattern().resourceType();
        AclOperation operation = action.operation();

        input.put("resource_type", resourceType.name());
        input.put("resource_name", action.resourcePattern().name());
        input.put("operation", operation.name());

        ObjectNode wrapper = MAPPER.createObjectNode();
        wrapper.set("input", input);
        return MAPPER.writeValueAsString(wrapper);
    }

    /**
     * Sends the JSON request to the OPA HTTP endpoint and parses the boolean result.
     */
    private AuthorizationResult sendOpaRequest(String requestJson) throws IOException {
        RequestBody body = RequestBody.create(requestJson, JSON);
        Request request = new Request.Builder()
                .url(opaUrl)
                .post(body)
                .header("Accept", "application/json")
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            if (!response.isSuccessful()) {
                log.warn("OPA returned HTTP {}", response.code());
                return AuthorizationResult.DENIED;
            }

            ResponseBody responseBody = response.body();
            if (responseBody == null) {
                log.warn("OPA returned empty response body");
                return AuthorizationResult.DENIED;
            }

            String responseJson = responseBody.string();
            return parseOpaResponse(responseJson);
        }
    }

    /**
     * Parses the OPA JSON response and extracts the boolean {@code result} field.
     */
    private AuthorizationResult parseOpaResponse(String responseJson) throws IOException {
        try {
            JsonNode root = MAPPER.readTree(responseJson);
            JsonNode resultNode = root.get("result");

            if (resultNode == null || resultNode.isNull()) {
                // Undefined result in OPA = deny
                log.debug("OPA returned undefined result, denying");
                return AuthorizationResult.DENIED;
            }

            boolean allowed = resultNode.asBoolean(false);
            return allowed ? AuthorizationResult.ALLOWED : AuthorizationResult.DENIED;

        } catch (Exception e) {
            throw new IOException("Failed to parse OPA response: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // ACL management (not supported)
    // =========================================================================

    @Override
    public List<? extends CompletionStage<AclCreateResult>> createAcls(
            AuthorizableRequestContext requestContext,
            List<AclBinding> aclBindings) {
        return aclBindings.stream()
                .map(acl -> CompletableFuture.completedFuture(
                        new AclCreateResult(new UnsupportedOperationException(
                                "OpaKafkaAuthorizer does not support static ACL management"))))
                .collect(Collectors.toList());
    }

    @Override
    public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
            AuthorizableRequestContext requestContext,
            List<AclBindingFilter> aclBindingFilters) {
        return aclBindingFilters.stream()
                .map(filter -> CompletableFuture.completedFuture(
                        new AclDeleteResult(new UnsupportedOperationException(
                                "OpaKafkaAuthorizer does not support static ACL management"))))
                .collect(Collectors.toList());
    }

    @Override
    public Iterable<AclBinding> acls(AclBindingFilter filter) {
        return Collections.emptyList();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private boolean isSuperUser(String principalName) {
        return superUsers.contains(principalName)
                || superUsers.contains("User:" + principalName);
    }

    private void logAuditBatch(String principal,
                               List<Action> actions,
                               AuthorizationResult result,
                               String reason) {
        if (auditLog.isInfoEnabled()) {
            for (Action action : actions) {
                auditLog.info(
                        "result={} principal='{}' resourceType={} resourceName='{}' operation={} reason={}",
                        result.name(),
                        principal,
                        action.resourcePattern().resourceType(),
                        action.resourcePattern().name(),
                        action.operation(),
                        reason);
            }
        }
    }
}
