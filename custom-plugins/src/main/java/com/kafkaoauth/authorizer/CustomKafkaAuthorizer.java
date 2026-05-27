package com.kafkaoauth.authorizer;

import org.apache.kafka.common.Endpoint;
import org.apache.kafka.common.errors.ApiException;
import org.apache.kafka.common.acl.AclBinding;
import org.apache.kafka.common.acl.AclBindingFilter;
import org.apache.kafka.common.acl.AclOperation;
import org.apache.kafka.common.resource.PatternType;
import org.apache.kafka.common.resource.ResourcePattern;
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
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * Multi-tenant Kafka authorizer driven by JWT claims stored in {@link ClaimStore}.
 *
 * <h2>Role-to-permission mapping</h2>
 * <table border="1">
 *   <tr><th>Role</th><th>Resource</th><th>Permitted operations</th></tr>
 *   <tr><td>kafka-superuser</td><td>*</td><td>ALL</td></tr>
 *   <tr><td>kafka-admin</td><td>tenant-{tenant_id}-* topics</td><td>READ, WRITE, CREATE, DELETE, DESCRIBE</td></tr>
 *   <tr><td>kafka-admin</td><td>_internal topics</td><td>READ, WRITE, DESCRIBE</td></tr>
 *   <tr><td>kafka-admin</td><td>CLUSTER</td><td>DESCRIBE, CREATE, DELETE</td></tr>
 *   <tr><td>kafka-producer</td><td>{tenant_id}-* topics</td><td>WRITE, DESCRIBE</td></tr>
 *   <tr><td>kafka-consumer</td><td>{tenant_id}-* topics</td><td>READ, DESCRIBE</td></tr>
 *   <tr><td>kafka-consumer</td><td>{tenant_id}-* consumer groups</td><td>READ, DESCRIBE</td></tr>
 * </table>
 *
 * <h2>Multi-tenancy enforcement</h2>
 * <ul>
 *   <li>All topic and group names for tenant users MUST start with {@code {tenant_id}-}.</li>
 *   <li>Cross-tenant access is always DENIED.</li>
 *   <li>Principals without a {@code tenant_id} claim have no access to tenant resources.</li>
 * </ul>
 *
 * <h2>Configuration (broker properties)</h2>
 * <ul>
 *   <li>{@code authorizer.super.users} – space-separated list of super-user principals</li>
 * </ul>
 */
public class CustomKafkaAuthorizer implements Authorizer {

    private static final Logger log = LoggerFactory.getLogger(CustomKafkaAuthorizer.class);
    private static final Logger auditLog = LoggerFactory.getLogger("kafka.authorizer.audit");

    // ---- Well-known role names -----------------------------------------------
    private static final String ROLE_SUPERUSER = "kafka-superuser";
    private static final String ROLE_ADMIN = "kafka-admin";
    private static final String ROLE_PRODUCER = "kafka-producer";
    private static final String ROLE_CONSUMER = "kafka-consumer";

    // ---- Permitted operations per role+resource type -------------------------
    private static final Set<AclOperation> ADMIN_TOPIC_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.READ, AclOperation.WRITE,
                    AclOperation.CREATE, AclOperation.DELETE,
                    AclOperation.DESCRIBE, AclOperation.DESCRIBE_CONFIGS,
                    AclOperation.ALTER_CONFIGS));

    private static final Set<AclOperation> ADMIN_INTERNAL_TOPIC_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.READ, AclOperation.WRITE, AclOperation.DESCRIBE,
                    AclOperation.DESCRIBE_CONFIGS));

    private static final Set<AclOperation> ADMIN_CLUSTER_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.DESCRIBE, AclOperation.CREATE, AclOperation.DELETE,
                    AclOperation.ALTER, AclOperation.DESCRIBE_CONFIGS,
                    AclOperation.ALTER_CONFIGS, AclOperation.CLUSTER_ACTION));

    private static final Set<AclOperation> ADMIN_GROUP_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.READ, AclOperation.DESCRIBE, AclOperation.DELETE));

    private static final Set<AclOperation> PRODUCER_TOPIC_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.WRITE, AclOperation.DESCRIBE, AclOperation.DESCRIBE_CONFIGS));

    private static final Set<AclOperation> CONSUMER_TOPIC_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.READ, AclOperation.DESCRIBE, AclOperation.DESCRIBE_CONFIGS));

    private static final Set<AclOperation> CONSUMER_GROUP_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.READ, AclOperation.DESCRIBE));

    private static final Set<AclOperation> TRANSACTIONAL_PRODUCER_OPS = Collections.unmodifiableSet(
            EnumSet.of(AclOperation.WRITE, AclOperation.DESCRIBE));

    // ---- State ---------------------------------------------------------------
    /** Super-user principal names loaded from broker config. */
    private Set<String> superUsers = Collections.emptySet();

    // =========================================================================
    // Authorizer lifecycle
    // =========================================================================

    @Override
    public Map<Endpoint, ? extends CompletionStage<Void>> start(AuthorizerServerInfo serverInfo) {
        log.info("CustomKafkaAuthorizer started on broker {}", serverInfo.brokerId());
        // Return an already-completed future for every endpoint
        return serverInfo.endpoints().stream()
                .collect(Collectors.toMap(
                        ep -> ep,
                        ep -> CompletableFuture.completedFuture(null)));
    }

    @Override
    @SuppressWarnings("unchecked")
    public void configure(Map<String, ?> configs) {
        // Parse authorizer.super.users (space or comma separated)
        Object superUsersConfig = configs.get("authorizer.super.users");
        if (superUsersConfig instanceof String raw && !raw.isBlank()) {
            superUsers = Set.of(raw.split("[,;\\s]+"));
        } else {
            superUsers = Collections.emptySet();
        }
        log.info("CustomKafkaAuthorizer configured, superUsers={}", superUsers);
    }

    @Override
    public void close() throws IOException {
        log.info("CustomKafkaAuthorizer closed");
    }

    // =========================================================================
    // Authorization
    // =========================================================================

    @Override
    public List<AuthorizationResult> authorize(AuthorizableRequestContext requestContext,
                                               List<Action> actions) {
        KafkaPrincipal principal = requestContext.principal();
        String principalName = principal.getName();

        // Super users bypass all checks
        if (isSuperUser(principalName)) {
            logAuditBatch(principalName, actions, AuthorizationResult.ALLOWED, "SUPERUSER");
            return Collections.nCopies(actions.size(), AuthorizationResult.ALLOWED);
        }

        // Retrieve JWT claims for this principal
        Map<String, Object> claims = ClaimStore.get(principalName);
        if (claims.isEmpty()) {
            // No claims available → deny everything (principal not authenticated via OAuth)
            log.warn("No JWT claims found for principal='{}', denying all {} action(s)",
                    principalName, actions.size());
            logAuditBatch(principalName, actions, AuthorizationResult.DENIED, "NO_CLAIMS");
            return Collections.nCopies(actions.size(), AuthorizationResult.DENIED);
        }

        return actions.stream()
                .map(action -> {
                    AuthorizationResult result = authorizeAction(principalName, action, claims);
                    logAudit(principalName, action, result, requestContext.clientAddress().toString());
                    return result;
                })
                .collect(Collectors.toList());
    }

    private AuthorizationResult authorizeAction(String principalName,
                                                Action action,
                                                Map<String, Object> claims) {
        String tenantId = (String) claims.get("tenant_id");
        @SuppressWarnings("unchecked")
        List<String> roles = (List<String>) claims.getOrDefault("roles", Collections.emptyList());

        ResourcePattern resource = action.resourcePattern();
        AclOperation operation = action.operation();

        // ALLOW_ALL operation implies any single operation is permitted
        if (operation == AclOperation.ALL) {
            // Only superusers can exercise ALL; tenant roles cannot
            return AuthorizationResult.DENIED;
        }

        return switch (resource.resourceType()) {
            case TOPIC -> authorizeTopicAccess(tenantId, roles, resource.name(), operation);
            case GROUP -> authorizeGroupAccess(tenantId, roles, resource.name(), operation);
            case CLUSTER -> authorizeClusterAccess(roles, operation);
            case TRANSACTIONAL_ID -> authorizeTransactionalAccess(tenantId, roles, resource.name(), operation);
            case DELEGATION_TOKEN -> AuthorizationResult.DENIED;
            default -> {
                log.debug("Unsupported resource type {} for principal='{}', denying",
                        resource.resourceType(), principalName);
                yield AuthorizationResult.DENIED;
            }
        };
    }

    // =========================================================================
    // Per-resource authorization helpers
    // =========================================================================

    /**
     * Authorizes access to a Kafka topic.
     *
     * <ul>
     *   <li>Internal topics (name starts with {@code _}) are only accessible to admins.</li>
     *   <li>All other topics must be prefixed with {@code {tenant_id}-}.</li>
     * </ul>
     */
    private AuthorizationResult authorizeTopicAccess(String tenantId,
                                                     List<String> roles,
                                                     String topicName,
                                                     AclOperation operation) {
        // Internal topic: only admins may access
        if (topicName.startsWith("_")) {
            if (roles.contains(ROLE_ADMIN) && ADMIN_INTERNAL_TOPIC_OPS.contains(operation)) {
                return AuthorizationResult.ALLOWED;
            }
            return AuthorizationResult.DENIED;
        }

        // Tenant-prefixed topic: principal must have a tenant_id and topic must match it
        if (tenantId == null || tenantId.isBlank()) {
            log.debug("Denying access to topic '{}' – principal has no tenant_id", topicName);
            return AuthorizationResult.DENIED;
        }

        String expectedPrefix = tenantId + "-";
        if (!topicName.startsWith(expectedPrefix)) {
            log.debug("Cross-tenant access denied: topic='{}' does not belong to tenant='{}'",
                    topicName, tenantId);
            return AuthorizationResult.DENIED;
        }

        // Evaluate role permissions
        if (roles.contains(ROLE_ADMIN) && ADMIN_TOPIC_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }
        if (roles.contains(ROLE_PRODUCER) && PRODUCER_TOPIC_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }
        if (roles.contains(ROLE_CONSUMER) && CONSUMER_TOPIC_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }

        return AuthorizationResult.DENIED;
    }

    /**
     * Authorizes access to a consumer group.
     *
     * <p>Group names must be prefixed with {@code {tenant_id}-}.
     */
    private AuthorizationResult authorizeGroupAccess(String tenantId,
                                                     List<String> roles,
                                                     String groupName,
                                                     AclOperation operation) {
        if (tenantId == null || tenantId.isBlank()) {
            return AuthorizationResult.DENIED;
        }

        String expectedPrefix = tenantId + "-";
        if (!groupName.startsWith(expectedPrefix)) {
            log.debug("Cross-tenant group access denied: group='{}' does not belong to tenant='{}'",
                    groupName, tenantId);
            return AuthorizationResult.DENIED;
        }

        if (roles.contains(ROLE_ADMIN) && ADMIN_GROUP_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }
        if (roles.contains(ROLE_CONSUMER) && CONSUMER_GROUP_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }

        return AuthorizationResult.DENIED;
    }

    /**
     * Authorizes cluster-level operations (e.g., metadata, create/delete topics cluster-wide).
     */
    private AuthorizationResult authorizeClusterAccess(List<String> roles,
                                                       AclOperation operation) {
        if (roles.contains(ROLE_ADMIN) && ADMIN_CLUSTER_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }
        // Producers and consumers may describe cluster metadata
        if ((roles.contains(ROLE_PRODUCER) || roles.contains(ROLE_CONSUMER))
                && operation == AclOperation.DESCRIBE) {
            return AuthorizationResult.ALLOWED;
        }
        return AuthorizationResult.DENIED;
    }

    /**
     * Authorizes access to a transactional ID.
     *
     * <p>Transactional IDs must also be prefixed with {@code {tenant_id}-}.
     */
    private AuthorizationResult authorizeTransactionalAccess(String tenantId,
                                                             List<String> roles,
                                                             String transactionalId,
                                                             AclOperation operation) {
        if (tenantId == null || tenantId.isBlank()) {
            return AuthorizationResult.DENIED;
        }

        String expectedPrefix = tenantId + "-";
        if (!transactionalId.startsWith(expectedPrefix)) {
            log.debug("Cross-tenant transactional ID denied: txId='{}' does not belong to tenant='{}'",
                    transactionalId, tenantId);
            return AuthorizationResult.DENIED;
        }

        if ((roles.contains(ROLE_ADMIN) || roles.contains(ROLE_PRODUCER))
                && TRANSACTIONAL_PRODUCER_OPS.contains(operation)) {
            return AuthorizationResult.ALLOWED;
        }

        return AuthorizationResult.DENIED;
    }

    // =========================================================================
    // ACL management (not supported – this authorizer uses JWT claims)
    // =========================================================================

    @Override
    public List<? extends CompletionStage<AclCreateResult>> createAcls(
            AuthorizableRequestContext requestContext,
            List<AclBinding> aclBindings) {
        // ACLs are managed through JWT claims; static ACL creation is not supported
        return aclBindings.stream()
                .map(acl -> CompletableFuture.<AclCreateResult>completedFuture(
                        new AclCreateResult(new ApiException(
                                "CustomKafkaAuthorizer does not support static ACL management"))))
                .collect(Collectors.toList());
    }

    @Override
    public List<? extends CompletionStage<AclDeleteResult>> deleteAcls(
            AuthorizableRequestContext requestContext,
            List<AclBindingFilter> aclBindingFilters) {
        return aclBindingFilters.stream()
                .map(filter -> CompletableFuture.<AclDeleteResult>completedFuture(
                        new AclDeleteResult(new ApiException(
                                "CustomKafkaAuthorizer does not support static ACL management"))))
                .collect(Collectors.toList());
    }

    @Override
    public Iterable<AclBinding> acls(AclBindingFilter filter) {
        return Collections.emptyList();
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private boolean isSuperUser(String principalName) {
        return superUsers.contains(principalName)
                || superUsers.contains("User:" + principalName);
    }

    // -------------------------------------------------------------------------
    // Audit logging
    // -------------------------------------------------------------------------

    private void logAudit(String principal,
                          Action action,
                          AuthorizationResult result,
                          String clientAddress) {
        if (auditLog.isInfoEnabled()) {
            auditLog.info(
                    "result={} principal='{}' resourceType={} resourceName='{}' operation={} clientAddress={}",
                    result.name(),
                    principal,
                    action.resourcePattern().resourceType(),
                    action.resourcePattern().name(),
                    action.operation(),
                    clientAddress);
        }
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
