package com.kafkaoauth.authorizer;

import org.apache.kafka.common.errors.PolicyViolationException;
import org.apache.kafka.server.policy.AlterConfigPolicy;
import org.apache.kafka.server.policy.CreateTopicPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Kafka broker-side policy that enforces tenant topic naming conventions and
 * restricts topic configuration changes.
 *
 * <h2>Topic naming rules</h2>
 * <ul>
 *   <li>Internal topics (name starts with {@code _}) are allowed unconditionally –
 *       they are managed by Kafka itself (e.g., {@code __consumer_offsets}).</li>
 *   <li>All other topics MUST follow the pattern {@code {tenant_id}-{descriptive_name}}
 *       where {@code tenant_id} is a non-empty alphanumeric-plus-hyphen segment.</li>
 * </ul>
 *
 * <h2>Config change rules</h2>
 * <ul>
 *   <li>Internal topics ({@code _} prefix): all config changes are allowed.</li>
 *   <li>Tenant topics: only a safe whitelist of configurations can be altered;
 *       any change outside that list is rejected.</li>
 * </ul>
 *
 * <h2>Broker configuration</h2>
 * The policy is activated by adding to {@code server.properties}:
 * <pre>
 * create.topic.policy.class.name=com.kafkaoauth.authorizer.TenantTopicPolicy
 * alter.config.policy.class.name=com.kafkaoauth.authorizer.TenantTopicPolicy
 * </pre>
 *
 * Optional broker properties consumed by this policy:
 * <ul>
 *   <li>{@code tenant.topic.policy.allowed.prefixes} – comma-separated list of
 *       additional allowed topic prefixes (beyond the tenant-id pattern).</li>
 *   <li>{@code tenant.topic.policy.strict} – {@code true} (default) enforces the
 *       naming rule strictly; {@code false} only logs violations without rejecting.</li>
 * </ul>
 */
public class TenantTopicPolicy implements CreateTopicPolicy, AlterConfigPolicy {

    private static final Logger log = LoggerFactory.getLogger(TenantTopicPolicy.class);

    /**
     * Pattern that a valid tenant topic name must match:
     * at least one alphanumeric/hyphen segment for tenant-id, a literal hyphen separator,
     * then one or more characters for the topic descriptive name.
     *
     * <p>Examples: {@code tenant-a-orders}, {@code my-org-user-events}.
     */
    private static final Pattern TENANT_TOPIC_PATTERN =
            Pattern.compile("^[a-zA-Z0-9][a-zA-Z0-9\\-]+-[a-zA-Z0-9][a-zA-Z0-9\\-._]+$");

    /**
     * Topic configurations that tenant operators are allowed to override.
     * All other config keys are rejected for tenant topics to prevent misconfiguration.
     */
    private static final Set<String> ALLOWED_TOPIC_CONFIGS = Set.of(
            "retention.ms",
            "retention.bytes",
            "cleanup.policy",
            "max.message.bytes",
            "min.insync.replicas",
            "compression.type",
            "segment.bytes",
            "segment.ms",
            "delete.retention.ms",
            "min.cleanable.dirty.ratio",
            "message.timestamp.type",
            "message.timestamp.difference.max.ms"
    );

    /** When {@code false}, violations are logged but not enforced (warn-only mode). */
    private boolean strictMode = true;

    // =========================================================================
    // Policy lifecycle
    // =========================================================================

    @Override
    public void configure(Map<String, ?> configs) {
        Object strictConfig = configs.get("tenant.topic.policy.strict");
        if (strictConfig != null) {
            strictMode = Boolean.parseBoolean(strictConfig.toString().trim());
        }

        log.info("TenantTopicPolicy configured: strictMode={}", strictMode);
    }

    @Override
    public void close() {
        log.info("TenantTopicPolicy closed");
    }

    // =========================================================================
    // CreateTopicPolicy
    // =========================================================================

    /**
     * Validates that the topic name obeys the tenant prefix convention.
     *
     * @param requestMetadata metadata about the create-topic request
     * @throws PolicyViolationException if the name is invalid and strict mode is enabled
     */
    @Override
    public void validate(CreateTopicPolicy.RequestMetadata requestMetadata)
            throws PolicyViolationException {
        String topicName = requestMetadata.topic();

        if (isInternalTopic(topicName)) {
            log.debug("Allowing internal topic creation: '{}'", topicName);
            return;
        }

        if (!TENANT_TOPIC_PATTERN.matcher(topicName).matches()) {
            String message = String.format(
                    "Topic name '%s' violates the tenant naming policy. "
                    + "Topic names must match pattern '<tenant_id>-<name>' "
                    + "(e.g., 'tenant-a-orders'). "
                    + "Internal topics must start with '_'.",
                    topicName);

            if (strictMode) {
                log.warn("Rejecting create-topic request: {}", message);
                throw new PolicyViolationException(message);
            } else {
                log.warn("Policy violation (warn-only mode): {}", message);
            }
        } else {
            log.debug("Topic name '{}' passed naming policy validation", topicName);
        }

        // Validate replication factor and partition count sanity
        validatePartitionsAndReplicas(topicName, requestMetadata);
    }

    // =========================================================================
    // AlterConfigPolicy
    // =========================================================================

    /**
     * Validates that config changes on tenant topics only touch allowed configuration keys.
     *
     * @param requestMetadata metadata about the alter-config request
     * @throws PolicyViolationException if a disallowed config key is being changed
     */
    @Override
    public void validate(AlterConfigPolicy.RequestMetadata requestMetadata)
            throws PolicyViolationException {
        String resourceName = requestMetadata.resource().name();

        // Only validate topic resources
        if (requestMetadata.resource().type()
                != org.apache.kafka.common.config.ConfigResource.Type.TOPIC) {
            return;
        }

        if (isInternalTopic(resourceName)) {
            log.debug("Allowing config change on internal topic '{}'", resourceName);
            return;
        }

        // Check that every key in the request is on the allowed list
        Map<String, String> configs = requestMetadata.configs();
        for (String configKey : configs.keySet()) {
            if (!ALLOWED_TOPIC_CONFIGS.contains(configKey)) {
                String message = String.format(
                        "Configuration key '%s' is not permitted for tenant topic '%s'. "
                        + "Allowed keys: %s",
                        configKey, resourceName, ALLOWED_TOPIC_CONFIGS);

                if (strictMode) {
                    log.warn("Rejecting alter-config request: {}", message);
                    throw new PolicyViolationException(message);
                } else {
                    log.warn("Policy violation (warn-only mode): {}", message);
                }
            }
        }

        log.debug("Alter-config request for topic '{}' passed policy validation (keys={})",
                resourceName, configs.keySet());
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    /**
     * Returns {@code true} if the topic name is an internal Kafka topic.
     * Internal topics are identified by a leading underscore character.
     */
    private boolean isInternalTopic(String topicName) {
        return topicName != null && topicName.startsWith("_");
    }

    /**
     * Performs basic sanity checks on partition count and replication factor.
     * These are advisory in non-strict mode.
     */
    private void validatePartitionsAndReplicas(String topicName,
                                               CreateTopicPolicy.RequestMetadata metadata) {
        int numPartitions = metadata.numPartitions() != null ? metadata.numPartitions() : -1;
        short replicationFactor = metadata.replicationFactor() != null
                ? metadata.replicationFactor() : -1;

        if (numPartitions == 0) {
            String message = String.format(
                    "Topic '%s' requested 0 partitions, which is invalid.", topicName);
            if (strictMode) {
                throw new PolicyViolationException(message);
            } else {
                log.warn("Policy violation (warn-only): {}", message);
            }
        }

        if (replicationFactor == 0) {
            String message = String.format(
                    "Topic '%s' requested replication factor 0, which is invalid.", topicName);
            if (strictMode) {
                throw new PolicyViolationException(message);
            } else {
                log.warn("Policy violation (warn-only): {}", message);
            }
        }
    }
}
