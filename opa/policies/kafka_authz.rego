package kafka.authz

import future.keywords.if
import future.keywords.in

# ---------------------------------------------------------------------------
# Input shape (expected from the Kafka authorizer calling OPA):
#
# {
#   "principal":     "alice",          -- Kafka principal (username / subject)
#   "tenant_id":     "tenant-a",       -- Extracted from JWT claim
#   "roles":         ["kafka-producer", "kafka-consumer"],
#   "resource_type": "TOPIC",          -- TOPIC | GROUP | CLUSTER | TRANSACTIONAL_ID
#   "resource_name": "tenant-a-events",
#   "operation":     "WRITE",          -- READ | WRITE | CREATE | DELETE | ALTER |
#                                      --   DESCRIBE | DESCRIBE_CONFIGS | ...
#   "patternType":   "LITERAL"         -- LITERAL | PREFIXED (optional)
# }
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Main allow rule
# ---------------------------------------------------------------------------

# Default deny – explicit allow is required for every decision.
default allow := false

# Super-users bypass all further checks.
allow if {
	is_superuser
}

# Topic-level decisions.
allow if {
	input.resource_type == "TOPIC"
	topic_allowed
}

# Consumer group decisions.
allow if {
	input.resource_type == "GROUP"
	group_allowed
}

# Cluster-level decisions.
allow if {
	input.resource_type == "CLUSTER"
	cluster_allowed
}

# Transactional ID – must carry tenant prefix.
allow if {
	input.resource_type == "TRANSACTIONAL_ID"
	transactional_id_allowed
}

# ---------------------------------------------------------------------------
# Super-user check
# ---------------------------------------------------------------------------

is_superuser if {
	"kafka-superuser" in input.roles
}

# ---------------------------------------------------------------------------
# Topic authorisation
# ---------------------------------------------------------------------------

# Regular tenant topics: must start with "{tenant_id}-" and the user must
# hold the appropriate role for the requested operation.
topic_allowed if {
	input.operation in {"READ", "WRITE", "DESCRIBE"}
	startswith(input.resource_name, tenant_prefix(input.tenant_id))
	has_required_role_for_operation(input.operation)
}

# CREATE / DELETE / ALTER on own-tenant topics – requires kafka-admin.
topic_allowed if {
	input.operation in {"CREATE", "DELETE", "ALTER", "ALTER_CONFIGS", "DESCRIBE_CONFIGS"}
	startswith(input.resource_name, tenant_prefix(input.tenant_id))
	"kafka-admin" in input.roles
}

# Internal topics (prefixed with "_") – kafka-admin only.
topic_allowed if {
	startswith(input.resource_name, "_")
	"kafka-admin" in input.roles
}

# kafka-admin may access any topic regardless of tenant prefix.
topic_allowed if {
	"kafka-admin" in input.roles
	input.operation in {"READ", "WRITE", "DESCRIBE", "CREATE", "DELETE", "ALTER",
		"ALTER_CONFIGS", "DESCRIBE_CONFIGS"}
}

# ---------------------------------------------------------------------------
# Consumer group authorisation
# ---------------------------------------------------------------------------

# Tenant consumer groups must carry the tenant prefix.
group_allowed if {
	input.operation in {"READ", "DESCRIBE", "DELETE"}
	startswith(input.resource_name, tenant_prefix(input.tenant_id))
	"kafka-consumer" in input.roles
}

# kafka-admin may manage any consumer group.
group_allowed if {
	"kafka-admin" in input.roles
	input.operation in {"READ", "DESCRIBE", "DELETE"}
}

# ---------------------------------------------------------------------------
# Cluster-level authorisation
# ---------------------------------------------------------------------------

# Read-only cluster operations are available to kafka-admin.
cluster_allowed if {
	"kafka-admin" in input.roles
	input.operation in {"DESCRIBE", "DESCRIBE_CONFIGS"}
}

# Mutating cluster operations require kafka-superuser.
cluster_allowed if {
	"kafka-superuser" in input.roles
	input.operation in {
		"DESCRIBE", "DESCRIBE_CONFIGS",
		"ALTER", "ALTER_CONFIGS",
		"CREATE", "DELETE",
		"CLUSTER_ACTION",
		"IdempotentWrite",
	}
}

# ---------------------------------------------------------------------------
# Transactional ID authorisation
# ---------------------------------------------------------------------------

transactional_id_allowed if {
	startswith(input.resource_name, tenant_prefix(input.tenant_id))
	"kafka-producer" in input.roles
	input.operation in {"WRITE", "DESCRIBE"}
}

transactional_id_allowed if {
	"kafka-admin" in input.roles
}

# ---------------------------------------------------------------------------
# Role → operation mapping helpers
# ---------------------------------------------------------------------------

# kafka-consumer: read access.
has_required_role_for_operation(op) if {
	op == "READ"
	"kafka-consumer" in input.roles
}

# kafka-producer: write access.
has_required_role_for_operation(op) if {
	op == "WRITE"
	"kafka-producer" in input.roles
}

# DESCRIBE is allowed to anyone who can at least read or write.
has_required_role_for_operation(op) if {
	op == "DESCRIBE"
	some role in input.roles
	role in {"kafka-consumer", "kafka-producer", "kafka-admin"}
}

# kafka-admin: full operation set.
has_required_role_for_operation(op) if {
	op in {"READ", "WRITE", "DESCRIBE", "CREATE", "DELETE", "ALTER",
		"ALTER_CONFIGS", "DESCRIBE_CONFIGS"}
	"kafka-admin" in input.roles
}

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

# tenant_prefix builds the expected topic/group prefix for a tenant.
# e.g. tenant_prefix("tenant-a") == "tenant-a-"
tenant_prefix(tenant_id) := concat("", [tenant_id, "-"])

# ---------------------------------------------------------------------------
# Audit metadata
#
# This object is included in OPA decision logs and can be scraped by the
# Kafka authorizer for structured audit trail writing.
# ---------------------------------------------------------------------------

audit := {
	"principal":    input.principal,
	"tenant_id":    input.tenant_id,
	"roles":        input.roles,
	"resource":     input.resource_name,
	"resource_type": input.resource_type,
	"operation":    input.operation,
	"decision":     allow,
	"timestamp_ns": time.now_ns(),
}
