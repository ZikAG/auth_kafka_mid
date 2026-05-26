#!/bin/sh
# init-kafka-topics.sh
# Creates Kafka topics for multi-tenant Kafka OAuth project.
# Runs as an init container after Kafka is healthy.
# Uses the plaintext internal listener on port 29092.

set -e

KAFKA_BOOTSTRAP="${KAFKA_BOOTSTRAP:-kafka:29092}"
KAFKA_TOPICS_CMD="/opt/kafka/bin/kafka-topics.sh"
MAX_RETRIES=30
RETRY_INTERVAL=5

# ─── Wait for Kafka to be ready ─────────────────────────────────────────────
echo "[kafka-init] Waiting for Kafka to be ready at ${KAFKA_BOOTSTRAP} ..."
RETRIES=0
until ${KAFKA_TOPICS_CMD} --bootstrap-server "${KAFKA_BOOTSTRAP}" --list > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ "${RETRIES}" -ge "${MAX_RETRIES}" ]; then
    echo "[kafka-init] ERROR: Kafka not ready after ${MAX_RETRIES} attempts. Exiting."
    exit 1
  fi
  echo "[kafka-init] Kafka not ready yet (attempt ${RETRIES}/${MAX_RETRIES}). Retrying in ${RETRY_INTERVAL}s ..."
  sleep "${RETRY_INTERVAL}"
done

echo "[kafka-init] Kafka is ready. Creating topics ..."

# ─── Helper function ────────────────────────────────────────────────────────
create_topic() {
  TOPIC_NAME="$1"
  PARTITIONS="${2:-3}"
  REPLICATION="${3:-1}"
  EXTRA_CONFIG="${4:-}"

  # Check if topic already exists
  if ${KAFKA_TOPICS_CMD} --bootstrap-server "${KAFKA_BOOTSTRAP}" --describe --topic "${TOPIC_NAME}" > /dev/null 2>&1; then
    echo "[kafka-init] Topic '${TOPIC_NAME}' already exists, skipping."
    return 0
  fi

  echo "[kafka-init] Creating topic: ${TOPIC_NAME} (partitions=${PARTITIONS}, replication=${REPLICATION}) ..."

  if [ -n "${EXTRA_CONFIG}" ]; then
    ${KAFKA_TOPICS_CMD} \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --create \
      --topic "${TOPIC_NAME}" \
      --partitions "${PARTITIONS}" \
      --replication-factor "${REPLICATION}" \
      --config "${EXTRA_CONFIG}"
  else
    ${KAFKA_TOPICS_CMD} \
      --bootstrap-server "${KAFKA_BOOTSTRAP}" \
      --create \
      --topic "${TOPIC_NAME}" \
      --partitions "${PARTITIONS}" \
      --replication-factor "${REPLICATION}"
  fi

  echo "[kafka-init] Topic '${TOPIC_NAME}' created successfully."
}

# ─── Tenant A Topics ────────────────────────────────────────────────────────
echo "[kafka-init] --- Creating Tenant A (tenant-a) topics ---"
create_topic "tenant-a-events"        3 1 "retention.ms=604800000"
create_topic "tenant-a-orders"        3 1 "retention.ms=604800000"
create_topic "tenant-a-notifications" 3 1 "retention.ms=86400000"

# ─── Tenant B Topics ────────────────────────────────────────────────────────
echo "[kafka-init] --- Creating Tenant B (tenant-b) topics ---"
create_topic "tenant-b-events"        3 1 "retention.ms=604800000"
create_topic "tenant-b-orders"        3 1 "retention.ms=604800000"
create_topic "tenant-b-notifications" 3 1 "retention.ms=86400000"

# ─── Internal / Audit Topics ────────────────────────────────────────────────
echo "[kafka-init] --- Creating internal topics ---"
create_topic "_auth-audit-log" 3 1 "retention.ms=2592000000,cleanup.policy=delete"

# ─── Verify all topics were created ─────────────────────────────────────────
echo ""
echo "[kafka-init] ============================================"
echo "[kafka-init] All topics created. Current topic list:"
${KAFKA_TOPICS_CMD} --bootstrap-server "${KAFKA_BOOTSTRAP}" --list
echo "[kafka-init] ============================================"
echo ""
echo "[kafka-init] Topic details:"
for TOPIC in \
  "tenant-a-events" \
  "tenant-a-orders" \
  "tenant-a-notifications" \
  "tenant-b-events" \
  "tenant-b-orders" \
  "tenant-b-notifications" \
  "_auth-audit-log"; do
  echo ""
  echo "[kafka-init] --- ${TOPIC} ---"
  ${KAFKA_TOPICS_CMD} \
    --bootstrap-server "${KAFKA_BOOTSTRAP}" \
    --describe \
    --topic "${TOPIC}" 2>/dev/null || echo "[kafka-init] WARNING: Could not describe topic '${TOPIC}'"
done

echo ""
echo "[kafka-init] Kafka topic initialization complete."
