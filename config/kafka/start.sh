#!/bin/bash
set -e

CLUSTER_ID="${CLUSTER_ID:-5L6g3nShT-eMCtK--X86sw}"
CONFIG="/opt/kafka/config/kraft/server.properties"

if [ ! -f /var/lib/kafka/data/meta.properties ]; then
  echo "Formatting KRaft storage (cluster ID: ${CLUSTER_ID})"
  /opt/kafka/bin/kafka-storage.sh format -t "${CLUSTER_ID}" -c "${CONFIG}"
fi

exec /opt/kafka/bin/kafka-server-start.sh "${CONFIG}"
