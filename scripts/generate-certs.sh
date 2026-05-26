#!/bin/sh
# generate-certs.sh
# Generates TLS certificates in PEM format for Kafka SASL_SSL.
# Runs inside alpine/openssl container; outputs to /certs/.
# Kafka is configured with KAFKA_SSL_KEYSTORE_TYPE=PEM so JKS is not needed.

set -e

CERTS_DIR="/certs"
CA_KEY="${CERTS_DIR}/ca.key"
CA_CERT="${CERTS_DIR}/ca.crt"
KAFKA_KEY="${CERTS_DIR}/kafka.key"
KAFKA_CSR="${CERTS_DIR}/kafka.csr"
KAFKA_CERT="${CERTS_DIR}/kafka.crt"
KAFKA_CERT_CHAIN="${CERTS_DIR}/kafka-cert-chain.pem"
CLIENT_KEY="${CERTS_DIR}/client.key"
CLIENT_CSR="${CERTS_DIR}/client.csr"
CLIENT_CERT="${CERTS_DIR}/client.crt"

# ─── Check if certs already exist ───────────────────────────────────────────
if [ -f "${CA_CERT}" ] && [ -f "${KAFKA_CERT}" ] && [ -f "${CLIENT_CERT}" ]; then
  echo "[cert-init] Certificates already exist in ${CERTS_DIR}, skipping generation."
  exit 0
fi

echo "[cert-init] Generating TLS certificates in ${CERTS_DIR} ..."
mkdir -p "${CERTS_DIR}"

# ─── 1. Generate CA private key and self-signed certificate ─────────────────
echo "[cert-init] Creating Certificate Authority (CA) ..."
openssl genrsa -out "${CA_KEY}" 4096

openssl req -new -x509 \
  -key "${CA_KEY}" \
  -out "${CA_CERT}" \
  -days 3650 \
  -subj "/C=US/ST=California/L=San Francisco/O=KafkaOAuth/OU=Platform/CN=kafka-ca" \
  -extensions v3_ca \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

echo "[cert-init] CA certificate created: ${CA_CERT}"

# ─── 2. Generate Kafka broker private key and CSR ───────────────────────────
echo "[cert-init] Creating Kafka broker key and certificate ..."
openssl genrsa -out "${KAFKA_KEY}" 4096

openssl req -new \
  -key "${KAFKA_KEY}" \
  -out "${KAFKA_CSR}" \
  -subj "/C=US/ST=California/L=San Francisco/O=KafkaOAuth/OU=Kafka/CN=kafka"

# Create SAN extension config for broker cert
cat > /tmp/kafka-ext.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
subjectAltName = @alt_names
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth

[alt_names]
DNS.1 = kafka
DNS.2 = localhost
DNS.3 = kafka-broker
IP.1 = 127.0.0.1
IP.2 = 172.20.0.0
EOF

# ─── 3. Sign Kafka broker certificate with CA ────────────────────────────────
openssl x509 -req \
  -in "${KAFKA_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${KAFKA_CERT}" \
  -days 365 \
  -extfile /tmp/kafka-ext.cnf \
  -extensions v3_req

echo "[cert-init] Kafka broker certificate created: ${KAFKA_CERT}"

# ─── 4. Create certificate chain (broker cert + CA cert) ────────────────────
# Kafka PEM keystore expects the full chain when KAFKA_SSL_KEYSTORE_TYPE=PEM.
# The keystore location points to this chain file; the key is in kafka.key.
cat "${KAFKA_CERT}" "${CA_CERT}" > "${KAFKA_CERT_CHAIN}"
echo "[cert-init] Certificate chain created: ${KAFKA_CERT_CHAIN}"

# ─── 5. Generate client private key and CSR ─────────────────────────────────
echo "[cert-init] Creating client certificate ..."
openssl genrsa -out "${CLIENT_KEY}" 4096

openssl req -new \
  -key "${CLIENT_KEY}" \
  -out "${CLIENT_CSR}" \
  -subj "/C=US/ST=California/L=San Francisco/O=KafkaOAuth/OU=Client/CN=kafka-client"

# ─── 6. Sign client certificate with CA ─────────────────────────────────────
cat > /tmp/client-ext.cnf <<EOF
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[v3_req]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EOF

openssl x509 -req \
  -in "${CLIENT_CSR}" \
  -CA "${CA_CERT}" \
  -CAkey "${CA_KEY}" \
  -CAcreateserial \
  -out "${CLIENT_CERT}" \
  -days 365 \
  -extfile /tmp/client-ext.cnf \
  -extensions v3_req

echo "[cert-init] Client certificate created: ${CLIENT_CERT}"

# ─── 7. Verify certificates ──────────────────────────────────────────────────
echo "[cert-init] Verifying certificate chain ..."
openssl verify -CAfile "${CA_CERT}" "${KAFKA_CERT}"
openssl verify -CAfile "${CA_CERT}" "${CLIENT_CERT}"

# ─── 8. Set permissions ──────────────────────────────────────────────────────
chmod 644 "${CA_CERT}" "${KAFKA_CERT}" "${KAFKA_CERT_CHAIN}" "${CLIENT_CERT}"
chmod 600 "${CA_KEY}" "${KAFKA_KEY}" "${CLIENT_KEY}"

# ─── 9. Cleanup temp files ───────────────────────────────────────────────────
rm -f "${KAFKA_CSR}" "${CLIENT_CSR}" /tmp/kafka-ext.cnf /tmp/client-ext.cnf

# ─── 10. Print summary ───────────────────────────────────────────────────────
echo ""
echo "[cert-init] ============================================"
echo "[cert-init] Certificate generation complete."
echo "[cert-init] Files created in ${CERTS_DIR}:"
ls -la "${CERTS_DIR}/"
echo "[cert-init] ============================================"
echo ""
echo "[cert-init] CA certificate fingerprint:"
openssl x509 -in "${CA_CERT}" -noout -fingerprint -sha256
echo ""
echo "[cert-init] Kafka broker certificate subject/issuer:"
openssl x509 -in "${KAFKA_CERT}" -noout -subject -issuer -dates
echo ""
echo "[cert-init] Client certificate subject/issuer:"
openssl x509 -in "${CLIENT_CERT}" -noout -subject -issuer -dates
