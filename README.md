# Kafka OAuth Security Platform

A production-grade multi-tenant Kafka security platform using SASL/OAUTHBEARER
authentication, Keycloak as the Identity Provider, a Go-based token exchange
service, and Open Policy Agent (OPA) for fine-grained Kafka authorisation.

---

## Architecture Overview

Every message flow is authenticated (JWT/OAUTHBEARER) and authorised
(custom Java plugin or OPA) at the Kafka broker level.  No anonymous access is
possible.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       Kafka OAuth Security Platform                          │
├──────────────┬──────────────┬──────────────────────┬────────────────────────┤
│   Keycloak   │ Auth Service │    Kafka Broker       │     OPA Engine         │
│   (IAM)      │    (Go)      │ (KRaft + Custom       │  (Policy Engine)       │
│  port 8180   │  port 8080   │  Java Authorizer)     │   port 8181            │
│              │              │  ports 9093 / 29092   │                        │
├──────────────┴──────────────┴──────────────────────┴────────────────────────┤
│                          Supporting Services                                 │
│   Prometheus (9090)   Grafana (3000)   plugin-builder (init container)       │
└─────────────────────────────────────────────────────────────────────────────┘

Authentication & authorisation flow:

  Client App
     │
     │ 1. POST /api/v1/login  (username + password + tenant_id)
     ▼
  Auth Service ─────────────────────────────────────────────────►  Keycloak
     │                                                            Direct Grant
     │ 2. Returns short-lived user JWT
     │
     │ 3. POST /api/v1/token-exchange  (subject_token + target_audience=kafka-broker)
     ▼
  Auth Service ─────────────────────────────────────────────────►  Keycloak
     │                                                            Token Exchange
     │ 4. Returns kafka-broker scoped JWT
     │    Claims: { tenant_id, roles, aud: "kafka-broker" }
     │
     │ 5. Produce / Consume via SASL/OAUTHBEARER
     ▼
  Kafka Broker
     │
     │ 6. Validate JWT signature against Keycloak JWKS endpoint
     │
     │ 7. Authorise operation
     │      ├─ CustomKafkaAuthorizer  (built-in, fast, in-process)
     │      └─ OpaKafkaAuthorizer     (external call to OPA REST API)
     ▼
  Topic / Consumer Group / Cluster resource
```

### Tenant Isolation

Topics follow the `{tenant_id}-{name}` naming convention.  The authorizer
extracts `tenant_id` from the JWT claim and rejects any access where the topic
prefix does not match, even if the JWT signature is valid.

```
  tenant-a user                    tenant-b user
       │                                │
       │  tenant-a-events  ✓ ALLOW      │  tenant-b-orders  ✓ ALLOW
       │  tenant-b-events  ✗ DENY       │  tenant-a-events  ✗ DENY
       │  orders (no prefix) ✗ DENY     │  orders (no prefix) ✗ DENY
```

---

## Quick Start

### Prerequisites

| Requirement | Version |
|-------------|---------|
| Docker | 24+ |
| Docker Compose | 2.20+ |
| Make | optional |
| RAM | 8 GB minimum |
| Disk | 4 GB free |

### 1. Clone and configure

```bash
git clone https://github.com/your-org/kafka-oauth-go.git
cd kafka-oauth-go
cp .env.example .env   # review and adjust secrets before starting
```

### 2. Generate TLS certificates

```bash
./scripts/generate-certs.sh
```

This creates `certs/ca.crt`, `certs/kafka.crt`, and `certs/kafka.key` used for
the SASL_SSL listener.

### 3. Start the full stack

```bash
docker compose up -d
```

The plugin-builder init container compiles the Java authorizer before Kafka
starts.  First startup takes 3–5 minutes.  Subsequent starts are faster because
Maven dependencies are cached.

### 4. Check health

```bash
docker compose ps
# All services should show "healthy" or "running"
```

Wait until Keycloak shows `healthy` before proceeding.

### 5. Initialise Keycloak realm and Kafka topics

```bash
# Import kafka-realm (if not auto-imported via --import-realm)
docker compose exec keycloak /opt/keycloak/bin/kc.sh import \
  --file /opt/keycloak/data/import/realm-export.json

# Create topics
./scripts/init-kafka-topics.sh
```

### 6. Run integration tests

```bash
docker compose run --rm test-client
```

---

## Service Endpoints

| Service | URL | Default Credentials |
|---------|-----|---------------------|
| Keycloak Admin Console | http://localhost:8180 | admin / admin_password |
| Auth Service | http://localhost:8080 | - |
| Kafka (SASL_SSL) | localhost:9093 | token-based |
| Kafka (Plaintext, internal) | localhost:29092 | no auth |
| OPA | http://localhost:8181 | - |
| Prometheus | http://localhost:9090 | - |
| Grafana | http://localhost:3000 | admin / admin_password |

---

## API Examples with curl

### 1. Login (Direct Access Grant)

```bash
curl -s -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice_password", "tenant_id": "tenant-a"}' \
  | jq .
```

Expected response:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 300,
  "tenant_id": "tenant-a"
}
```

### 2. Token Exchange for Kafka

```bash
# Step 1 – obtain user token
USER_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice_password", "tenant_id": "tenant-a"}' \
  | jq -r .access_token)

# Step 2 – exchange for kafka-broker scoped token
KAFKA_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/token-exchange \
  -H "Content-Type: application/json" \
  -d "{
        \"subject_token\": \"$USER_TOKEN\",
        \"target_audience\": \"kafka-broker\",
        \"tenant_id\": \"tenant-a\"
      }" \
  | jq -r .access_token)

echo "Kafka token: ${KAFKA_TOKEN:0:80}..."
```

### 3. Introspect Token

```bash
curl -s -X POST http://localhost:8080/api/v1/introspect \
  -H "Content-Type: application/json" \
  -d "{\"token\": \"$KAFKA_TOKEN\"}" \
  | jq .
```

### 4. Refresh Token

```bash
REFRESH_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "alice_password", "tenant_id": "tenant-a"}' \
  | jq -r .refresh_token)

curl -s -X POST http://localhost:8080/api/v1/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}" \
  | jq .
```

### 5. Decode JWT Claims

```bash
# The second segment of a JWT is the payload (base64url-encoded JSON)
echo "$KAFKA_TOKEN" | cut -d'.' -f2 \
  | awk '{printf "%s", $0}' \
  | base64 -d 2>/dev/null \
  | jq .
```

Expected decoded claims for a kafka-broker token:

```json
{
  "iss": "http://keycloak:8080/realms/kafka-realm",
  "sub": "alice-user-id",
  "aud": "kafka-broker",
  "azp": "auth-service",
  "preferred_username": "alice",
  "tenant_id": "tenant-a",
  "roles": ["kafka-producer", "kafka-consumer"],
  "exp": 1700001234,
  "iat": 1700000934,
  "jti": "abc123..."
}
```

### 6. Direct Keycloak Token Exchange (bypassing auth-service)

```bash
# Obtain user token via Keycloak directly
KC_USER_TOKEN=$(curl -s \
  -X POST "http://localhost:8180/realms/kafka-realm/protocol/openid-connect/token" \
  -d "client_id=kafka-client" \
  -d "client_secret=kafka-client-secret" \
  -d "grant_type=password" \
  -d "username=alice" \
  -d "password=alice_password" \
  -d "scope=kafka-access openid" \
  | jq -r .access_token)

# Exchange for kafka-broker token
KC_KAFKA_TOKEN=$(curl -s \
  -X POST "http://localhost:8180/realms/kafka-realm/protocol/openid-connect/token" \
  -d "client_id=auth-service" \
  -d "client_secret=auth-service-secret" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=$KC_USER_TOKEN" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "audience=kafka-broker" \
  | jq -r .access_token)

echo "KC Kafka token: ${KC_KAFKA_TOKEN:0:80}..."
```

---

## Running Tests

### Automated Integration Test Suite

```bash
# Run all 4 scenarios and print results table
docker compose run --rm test-client

# With debug logging
docker compose run --rm -e LOG_LEVEL=debug test-client
```

The test client runs these scenarios in order:

| # | Scenario | Expected |
|---|----------|----------|
| 1 | alice produces 3 messages to `tenant-a-events`, then consumes them | SUCCESS |
| 2 | alice attempts to write to `tenant-b-events` | DENIED |
| 3 | bob produces 2 messages to `tenant-b-orders`, then consumes them | SUCCESS |
| 4 | alice attempts to write to `orders` (no tenant prefix) | DENIED |

Sample output:

```
╔══════════════════════════════════════════════════════════════════╗
║                    KAFKA OAUTH TEST RESULTS                      ║
╠════════════════════════════════════╦══════════════╦═════════════╣
║ Scenario                           ║ Expected     ║ Result      ║
╠════════════════════════════════════╬══════════════╬═════════════╣
║ Tenant A: produce to own topic     ║ SUCCESS      ║ ✓ PASS      ║
║ Tenant A: cross-tenant access      ║ DENIED       ║ ✓ PASS      ║
║ Tenant B: produce to own topic     ║ SUCCESS      ║ ✓ PASS      ║
║ Wrong topic prefix                 ║ DENIED       ║ ✓ PASS      ║
╚════════════════════════════════════╩══════════════╩═════════════╝
```

### Manual Testing with kcat / kafkacat

```bash
# Export token
KAFKA_TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/token-exchange \
  -H "Content-Type: application/json" \
  -d "{\"subject_token\": \"$USER_TOKEN\", \"target_audience\": \"kafka-broker\", \"tenant_id\": \"tenant-a\"}" \
  | jq -r .access_token)

# Produce to own topic (should SUCCEED for tenant-a)
echo '{"event":"test"}' | kcat \
  -b localhost:9093 \
  -X security.protocol=SASL_SSL \
  -X sasl.mechanism=OAUTHBEARER \
  -X "sasl.oauthbearer.config=oauth_token=$KAFKA_TOKEN" \
  -X ssl.ca.location=./certs/ca.crt \
  -t tenant-a-events -P

# Produce to wrong tenant topic (should FAIL)
echo '{"event":"test"}' | kcat \
  -b localhost:9093 \
  -X security.protocol=SASL_SSL \
  -X sasl.mechanism=OAUTHBEARER \
  -X "sasl.oauthbearer.config=oauth_token=$KAFKA_TOKEN" \
  -X ssl.ca.location=./certs/ca.crt \
  -t tenant-b-events -P
# Expected: ERROR TOPIC_AUTHORIZATION_FAILED

# Consume from own topic
kcat \
  -b localhost:9093 \
  -X security.protocol=SASL_SSL \
  -X sasl.mechanism=OAUTHBEARER \
  -X "sasl.oauthbearer.config=oauth_token=$KAFKA_TOKEN" \
  -X ssl.ca.location=./certs/ca.crt \
  -t tenant-a-events -C -o beginning -e
```

---

## Multi-Tenancy

### Tenant Isolation Model

The platform enforces three layers of isolation:

1. **JWT claim** – The `tenant_id` claim in the Kafka token is set by Keycloak
   and cannot be forged by the client.
2. **Authorizer** – Every Kafka operation is evaluated against a policy that
   verifies `topic_name.startsWith(tenant_id + "-")`.
3. **Consumer group** – Consumer groups must also carry the tenant prefix, so
   cross-tenant group coordination is impossible.

### Adding a New Tenant

```bash
# 1. Create Kafka topics
docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:29092 \
  --create --topic tenant-c-events \
  --partitions 3 --replication-factor 1 \
  --config retention.ms=604800000

docker compose exec kafka /opt/kafka/bin/kafka-topics.sh \
  --bootstrap-server localhost:29092 \
  --create --topic tenant-c-orders \
  --partitions 3 --replication-factor 1

# 2. Create group in Keycloak
ADMIN_TOKEN=$(curl -s \
  -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli" -d "grant_type=password" \
  -d "username=admin" -d "password=admin_password" \
  | jq -r .access_token)

curl -s -X POST "http://localhost:8180/admin/realms/kafka-realm/groups" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "tenant-c-users",
    "attributes": {"tenant_id": ["tenant-c"]},
    "realmRoles": ["kafka-producer", "kafka-consumer"]
  }'

# 3. Create user charlie in Keycloak
curl -s -X POST "http://localhost:8180/admin/realms/kafka-realm/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "charlie",
    "enabled": true,
    "emailVerified": true,
    "firstName": "Charlie",
    "lastName": "TenantC",
    "email": "charlie@tenant-c.example.com",
    "attributes": {"tenant_id": ["tenant-c"]},
    "credentials": [{"type":"password","value":"charlie_password","temporary":false}],
    "groups": ["/tenant-c-users"]
  }'

# 4. Add tenant-c to OPA data (opa/data/tenants.json), then reload OPA
docker compose exec opa curl -s -X PUT http://localhost:8181/v1/data/tenants/tenant-c \
  -H "Content-Type: application/json" \
  -d '{
    "id": "tenant-c",
    "name": "Tenant C",
    "topic_prefix": "tenant-c-",
    "quota_producer_byte_rate": 1048576,
    "quota_consumer_byte_rate": 2097152,
    "allowed_topics": ["events", "orders"],
    "admin_users": ["charlie-admin"]
  }'
```

### Topic Naming Convention

```
{tenant_id}-{short_name}

Examples:
  tenant-a-events          ✓
  tenant-a-orders          ✓
  tenant-b-notifications   ✓
  events                   ✗  (no tenant prefix → always denied)
  TENANT-A-events          ✗  (case-sensitive match)
```

---

## Switching to OPA Authorizer

By default the custom Java `CustomKafkaAuthorizer` is active (fast, in-process).
To switch to the OPA-backed authorizer:

```bash
# In .env
AUTHORIZER_CLASS=com.kafkaoauth.authorizer.OpaKafkaAuthorizer

# Or via override
AUTHORIZER_CLASS=com.kafkaoauth.authorizer.OpaKafkaAuthorizer \
  docker compose up -d kafka
```

The OPA authorizer calls `http://opa:8181/v1/data/kafka/authz/allow` with the
decision input derived from the Kafka `AuthorizableRequestContext`.

### OPA Policy Testing

```bash
# Evaluate a policy decision directly
curl -s -X POST http://localhost:8181/v1/data/kafka/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "principal": "alice",
      "tenant_id": "tenant-a",
      "roles": ["kafka-producer", "kafka-consumer"],
      "resource_type": "TOPIC",
      "resource_name": "tenant-a-events",
      "operation": "WRITE"
    }
  }' | jq .result
# Expected: true

# Test cross-tenant access (should be false)
curl -s -X POST http://localhost:8181/v1/data/kafka/authz/allow \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "principal": "alice",
      "tenant_id": "tenant-a",
      "roles": ["kafka-producer", "kafka-consumer"],
      "resource_type": "TOPIC",
      "resource_name": "tenant-b-events",
      "operation": "WRITE"
    }
  }' | jq .result
# Expected: false
```

---

## Observability

### Prometheus Queries

```promql
# Request rate to auth service (all endpoints)
rate(http_requests_total{job="auth-service"}[5m])

# Token exchange latency p99
histogram_quantile(0.99,
  rate(http_request_duration_seconds_bucket{
    job="auth-service",
    path="/api/v1/token-exchange"
  }[5m])
)

# Login success rate
sum(rate(token_exchange_total{success="true"}[5m]))
  /
sum(rate(token_exchange_total[5m]))

# Failed auth attempts per tenant
sum by (tenant_id) (
  rate(token_exchange_total{success="false"}[5m])
)

# Kafka authorizer decisions (custom metric from Java plugin)
sum by (decision, tenant_id, operation) (
  rate(kafka_authorizer_decisions_total[5m])
)

# OPA evaluation latency
histogram_quantile(0.95,
  rate(opa_request_duration_seconds_bucket[5m])
)
```

### Grafana Dashboards

Pre-built dashboards are provisioned automatically on first start:

| Dashboard | Description |
|-----------|-------------|
| Kafka OAuth Overview | Auth success/failure rates, token exchange latency |
| Tenant Activity | Per-tenant produce/consume rates, denied requests |
| OPA Performance | Policy evaluation latency, cache hit rate |

Access at http://localhost:3000 with credentials `admin / admin_password`.

### Kafka Audit Logs

The custom authorizer writes structured JSON audit events to the Kafka
`_kafka_auth_audit` internal topic (admin access only):

```json
{
  "ts": "2024-01-15T10:30:00Z",
  "principal": "alice",
  "tenant_id": "tenant-a",
  "resource_type": "TOPIC",
  "resource_name": "tenant-a-events",
  "operation": "WRITE",
  "decision": "ALLOW",
  "client_ip": "172.20.0.5"
}
```

Consume audit events:

```bash
docker compose exec kafka /opt/kafka/bin/kafka-console-consumer.sh \
  --bootstrap-server localhost:29092 \
  --topic _kafka_auth_audit \
  --from-beginning
```

---

## Troubleshooting

### Common Issues

#### Kafka cannot connect to Keycloak (JWKS endpoint)

```bash
# Check Keycloak is healthy and JWKS endpoint is reachable from inside Kafka container
docker compose logs keycloak | grep -i "started\|error"
docker compose exec kafka curl -sf \
  http://keycloak:8080/realms/kafka-realm/protocol/openid-connect/certs \
  | jq .

# If DNS fails: verify the docker-compose network and hostname
docker compose exec kafka nslookup keycloak
```

#### Token Exchange returns 400 / 401

```bash
# Verify token-exchange feature is enabled in realm attributes
docker compose logs keycloak | grep -i "token-exchange"

# Check the realm export has  "token-exchange": "true"  in .attributes
curl -s http://localhost:8180/realms/kafka-realm/.well-known/openid-configuration \
  | jq '."token_endpoint_auth_methods_supported"'

# Verify auth-service client has the permission to exchange tokens targeting kafka-broker
# (check authorizationSettings in realm-export.json)
```

#### Authorization denied for a valid user

```bash
# 1. Decode the Kafka token and inspect claims
echo $KAFKA_TOKEN | cut -d'.' -f2 \
  | awk '{printf "%s", $0}' | base64 -d 2>/dev/null | jq .

# 2. Verify tenant_id claim matches the topic prefix
# e.g. tenant_id="tenant-a" → must use topics starting with "tenant-a-"

# 3. Check Kafka authorizer decision logs
docker compose logs kafka | grep -E "ALLOW|DENY|authorizer"

# 4. Check OPA decision log (if OPA authorizer is active)
docker compose logs opa | grep -E "decision|allow|deny" | tail -20
```

#### Java plugin not loaded

```bash
# Check plugin builder output
docker compose logs plugin-builder

# Verify JAR is present in plugin directory
docker compose exec kafka ls -lh /opt/kafka/plugins/
# Should show: kafka-oauth-plugins.jar

# Check Kafka startup for plugin loading
docker compose logs kafka | grep -i "authorizer\|plugin\|ClassLoader"
```

#### Keycloak realm import fails on startup

```bash
# Manually import via the admin REST API
ADMIN_TOKEN=$(curl -s \
  -X POST "http://localhost:8180/realms/master/protocol/openid-connect/token" \
  -d "client_id=admin-cli&grant_type=password&username=admin&password=admin_password" \
  | jq -r .access_token)

curl -s -X POST "http://localhost:8180/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d @keycloak/realm-export.json
```

#### TLS / certificate errors

```bash
# Regenerate certs
rm -rf certs/ && ./scripts/generate-certs.sh

# Verify cert CN matches the broker hostname
openssl x509 -in certs/kafka.crt -noout -subject -altname

# Re-create containers that mount the certs volume
docker compose up -d --force-recreate kafka
```

---

## Security Considerations

- **Secrets management**: All client secrets in `realm-export.json` and `.env`
  are development defaults.  Replace with Docker Secrets, HashiCorp Vault, or
  a Kubernetes Secret in production.
- **TLS**: The self-signed CA in `certs/` is for development only.  Use a
  properly-signed certificate from an internal CA or a public CA for production.
- **Token lifetime**: The 300-second access token lifetime is suitable for
  production.  Shorter lifetimes increase Keycloak load; longer lifetimes
  increase the window of risk if a token is leaked.
- **Rate limiting**: The auth-service enforces 100 requests/second per IP via
  middleware.  Adjust in `services/auth-service/internal/config/config.go`.
- **Audit logs**: Authorizer decisions are written to `_kafka_auth_audit`.
  In production, archive this topic to object storage for compliance.
- **Network policy**: In Kubernetes, add NetworkPolicies so only the Kafka
  broker can reach Keycloak on the token introspection / JWKS endpoints.
- **Admin credentials**: Change the `admin / admin_password` Keycloak master
  realm credentials immediately after provisioning.
- **JWKS caching**: The custom login callback handler caches the JWKS keys for
  60 seconds.  Adjust `OAUTH_JWKS_CACHE_SECONDS` to balance security vs load.

---

## Project Structure

```
kafka-oauth-go/
├── docker-compose.yml          # Full stack definition
├── .env                        # Environment variables (dev defaults)
├── certs/                      # TLS certificates (generated, gitignored)
│   ├── ca.crt
│   ├── kafka.crt
│   └── kafka.key
├── config/
│   ├── kafka/
│   │   └── log4j.properties    # Kafka / authorizer log levels
│   ├── prometheus/
│   │   └── prometheus.yml      # Scrape configs
│   └── grafana/
│       └── provisioning/
│           └── datasources/
│               └── prometheus.yml
├── custom-plugins/             # Java: Kafka SASL/OAuth plugins
│   ├── pom.xml
│   └── src/main/java/com/kafkaoauth/
│       ├── OAuthBearerLoginCallbackHandler.java
│       ├── OAuthBearerValidatorCallbackHandler.java
│       └── authorizer/
│           ├── CustomKafkaAuthorizer.java
│           ├── OpaKafkaAuthorizer.java
│           ├── TenantTopicPolicy.java
│           └── ClaimStore.java
├── services/
│   ├── auth-service/           # Go: Token proxy + exchange service
│   │   ├── go.mod
│   │   ├── internal/
│   │   │   ├── config/config.go
│   │   │   ├── handlers/
│   │   │   │   ├── login.go
│   │   │   │   ├── token_exchange.go
│   │   │   │   └── refresh.go
│   │   │   └── keycloak/client.go
│   │   └── Dockerfile
│   └── test-client/            # Go: Integration test suite
│       ├── go.mod
│       ├── main.go             # Test scenarios + results table
│       ├── pkg/
│       │   ├── auth/client.go  # Auth-service HTTP client
│       │   └── kafka/client.go # Kafka SASL/OAUTHBEARER client
│       └── Dockerfile
├── keycloak/
│   └── realm-export.json       # Kafka realm: clients, users, roles, scopes
├── opa/
│   ├── policies/
│   │   └── kafka_authz.rego    # Rego policy: tenant isolation + RBAC
│   └── data/
│       └── tenants.json        # Tenant configuration data
└── scripts/
    ├── generate-certs.sh       # Self-signed CA + broker cert
    ├── init-kafka-topics.sh    # Create tenant topics
    └── init-keycloak.sh        # Keycloak realm bootstrap helper
```

---

## Environment Variables Reference

### Auth Service

| Variable | Default | Description |
|----------|---------|-------------|
| `KEYCLOAK_URL` | `http://keycloak:8080` | Keycloak base URL |
| `KEYCLOAK_REALM` | `kafka-realm` | Realm name |
| `KEYCLOAK_CLIENT_ID` | `auth-service` | Client ID |
| `KEYCLOAK_CLIENT_SECRET` | `auth-service-secret` | Client secret |
| `PORT` | `8080` | Auth service listen port |
| `LOG_LEVEL` | `info` | Logging level |

### Test Client

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_SERVICE_URL` | `http://auth-service:8080` | Auth service base URL |
| `KAFKA_BOOTSTRAP` | `kafka:9093` | Kafka broker address |
| `SECURITY_PROTO` | `SASL_SSL` | `SASL_SSL` or `PLAINTEXT` |
| `SASL_MECHANISM` | `OAUTHBEARER` | SASL mechanism |
| `CA_CERT_PATH` | `/certs/ca.crt` | Path to CA certificate |
| `ALICE_USERNAME` | `alice` | Tenant-A test user |
| `ALICE_PASSWORD` | `alice_password` | Tenant-A test password |
| `ALICE_TENANT_ID` | `tenant-a` | Tenant-A identifier |
| `BOB_USERNAME` | `bob` | Tenant-B test user |
| `BOB_PASSWORD` | `bob_password` | Tenant-B test password |
| `BOB_TENANT_ID` | `tenant-b` | Tenant-B identifier |

### Kafka (via docker-compose .env)

| Variable | Default | Description |
|----------|---------|-------------|
| `KAFKA_OAUTH_JWKS_URL` | `http://keycloak:8080/realms/kafka-realm/...` | JWKS endpoint |
| `KAFKA_OAUTH_EXPECTED_AUDIENCE` | `kafka-broker` | Required JWT audience |
| `KAFKA_OAUTH_EXPECTED_ISSUER` | `http://keycloak:8080/realms/kafka-realm` | Required JWT issuer |
| `AUTHORIZER_CLASS` | `com.kafkaoauth.authorizer.CustomKafkaAuthorizer` | Authorizer implementation |
| `OPA_URL` | `http://opa:8181` | OPA base URL (OpaKafkaAuthorizer only) |

---

## License

Apache License 2.0 – see [LICENSE](LICENSE) for details.
