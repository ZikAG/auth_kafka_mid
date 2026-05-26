#!/bin/bash
# init-keycloak.sh
# Supplementary Keycloak initialization script.
# Assumes the kafka-realm was already imported via realm-export.json.
# This script creates test users (alice, bob) and prints status.
#
# Usage: ./scripts/init-keycloak.sh
# Prerequisites: curl, jq

set -e

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:8180}"
KEYCLOAK_REALM="kafka-realm"
ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
ADMIN_PASSWORD="${KEYCLOAK_ADMIN_PASSWORD:-admin_password}"
MASTER_REALM="master"

MAX_RETRIES=20
RETRY_INTERVAL=5

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()    { echo -e "${GREEN}[keycloak-init] INFO:${NC}  $*"; }
log_warn()    { echo -e "${YELLOW}[keycloak-init] WARN:${NC}  $*"; }
log_error()   { echo -e "${RED}[keycloak-init] ERROR:${NC} $*"; }
log_section() { echo -e "${BLUE}[keycloak-init] ===== $* =====${NC}"; }

# ─── Wait for Keycloak to be ready ──────────────────────────────────────────
log_section "Waiting for Keycloak"
RETRIES=0
until curl -sf "${KEYCLOAK_URL}/health/ready" > /dev/null 2>&1; do
  RETRIES=$((RETRIES + 1))
  if [ "${RETRIES}" -ge "${MAX_RETRIES}" ]; then
    log_error "Keycloak not ready after ${MAX_RETRIES} attempts. Exiting."
    exit 1
  fi
  log_warn "Keycloak not ready (attempt ${RETRIES}/${MAX_RETRIES}). Retrying in ${RETRY_INTERVAL}s ..."
  sleep "${RETRY_INTERVAL}"
done
log_info "Keycloak is ready at ${KEYCLOAK_URL}"

# ─── Get admin access token ─────────────────────────────────────────────────
log_section "Obtaining Admin Token"
ADMIN_TOKEN=$(curl -sf -X POST \
  "${KEYCLOAK_URL}/realms/${MASTER_REALM}/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=${ADMIN_USER}" \
  -d "password=${ADMIN_PASSWORD}" \
  | jq -r '.access_token')

if [ -z "${ADMIN_TOKEN}" ] || [ "${ADMIN_TOKEN}" = "null" ]; then
  log_error "Failed to obtain admin token. Check credentials."
  exit 1
fi
log_info "Admin token obtained successfully."

# ─── Check if kafka-realm exists ────────────────────────────────────────────
log_section "Checking Realm Status"
REALM_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo "000")

if [ "${REALM_STATUS}" = "200" ]; then
  log_info "Realm '${KEYCLOAK_REALM}' exists (imported via realm-export.json)."
else
  log_warn "Realm '${KEYCLOAK_REALM}' not found (HTTP ${REALM_STATUS})."
  log_warn "Ensure realm-export.json is present in ./keycloak/ and Keycloak has imported it."
  log_warn "Keycloak may still be importing. Waiting 15s and retrying ..."
  sleep 15
  REALM_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo "000")
  if [ "${REALM_STATUS}" != "200" ]; then
    log_error "Realm '${KEYCLOAK_REALM}' still not available. Cannot create users."
    exit 1
  fi
  log_info "Realm '${KEYCLOAK_REALM}' is now available."
fi

# ─── Helper: get role ID ─────────────────────────────────────────────────────
get_role_id() {
  ROLE_NAME="$1"
  curl -sf \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE_NAME}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | jq -r '.id // empty'
}

# ─── Helper: create or update user ──────────────────────────────────────────
create_user() {
  USERNAME="$1"
  PASSWORD="$2"
  EMAIL="$3"
  FIRST_NAME="$4"
  LAST_NAME="$5"
  TENANT_ID="$6"

  log_info "Creating user: ${USERNAME} (tenant: ${TENANT_ID}) ..."

  # Check if user already exists
  EXISTING_USER=$(curl -sf \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${USERNAME}&exact=true" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | jq -r '.[0].id // empty')

  if [ -n "${EXISTING_USER}" ]; then
    log_warn "User '${USERNAME}' already exists (id: ${EXISTING_USER}). Updating password ..."
    # Update password
    curl -sf -X PUT \
      "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/${EXISTING_USER}/reset-password" \
      -H "Authorization: Bearer ${ADMIN_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"type\":\"password\",\"value\":\"${PASSWORD}\",\"temporary\":false}"
    echo "${EXISTING_USER}"
    return 0
  fi

  # Create user with tenant_id attribute
  HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "{
      \"username\": \"${USERNAME}\",
      \"email\": \"${EMAIL}\",
      \"firstName\": \"${FIRST_NAME}\",
      \"lastName\": \"${LAST_NAME}\",
      \"enabled\": true,
      \"emailVerified\": true,
      \"attributes\": {
        \"tenant_id\": [\"${TENANT_ID}\"]
      },
      \"credentials\": [{
        \"type\": \"password\",
        \"value\": \"${PASSWORD}\",
        \"temporary\": false
      }]
    }")

  if [ "${HTTP_STATUS}" != "201" ]; then
    log_error "Failed to create user '${USERNAME}' (HTTP ${HTTP_STATUS})."
    return 1
  fi

  # Retrieve the new user ID
  NEW_USER_ID=$(curl -sf \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users?username=${USERNAME}&exact=true" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    | jq -r '.[0].id')

  log_info "User '${USERNAME}' created with id: ${NEW_USER_ID}"
  echo "${NEW_USER_ID}"
}

# ─── Helper: assign realm role to user ──────────────────────────────────────
assign_role() {
  USER_ID="$1"
  ROLE_NAME="$2"

  ROLE_DATA=$(curl -sf \
    "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/roles/${ROLE_NAME}" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" 2>/dev/null || echo "null")

  if [ "${ROLE_DATA}" = "null" ] || [ -z "${ROLE_DATA}" ]; then
    log_warn "Role '${ROLE_NAME}' not found in realm '${KEYCLOAK_REALM}'. Skipping assignment."
    return 0
  fi

  ROLE_ID=$(echo "${ROLE_DATA}" | jq -r '.id')
  log_info "  Assigning role '${ROLE_NAME}' (id: ${ROLE_ID}) to user ${USER_ID} ..."

  HTTP_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" \
    -X POST "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users/${USER_ID}/role-mappings/realm" \
    -H "Authorization: Bearer ${ADMIN_TOKEN}" \
    -H "Content-Type: application/json" \
    -d "[{\"id\":\"${ROLE_ID}\",\"name\":\"${ROLE_NAME}\"}]")

  if [ "${HTTP_STATUS}" = "204" ]; then
    log_info "  Role '${ROLE_NAME}' assigned successfully."
  else
    log_warn "  Role assignment returned HTTP ${HTTP_STATUS} (may already be assigned)."
  fi
}

# ─── Create Alice (Tenant A) ────────────────────────────────────────────────
log_section "Creating User: alice (tenant-a)"
ALICE_ID=$(create_user \
  "alice" \
  "${ALICE_PASSWORD:-alice_password}" \
  "alice@tenant-a.example.com" \
  "Alice" \
  "Smith" \
  "tenant-a")

if [ -n "${ALICE_ID}" ]; then
  assign_role "${ALICE_ID}" "kafka-producer"
  assign_role "${ALICE_ID}" "kafka-consumer"
  log_info "User 'alice' fully configured."
else
  log_error "Failed to create or retrieve user 'alice'."
fi

# ─── Create Bob (Tenant B) ──────────────────────────────────────────────────
log_section "Creating User: bob (tenant-b)"
BOB_ID=$(create_user \
  "bob" \
  "${BOB_PASSWORD:-bob_password}" \
  "bob@tenant-b.example.com" \
  "Bob" \
  "Jones" \
  "tenant-b")

if [ -n "${BOB_ID}" ]; then
  assign_role "${BOB_ID}" "kafka-producer"
  assign_role "${BOB_ID}" "kafka-consumer"
  log_info "User 'bob' fully configured."
else
  log_error "Failed to create or retrieve user 'bob'."
fi

# ─── Print status summary ────────────────────────────────────────────────────
log_section "Status Summary"

echo ""
log_info "Realm: ${KEYCLOAK_REALM}"

echo ""
log_info "Users in realm:"
curl -sf \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/users" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq -r '.[] | "  - \(.username) (id: \(.id), enabled: \(.enabled), tenant_id: \(.attributes.tenant_id[0] // "N/A"))"'

echo ""
log_info "Realm roles:"
curl -sf \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/roles" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq -r '.[] | "  - \(.name)"'

echo ""
log_info "Clients in realm:"
curl -sf \
  "${KEYCLOAK_URL}/admin/realms/${KEYCLOAK_REALM}/clients?briefRepresentation=true" \
  -H "Authorization: Bearer ${ADMIN_TOKEN}" \
  | jq -r '.[] | select(.clientId != null) | "  - \(.clientId) (enabled: \(.enabled))"'

echo ""
log_section "Keycloak Initialization Complete"
log_info "Keycloak URL:  ${KEYCLOAK_URL}"
log_info "Realm:         ${KEYCLOAK_REALM}"
log_info "Admin console: ${KEYCLOAK_URL}/admin/master/console/#/${KEYCLOAK_REALM}"
echo ""
log_info "Test credentials:"
log_info "  alice / ${ALICE_PASSWORD:-alice_password}  (tenant-a, roles: kafka-producer, kafka-consumer)"
log_info "  bob   / ${BOB_PASSWORD:-bob_password}    (tenant-b, roles: kafka-producer, kafka-consumer)"
echo ""
