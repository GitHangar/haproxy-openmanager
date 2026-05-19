#!/usr/bin/env bash
# scripts/admin-mfa-reset-all.sh
# Issue #18 — v1.6.0 — Emergency: disable MFA for ALL users in one call.
#
# This is a break-glass tool. It calls POST /api/mfa/admin-reset-all on the
# backend with a strict, double-confirmed body and writes the action into the
# server's audit log (action=mfa.disabled.admin_bulk_reset). All users will be
# able to log in with username/password alone afterwards and must re-enroll if
# they want MFA again.
#
# Usage:
#   ./scripts/admin-mfa-reset-all.sh
#   API_URL=https://hap.example.com ADMIN_TOKEN=ey... ./scripts/admin-mfa-reset-all.sh
#
# Required: a JWT bearer token belonging to a user whose `users.is_admin = TRUE`.
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"
ADMIN_TOKEN="${ADMIN_TOKEN:-}"

if [ -z "$ADMIN_TOKEN" ]; then
  read -rsp "Admin Bearer token (user with is_admin=TRUE): " ADMIN_TOKEN
  echo
fi

if [ -z "$ADMIN_TOKEN" ]; then
  echo "ERROR: no admin token provided." >&2
  exit 1
fi

cat <<'WARN'
========================================================================
  WARNING — IRREVERSIBLE BULK ACTION
========================================================================
  This will:
    * set mfa_enabled = FALSE for every user
    * delete every backup code
    * invalidate all pending MFA login challenges and enrollments
    * write a permanent entry to user_activity_logs
  After this, all users can sign in with username/password only and must
  re-enroll MFA from the Users page.
========================================================================
WARN

read -rp "Type 'yes' to proceed: " confirm1
if [ "$confirm1" != "yes" ]; then
  echo "Aborted."
  exit 1
fi
read -rp "Type 'RESET ALL MFA' (exact) to confirm: " confirm2
if [ "$confirm2" != "RESET ALL MFA" ]; then
  echo "Aborted."
  exit 1
fi
read -rp "Reason (logged in audit): " reason
if [ -z "$reason" ]; then
  echo "Aborted: reason is required."
  exit 1
fi

# Compose JSON safely (python3 for proper JSON escaping; reliably available
# everywhere the backend already runs).
payload=$(python3 -c "
import json, sys
print(json.dumps({'confirm': 'RESET ALL MFA', 'reason': sys.argv[1]}))
" "$reason")

echo "Calling $API_URL/api/mfa/admin-reset-all ..."
http_response=$(curl -fsS -X POST "$API_URL/api/mfa/admin-reset-all" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d "$payload")

echo "$http_response"
echo
echo "Done. Verify in user_activity_logs: action='mfa.disabled.admin_bulk_reset'."
