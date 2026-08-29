# Administrator role change

Use this runbook for any interactive-account role change. Direct role updates
are disabled; the legacy `PATCH /api/v1/admin/users/{user_id}/role` endpoint
returns HTTP 410.

## Preconditions

- Assign a requester and a different approver. Both must currently be active
  `platform_admin` users in the target tenant.
- Confirm the target user, current role, intended role, ticket/change reason,
  and expected impact on active tasks.
- Confirm Keycloak maps the configured
  `PLATFORM_ADMIN_ROLE_CHANGE_ACR` to the approved MFA flow. The default is
  `urn:email-platform:acr:mfa`.
- Never copy access tokens, MFA values, or credential material into the ticket.

## Request

1. In the Web user-management view, select the intended role and create the
   role-change request. The target role is not changed at this point.
2. Record the request ID, target user ID, requester, request trace ID, old role,
   new role, creation time, and expiry time in the change ticket.
3. Stop if the API returns 404, 409, or 422. Re-read the user and pending-request
   lists before deciding whether to submit a new request.

Only one pending request can exist for a target user. The default validity
window is 900 seconds and is bounded by
`PLATFORM_ADMIN_ROLE_CHANGE_TTL_SECONDS`.

## Independent approval

1. The approver opens the pending-request list and verifies the target, old
   role, new role, requester, ticket, and expiry.
2. The approver uses **重新 MFA 登录**. The resulting OIDC authentication must
   happen after the request creation time and must carry the exact configured
   ACR.
3. The approver submits approval once. Do not treat a timeout as a failure;
   refresh the request and user lists first.
4. A successful response has `status=applied`, the approver ID, approval trace
   ID, and applied time. A competing approval, expired request, target-role
   drift, self-approval, stale authentication, or wrong ACR fails closed.

## Evidence and recovery

- Verify `admin.user_role_change_requested`,
  `admin.user_role_change_approved`, and `admin.user_role_changed` audit events.
  The requester and approver must be different and the traces must match the
  recorded request and approval attempts.
- Verify the user list shows the new role. Existing bearer tokens are evaluated
  against the database on their next request, so the new authorization boundary
  takes effect without waiting for token expiry.
- When changing away from `operator`, verify active task, mail, card, upload,
  and outbox resources were compensated. Replaying approval on an already
  applied request returns 409 but safely retries this idempotent cleanup only
  while the target still has that applied role.
- If cleanup or state verification remains incomplete, stop the change, keep
  the evidence and trace IDs, and escalate through the incident runbook. Do not
  create a no-op role request as a repair mechanism.
