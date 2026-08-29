# Keycloak browser MFA verification

The reviewed local-account browser flow is `email-platform-browser-mfa`. A
fresh authentication enters `email-platform-browser-mfa-forms` and must execute
`auth-username-password-form` as `REQUIRED`, followed by `auth-otp-form` as
`REQUIRED`. The `auth-cookie` alternative is only for an already authenticated
SSO session; no password-only, conditional, disabled, or alternative OTP path is
approved.

`CONFIGURE_TOTP` with `defaultAction=true` enrolls a TOTP credential. Enrollment is not the OTP challenge:
the bound browser flow must still contain the required
`auth-otp-form` execution. Desktop and Web clients must keep
`directAccessGrantsEnabled=false` so they cannot bypass the browser MFA flow with
the resource-owner password grant.

## Repository preflight

```powershell
python scripts/verify_keycloak_realm.py
python -m unittest tests.test_keycloak_realm -v
```

These checks parse the realm JSON and reject a missing/wrong flow binding,
password-only or extra flow, duplicate aliases/executions, reordered password
and OTP steps, weakened OTP requirements, unreviewed execution configuration,
disabled enrollment, and enabled direct grants. Static validation has
`production_acceptance=false` and does not prove that a target Keycloak imported
the realm successfully.

## Target-environment verification

1. Import the reviewed realm through the controlled Keycloak deployment path.
   Export it again through the Admin API and record the realm export SHA-256.
2. Confirm `browserFlow=email-platform-browser-mfa` and compare both reviewed
   flow aliases, exact execution order, requirements, and priorities with the
   repository JSON.
3. Treat the flow binding as an MFA cutover. Raise the realm `notBefore` through
   the controlled Admin API and invoke `logout-all` so browser sessions and
   tokens created under the previous flow cannot enter through the Cookie
   alternative. Prove an old session cookie, access token, and refresh token are
   rejected before continuing.
4. With a new non-privileged test user, complete password authentication and
   `CONFIGURE_TOTP` enrollment. End the SSO session before the challenge test.
5. Start a fresh authorization-code + PKCE login. Prove that password-only does not issue an authorization code,
   then prove password plus a valid OTP does.
6. Repeat the fresh-login rejection with an invalid OTP and confirm the reviewed
   `LOGIN_ERROR` event is present without credentials or OTP values.
7. Confirm password-grant requests for `email-platform-desktop` and
   `email-platform-web` are rejected because direct grants are disabled.

Record UTC timestamps, test-user identifiers, trace/event correlation, the
export hash, `notBefore`/`logout-all` evidence, old-session/token rejection,
password-only and invalid-OTP rejection, password-plus-OTP success, and an
independent reviewer. Never record the password, TOTP seed, or OTP code.
