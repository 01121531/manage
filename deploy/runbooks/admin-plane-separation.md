# Keycloak and Vault administration separation

Apply this control before production acceptance and after every administrator,
SSO-group, or break-glass change.

1. Assign Keycloak administration and Vault administration to distinct human administrator groups.
   A person, group, service account, API token, password, recovery key, or automation
   credential must not administer both control planes during normal operation.
2. Export redacted identity-provider membership evidence and record a SHA-256
   digest for each group. Record stable subject/entity identifiers, never names,
   email addresses, passwords, tokens, recovery keys, or session cookies.
3. Using one non-privileged test identity from each group, prove that the
   Keycloak administrator is denied Vault administration and the Vault
   administrator is denied Keycloak administration. Retain both denied-event
   trace IDs and the corresponding Keycloak/Vault audit-event identifiers.
4. Keep each control plane's recovery material with a different custodian.
   Break-glass activation requires two-person approval, a bounded incident or
   change ticket, and immediate post-use credential rotation plus session/token
   revocation.
5. An independent security reviewer compares the two membership digests,
   denied-event evidence, custodians, and ticket. Any overlap, shared credential,
   missing denial, or unrotated break-glass credential blocks production.

Repository checks prove only that this procedure and its evidence fields exist.
The target-environment membership, access-denial, audit, and rotation artifacts
are mandatory production evidence and must remain outside the repository.
