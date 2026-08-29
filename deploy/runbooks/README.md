# Operational runbooks

Use these during incident handling and change control:

- [restore.md](./restore.md)
- [vault-restore.md](./vault-restore.md)
- [vault-audit.md](./vault-audit.md)
- [phase6-rehearsal.md](./phase6-rehearsal.md)
- [role-training.md](./role-training.md)
- [keycloak-audit.md](./keycloak-audit.md)
- [keycloak-mfa.md](./keycloak-mfa.md)
- [internal-tls.md](./internal-tls.md)
- [runtime-secrets.md](./runtime-secrets.md)
- [private-secret-provenance.md](./private-secret-provenance.md)
- [migration-rollout.md](./migration-rollout.md)
- [container-release.md](./container-release.md)
- [container-logs.md](./container-logs.md)
- [deploy.md](./deploy.md)
- [rolling-release.md](./rolling-release.md)
- [dependency-audit.md](./dependency-audit.md)
- [ci-token-hygiene.md](./ci-token-hygiene.md)
- [alert-delivery.md](./alert-delivery.md)
- [rollback.md](./rollback.md)
- [device-revocation.md](./device-revocation.md)
- [admin-role-change.md](./admin-role-change.md)
- [key-rotation.md](./key-rotation.md)
- [incident-response.md](./incident-response.md)
- [admin-plane-separation.md](./admin-plane-separation.md)
- [nonproduction-data-boundary.md](./nonproduction-data-boundary.md)
- [target-intake-preflight.md](./target-intake-preflight.md)
- [../production-signoff-template.md](../production-signoff-template.md)
- [audit-archive.md](audit-archive.md)

`restore.md`, `rollback.md`, and `deploy.md` treat the PostgreSQL bundle and
Redis release backup as one recovery set. Redis artifacts use authenticated,
write-once, absolute repository-external paths and are release-bound before any
restore. A successful drill records restored key counts, representative TTL
samples, and proof that an expired key did not reappear; a Redis `PING` alone is
never restore evidence.

Phase 6 rehearsal and role-training JSON evidence uses the same single-file
write-once policy: an absent absolute repository-external path under a protected,
pre-existing directory is preflighted before the rehearsal or training-input
read, and a racing target wins without being replaced. The hard-link publication
closes only the leaf-name race; operators must still protect the parent directory
with target-platform ACLs against concurrent ancestor replacement.
