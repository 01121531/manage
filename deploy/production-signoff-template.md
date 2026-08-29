# Production readiness signoff template

Release manifest:

- Release ID:
- Backend version:
- Frontend version:
- Migration head:
- Backup artifact:
- Vault snapshot artifact and SHA-256:
- Vault recovery-set, PostgreSQL manifest SHA-256 and schema-v2 HMAC evidence:
- Vault primary/secondary audit device and persistent-path evidence:
- Vault audit allowed/denied request correlation and raw-secret absence evidence:
- Vault audit 180-day retention, rotation, SIGHUP and capacity-alert evidence:
- Internal TLS CA fingerprint and nine unique leaf certificate/SAN/key evidence:
- Internal TLS API, JWKS, metrics and Alertmanager hostname-verification evidence:
- Internal TLS leaf/CA rotation drill and expiry-alert evidence:
- Internal/Edge TLS bounded stable PEM, unsafe-file/read-drift rejection and exact-limit result:
- Internal/Edge TLS and Vault sink `.env`/inventory 64 KiB single stable-read, strict UTF-8 and fixed-error result:
- Runtime secret-file verifier and protected Compose-render evidence:
- PostgreSQL/application/Redis/Keycloak secret file owner, mode and distinct-inode evidence:
- Runtime process argv/environment credential-absence evidence:
- Runtime credential rotation with old-secret rejection and redacted rollback evidence:
- Bounded container logging verifier and rendered production Compose evidence:
- Runtime LogConfig for all 11 base non-Vault containers and all 13 when both slots are retained:
- Container log rotation pilot UTC, retained-file counts and observed disk usage:
- Container logs versus database/Keycloak/Vault audit-retention acknowledgement:
- Migration baseline/head, reviewed expansion SHA-256 and compatibility-verifier evidence:
- Target N/N+1 expand/backfill rolling-rehearsal evidence:
- Audit archive schema/tool source commit, ciphertext/manifest SHA-256 and key ID:
- Audit archive tenant, half-open UTC window, row count and first/last key:
- Consecutive audit-window no-gap/no-overlap review evidence:
- Audit archive SELECT-only role, source-table before/after and zero-prune evidence:
- Independent audit archive decrypt/verify evidence:
- Audit archive WORM/object-lock mode, retention, deny-delete and lifecycle evidence:
- Audit archive operator and independent reviewer:
- Container release manifest:
- Repository release snapshot/frontend package JSON 64 KiB stable-read, unique-key, link/read-drift rejection and fixed-error result:
- Release snapshot backend/Compose/migration source 64 KiB stable-read, full-depth unique YAML mapping and candidate-file shape result:
- Shared production Compose verifier 64 KiB stable-read/unique-key YAML coverage across thirteen consumers and text-injection contracts result:
- Remaining raw Compose/Prometheus/Kubernetes multi-document/rolling Compose stable-read, full-depth unique-key and exact-source-text coverage result:
- CI/Security/Tag Release/container supply-chain workflow 64 KiB stable-read, full-depth unique-key and text-injection parity result:
- Repository secret scan 16 MiB stable-read, pruned traversal, unsafe-file/read-drift and fixed-error result:
- Edge/Web Nginx Dockerfile/config/script/env/canonical-route 64 KiB stable-read, strict UTF-8, unsafe-file/read-drift and fixed-error result:
- Backup/restore verifier eleven-asset 64 KiB single stable-snapshot, same-source module execution, import-registry restoration and fixed-error result:
- Internal TLS verifier seven-text-asset 64 KiB single stable-snapshot, same-source expiry-module execution and fixed-error result:
- Runtime Secret verifier six-text-asset 64 KiB stable default loading, injected-text bypass parity and fixed-error result:
- Vault isolation verifier six-text-asset 64 KiB single stable-snapshot and fixed-error result:
- Target-platform inventory environment-contract 64 KiB stable default loading, injected-text bypass parity and fixed alignment-error result:
- Chapter 13 realm/env two-asset 64 KiB stable default loading, unique-key realm, injected-text bypass parity and fixed-error result:
- Chapter 14 MVI quality-gate 64 KiB stable default loading, injected-text bypass parity and fixed-error result:
- CI workflow quality-gate 64 KiB stable default loading, injected-text bypass parity and fixed-error result:
- Compose environment verifier env/runtime-role two-asset 64 KiB stable default loading, partial/full injected-text bypass parity and fixed-error result:
- Container hardening verifier runtime-role 64 KiB single stable default loading and fixed-error result:
- Container supply-chain verifier API/Web/edge Dockerfile 64 KiB single stable default loading and fixed-error result:
- Deploy-release verifier production/development env, executor and upstream scanner 64 KiB single stable default loading and fixed-error result:
- Desktop-package verifier build/reachable-source 256 KiB single stable snapshot, AST and fixed-error result:
- HTTP error-boundary verifier four-source 256 KiB single stable snapshot, fixed read/syntax error and contract result:
- Keycloak realm verifier OIDC TypeScript 64 KiB single stable default loading and fixed-error result:
- Kubernetes portability runbook 64 KiB single stable default loading and fixed-error result:
- Monitoring verifier environment example 64 KiB single stable default loading and fixed-error result:
- OpenAPI client verifier four-artifact 256 KiB single stable-snapshot, CRLF normalization and fixed-error result:
- Phase 6 evidence-output verifier three-source 64 KiB single stable-snapshot, AST and fixed-error result:
- Chapter 13/14, phase matrix, completion ledger and requirement inventory 64 KiB stable-read/full-depth unique-key JSON result:
- Chapters 1–11 source-plan DOCX 5 MiB single stable-read SHA-256 binding, link/non-regular/read-drift/replacement rejection result:
- Keycloak realm/Kubernetes contracts/migration baseline 64 KiB stable-read/full-depth unique-key JSON result:
- Migration Python candidates single-read 64 KiB stable SHA-256/AST, link/non-regular/UTF-8/read-drift rejection result:
- Forward/rollback container, PostgreSQL and Redis manifest authenticated single-read SHA-256 binding result:
- Container release nine-input stable-read result (3 metadata <=64 KiB; 6 SBOM/SARIF <=32 MiB):
- CI/release SARIF reporter and third-party image gate 32 MiB stable-read, unique-key and link/read-drift rejection result:
- Desktop updater remote manifest 64 KiB unique-key parse, startup-ready marker 32-byte stable-read/non-resolved-leaf, and local notice 256-byte stable-read/unique-key/link/read-drift rejection result:
- Windows release-manifest final EXE 1–200 MiB stable 1 MiB-chunk size/SHA-256 binding, link/non-regular/truncate/append/replace/mode-drift rejection result:
- Desktop platform API/OIDC success and error response 64 KiB bounded-read, boundary-size acceptance, oversized-response rejection and full-depth unique-key parse result:
- Runtime Vault KV v1/v2 2xx response 64 KiB bounded-read, strict UTF-8, boundary-size acceptance, oversized-response rejection and full-depth unique-key parse result:
- Runtime Mail/Sub2 success response 64 KiB bounded-read, charset-independent strict UTF-8, boundary-size acceptance and full-depth unique-key parse result:
- Local HS256/OIDC RS256 Bearer JWT 8 KiB compact-token, 2/6/1 KiB decoded-segment, canonical Base64URL and full-depth unique-key preflight result:
- Persisted audit/card-event legacy JSON 64 KiB UTF-8 byte limit, boundary-size acceptance, full-depth unique-key parse and safe-empty fallback result:
- API OCI digest:
- Web OCI digest:
- Edge OCI digest:
- SBOM SHA-256 values:
- Trivy report SHA-256 values:
- Cosign certificate identity:
- Cosign OIDC issuer:
- Provenance attestation evidence:
- Stable container tag post-verification promotion and resolved-digest equality evidence:
- Forward deployment release tag, commit and migration head:
- Forward deployment container manifest SHA-256:
- Forward deployment expected and observed application OCI digests:
- Forward deployment five reviewed third-party OCI digest references:
- Forward deployment write-once terminal evidence file, whole-file SHA-256 and canonical payload SHA-256:
- Forward deployment Phase 0 target environment, canonical intake payload SHA-256 and requirements SHA-256:
- Phase 0 PCI/OIDC decision review references, canonical review times, exclusive validity deadlines and same-manifest projection result:
- Target-platform inventory review reference, canonical review time, exclusive validity deadline and same-manifest projection result:
- Phase 0 approval review reference/time/deadline, five exact input bindings and no-predated-input result:
- Strict-intake single UTC evaluation instant and trusted-time/non-authentication limitation acknowledgement:
- Release-execution immutable-history/no-invented-expiry acknowledgement and current Phase 0/evidence-index reuse result:
- Forward expected target/rollback projection stable 64 KiB unique-key parse result:
- Forward deployment terminal state, fixed error code, ordered phase UTC values and final Edge state:
- Forward deployment Cosign, SPDX attestation and provenance verification:
- Forward deployment preflight-before-edge-stop and edge-closed failure evidence:
- Forward deployment current rollback release tag, commit and migration head:
- Forward deployment authenticated schema-v5 rollback manifest SHA-256, MAC and freshness evidence:
- Forward deployment current running application OCI digests:
- Forward deployment zero-mutation rollback-readiness failure evidence:
- Forward deployment Git HEAD/manifest commit equality and clean tracked checkout evidence:
- Forward deployment explicit production Compose path/project and override absence evidence:
- Single-instance outage window and no-rolling-release acknowledgement:
- Web/API blue-green plan fingerprint, source/target slot and release identity:
- Web/API rolling execution evidence file and canonical payload SHA-256:
- Web/API rolling Phase 0 target environment, canonical intake payload SHA-256 and requirements SHA-256:
- Web/API rolling terminal state and ordered phase UTC values:
- Web/API current/target exact API, Web and unchanged Edge OCI digests:
- Web/API Worker Mail/Sub2 before/after digest equality evidence:
- Web/API route before/after and canonical source/target SHA-256 evidence:
- Web/API active/canonical route bounded stable-snapshot and unsafe-file rejection result:
- Web/API atomic paired route, Nginx test/reload and three-observation evidence:
- Web/API three public releasez result identities and UTC values:
- Web/API mixed-version readiness, alert continuity and connection-drain evidence:
- Web/API failure-injection switch-back and `route_unconfirmed` handling evidence:
- Web/API source-retained cleanup approval and independent operator/reviewer:
- Web/API-only scope and unchanged single-instance Worker acknowledgement:
- Web/API rolling pilot `production_acceptance=false` preflight acknowledgement:
- Third-party runtime image digest-lock status and unresolved blocker:
- CodeQL Python result:
- CodeQL JavaScript/TypeScript result:
- Python runtime/test/desktop-build dependency audit evidence:
- Full frontend dependency-tree audit evidence (including devDependencies):
- CI/Security/Release checkout `persist-credentials=false` verifier evidence:
- Explicit-token publication step and authenticated Git-write review evidence:
- Phase 6 CI rehearsal evidence, file SHA-256 and payload SHA-256 (preflight only):
- Phase 6 pilot input inventory, payload SHA-256 and same-manifest target inventory binding:
- Phase 6 pilot opaque roster/ownership references and approved UTC maintenance window:
- Phase 6 pilot-input sealed review/valid-until and maintenance-window validity result:
- Phase 6 target pilot evidence index and canonical payload SHA-256:
- Phase 6 pilot evidence release tag, commit and container-manifest SHA-256:
- Phase 6 selected release-execution ledger type, opaque storage reference and whole-file SHA-256:
- Phase 6 selected release-execution Phase 0 environment, manifest payload SHA-256, requirements SHA-256 and checkpoint phase:
- Repository-external write-once Phase 0 checkpoint snapshot path, canonical manifest payload SHA-256 and retention reference:
- Intake manifest/checkpoint 64 KiB limit, duplicate-key rejection and stable bounded-read result:
- Authoring immutable-generation chain, previous payload/file caller pins, exactly-one missing-to-provided transition, input/candidate/new-artifact pre/post stable single-link rechecks and fsynced local no-replace/readback result; fork protection, latest-head selection, pin authority, cross-host linearization and post-publication custody `unverified` acknowledgement:
- Seventeen registered artifacts bounded stable-read, whole-file SHA-256 and sixteen ordinary JSON unique-key parse result:
- Standalone artifact check/strict-intake bounded-reader and unique-key parse parity result:
- Six generated execution-evidence readers stable 64 KiB unique-key parse and error-mapping result:
- Final strict current-to-checkpoint six-item equality and release-ledger-to-checkpoint identity result:
- Finalized target-intake repository-external path, canonical payload SHA-256, whole-file SHA-256 and local no-replace/readback result:
- Final strict caller-pinned payload/file SHA-256 match plus pin-authority, post-publication custody and global rollback-protection `unverified` acknowledgement:
- Seven standalone manifest-consumer checks' reviewed authoring-manifest payload/file SHA-256 pins, exact closed-v2/seventeen-item result, caller `--input` exact case-preserving normalized absolute match to the own `artifact_path`, manifest-locator stable read plus final same-identity/single-link/raw-byte recheck, and caller identity/review-time inode continuity/post-recheck custody/delete-recreate/parent-race/pin-authority/global rollback-protection `unverified` acknowledgement:
- Standalone ledger integrity/identity result versus final-strict Phase 0 start-replay authority result:
- Release entry Phase 0 evaluation equals ledger started_at and frozen six-item validity-intersection replay result:
- Release finished_at to exact-ledger selection review and every consuming execution-window start ordering result:
- Target-intake schema-v2 release review subject kind and exact full-selector projection result:
- Release-selection opaque reviewer reference/time plus reviewer-authentication, trusted-time and replay-protection `unverified` acknowledgement:
- Release-execution opaque storage locator plus provider-native enforcement, retention, delete-denial and post-denial readback `unverified` acknowledgement:
- Final-strict all-consumer exact release selector equality, including the opaque locator, result:
- Release-execution namespace authority, immutable version identity and cross-manifest rebinding protection `unverified` acknowledgement:
- Phase 0 entry-authorization versus continuous-execution authorization decision, host-clock trust status and external approval authentication status:
- Mail/Sub2 provider scope, external source version/SHA-256, capture/review/valid-until UTC and same-manifest review result:
- Phase 1–5/Sub2/Vault execution-index sealed review/valid-until and same-manifest review result:
- Windows pilot-input sealed review/valid-until and same-manifest review result:
- Phase 5 execution-window containment in Windows-input validity and single-clock preflight result:
- Phase 1–5 execution-index exact release-ledger selectors and target-release alignment result:
- Phase 4 Sub2 evidence exact release-ledger whole-file selector and target-release alignment result:
- Phase 4 Sub2 sealed review reference/time, execution window and same-manifest review-metadata result:
- Phase 6 selected schema-v3 ledger independent parse and successful-terminal result:
- Phase 6 pilot evidence same-manifest Sub2-evidence, pilot-input and target-inventory SHA-256 bindings:
- Phase 6 pilot operator/security-auditor subject, trace-set, sealed review reference and post-window review time:
- Phase 6 pilot execution containment and pre-deadline reviewed result:
- Phase 6 pilot UTC window and nine target OIDC/real Mail/Sub2 scenario WORM references:
- Phase 6 target operations evidence index and canonical payload SHA-256:
- Phase 6 operations release identity and same-manifest T41/T42/target-inventory bindings:
- Phase 6 operations/pilot exact release-execution selector equality:
- Phase 6 Alertmanager, PostgreSQL, Redis, Vault, rollback and training source-artifact SHA-256 values:
- Phase 6 operations four-role subjects, pilot trace-set, sealed review reference and post-window review time:
- Phase 6 operations post-pilot/maintenance-window/rollback-deadline and review-validity result:
- Phase 6 nine alert/restore/rollback/training/audit scenario WORM references and UTC window:
- Target-environment pilot evidence:
- Keycloak administrator group subject digest and membership evidence:
- Vault administrator group entity digest and membership evidence:
- Keycloak/Vault administrator non-overlap and no-shared-credential review:
- Cross-control-plane denied-access trace and audit-event evidence:
- Separate recovery custodians, two-person break-glass approval and post-use rotation evidence:
- Keycloak/Vault administration-separation independent reviewer:
- Non-production source/target environment and synthetic-fixture provenance:
- Non-production fixture SHA-256, masked last-four and `.invalid` validation evidence:
- Non-production denial of production backup/snapshot/clone/Vault-path access evidence:
- Non-production mailbox-secret and live-connector absence evidence:
- Non-production data-boundary independent privacy/security reviewer:
- Rollback release tag, commit and migration head:
- Rollback container manifest SHA-256:
- Rollback write-once terminal evidence file, file SHA-256 and canonical payload SHA-256:
- Rollback terminal state/error code (`succeeded`, `preflight_failed`, `edge_closed_failure`, or `edge_unconfirmed`):
- Independent verifier command and reviewed expected release/recovery/image inputs:
- Release-bound dual-database backup manifest SHA-256:
- Redis release backup artifact and authenticated manifest SHA-256:
- Redis recovery-set, PostgreSQL manifest SHA-256 and release-binding evidence:
- Write-once external PostgreSQL/Redis/Vault output paths and pre-existing-target refusal evidence:
- PostgreSQL/Redis/Vault 64 KiB stable-manifest, unique-key, non-link/reparse and read-shape-drift rejection evidence:
- Rollback expected and observed OCI digests:
- Rollback Cosign, SBOM attestation and provenance verification:
- Rollback drill start/end UTC and achieved RTO/RPO:
- Rollback dual-database critical row counts:
- PostgreSQL/Redis shared recovery-set and restore-order evidence:
- Redis restored key count, representative TTL samples and expired-key non-revival evidence:
- Restore internal TLS readiness smoke and edge-closed failure evidence:
- Keycloak user/admin event configuration and 30-day retention evidence:
- Keycloak browser MFA flow alias and target realm export SHA-256:
- Keycloak password-required then OTP-required execution evidence:
- Keycloak password-only/invalid-OTP rejection and password-plus-OTP success evidence:
- Keycloak CONFIGURE_TOTP enrollment versus OTP challenge review evidence:
- Keycloak Desktop/Web direct-grant rejection evidence:
- Keycloak MFA cutover notBefore/logout-all and old session/token rejection evidence:
- Keycloak failed-login event and Alertmanager delivery evidence:
- Alertmanager external config path/SHA-256 and production verifier evidence:
- Alertmanager page firing/resolved receiver delivery IDs and UTC timestamps:
- Monitoring control-plane Prometheus/Alertmanager strict-TLS self-scrape evidence:
- Monitoring watchdog dedicated route/receiver and <=2m cadence evidence:
- Monitoring watchdog consecutive receiver delivery IDs and UTC timestamps:
- Monitoring watchdog suppression window, missed-heartbeat alarm and recovery evidence:
- Keycloak admin event with request representation disabled:
- Keycloak event_entity/admin_event_entity restore counts:
- Rollback failure-injection result (edge remained closed):
- Rollback evidence-publication failure result and confirmed Edge state:
- Rollback Git HEAD/manifest commit equality and clean tracked checkout evidence:
- Rollback explicit production Compose path/project and override absence evidence:
- Rollback independent operator/reviewer:
- Signed by:
- Reviewer role:
- Review date:

## Gate evidence

1. Compose/config and secret scan

   - Evidence:
   - Result:

2. CodeQL SAST plus container build, HIGH/CRITICAL scan, SPDX SBOM, keyless signature and provenance

   - Evidence:
   - Result:
   - Python runtime/test/desktop-build dependency audit evidence:
   - Full frontend dependency-tree audit evidence (including devDependencies):
   - CI/Security/Release checkout `persist-credentials=false` verifier evidence:
   - Explicit-token publication step and authenticated Git-write review evidence:

3. PostgreSQL and Redis release recovery-set plus Vault isolated backup/restore drills and Alembic upgrade

   - Evidence:
   - Result:
   - PostgreSQL/Redis shared recovery-set, release binding and manifest SHA-256 evidence:
   - Redis restored key count, representative TTL samples and expired-key non-revival evidence:
   - Vault two-device audit, independent storage, allowed/denied events and alert result:

4. Keycloak realm, redirect URIs, client auth, MFA, user/admin audit and retention

   - Evidence:
   - Result:

5. TLS headers, rate limits, log redaction, retention, alerting

   - Evidence:
   - Result:
   - Internal cross-container HTTPS, CA, SAN/hostname and rotation evidence:
   - Bounded container LogConfig and target rotation evidence:
   - Monitoring control-plane self-scrape and dead-man heartbeat evidence:

6. Mail connector and Sub2 boundary

   - Evidence:
   - Result:

7. Worker retry / reconciliation / card lease safety

   - Evidence:
   - Result:

8. Runbooks signed off by a separate operator

   - Evidence:
   - Audit archive schema/tool source commit, encrypted artifact and manifest hashes:
   - Audit archive UTC boundary/count continuity, SELECT-only and zero-prune evidence:
   - Independent decrypt/verify plus target WORM/object-lock/retention evidence:
   - Result:

9. Target-environment pilot, alert delivery, training and rollback drill

   - Evidence:
   - Result:
   - Sealed target-pilot evidence index and payload SHA-256:
   - Same-manifest pilot-input/target-inventory bindings and release identity:
   - Nine reviewed scenario WORM references and independent reviewer:
   - Sealed target-operations evidence index and payload SHA-256:
   - Six source-artifact SHA-256 values and same-release dependency bindings:
   - Nine operations scenario WORM references and independent reviewer:

   - Phase 6 role-training evidence file and payload SHA-256:
   - Phase 6 rehearsal/training external write-once paths and pre-existing-target refusal evidence:
   - Training session/environment/release/window:
   - Operator trainee/reviewer:
   - Ops administrator trainee/reviewer:
   - Security auditor trainee/reviewer:
   - Platform administrator trainee/reviewer:
   - Required tabletop scenarios and trace IDs:

   Rollback evidence must name the same release tag, commit, migration head,
   container-manifest SHA-256 and authenticated schema-v5 platform + Keycloak backup bundle.
   - Release-bound schema-v5 manifest HKDF/HMAC verification evidence:
   Record actual running image digests and confirm that a forced restore or
   smoke-test failure kept edge closed. A local mocked command-order test is
   preflight only and does not satisfy this gate.

The Phase 6 CI rehearsal is only a preflight artifact and must have
`production_acceptance=false`. It cannot be used as the evidence for gate 9.

## Final signoff

- Approved for production:
- Conditions:
- Follow-up actions:
