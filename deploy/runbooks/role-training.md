# Phase 6 role training and tabletop evidence

This package records role-based training before the target-environment pilot.
It is a reviewed training record, not proof that the production platform,
Mail provider, Sub2 service, backup restore, alert receiver, or rollback was
successfully exercised. Every sealed record has `production_acceptance=false`.

## Required roles

- `operator`: create and close tasks, consume one-time codes, handle temporary
  values, and stop safely after session loss.
- `ops_admin`: manage operational resources and reconcile ambiguous uploads
  without blind retries.
- `security_auditor`: perform read-only alert triage, trace replay, and redacted
  audit export without changing business state.
- `platform_admin`: revoke devices, govern policy, and make backup/rollback
  go/no-go decisions while keeping edge closed on failure.

Each role must have a distinct trainee. The reviewer set must be disjoint from
the trainee set; an independent reviewer signs every role and scenario result.
Use opaque staff IDs, never names, email addresses, tokens, credentials, or
free-form notes in the JSON record.

## Required tabletop scenarios

1. `operator_session_token_loss` (`operator`): stop polling and sensitive-value
   handling, do not reuse a lost session token, sign in again, and reconcile or
   close the prior task by trace ID.
2. `unknown_upload_no_blind_retry` (`ops_admin`): keep the job `unknown`, do not
   submit a new idempotency key, verify the upstream result, and use the
   privileged reconcile path with an audit trace.
3. `alert_triage_and_audit_replay` (`security_auditor`): inspect the alert and
   tenant-scoped trace, export the redacted audit record, and escalate without
   calling a mutating endpoint.
4. `device_revocation` (`platform_admin`): revoke the device, confirm the old
   bearer is rejected, confirm task/card/mail cleanup, and replay the audit
   trace.
5. `backup_rollback_go_no_go` (`platform_admin`): reject mutable images, schema
   v1 or mismatched backup bundles, missing Cosign/SBOM/provenance proof, and any
   plan that opens edge before both databases and internal services verify.

The reviewer records one non-secret trace ID for each scenario. A failed or
skipped role/scenario cannot be sealed as completed evidence.

## Record and seal evidence

Prepare a JSON payload with these exact top-level fields:
`schema_version`, `evidence_kind`, `production_acceptance`, `session_id`,
`environment_id`, `release_tag`, `release_commit`, `window`, `roles`, and
`scenarios`. Use `schema_version=1`,
`evidence_kind=phase6_role_training`, and `production_acceptance=false`.

Each role record contains only `trainee_id`, `reviewer_id`, `status=passed`, and
UTC `completed_at`. Each scenario record contains only `actor_role`,
`reviewer_id`, `result=passed`, `trace_id`, and UTC `completed_at`. All completion
times must fall inside the UTC training window.

Seal and independently verify the record:

```powershell
python -m scripts.training_evidence create `
  --input C:\secure\phase6-training-session.json `
  --output release\evidence\phase6-role-training-evidence.json
python -m scripts.training_evidence verify `
  --input release\evidence\phase6-role-training-evidence.json `
  --expected-release-tag v1.2.3 `
  --expected-release-commit 0123456789abcdef0123456789abcdef01234567
```

The writer invalidates stale output first, uses a same-directory temporary file,
flushes it, replaces atomically, and verifies the published bytes. The closed
schema rejects unknown fields and secret-like identifiers; integrity covers the
canonical payload SHA-256. The `release/` directory is ignored by Git. Store the
target record in the controlled release evidence archive and copy only its file
and payload SHA-256 into the production signoff.

This repository's unit tests and asset verifier prove the evidence tool's
behavior only. They do not replace the target session, real participants, or
the final two-person production decision.
