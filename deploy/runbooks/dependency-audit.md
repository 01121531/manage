# Dependency audit release gate

Use this gate for every release candidate and for the scheduled security workflow.
It covers dependencies that run in production as well as tools that execute while
testing or constructing the Windows EXE and frontend assets.

## Required fail-closed audits

Run the repository security workflow and retain its job URL and logs. The gate
must complete all of these commands without `continue-on-error`:

- `pip-audit -r platform/requirements.txt`
- `pip-audit -r platform/requirements-test.txt`
- `pip-audit -r requirements-desktop-build.txt`
- from `frontend`, `npm audit --audit-level=high --include=prod --include=dev --include=optional --include=peer`

The npm command explicitly includes every dependency type because TypeScript,
Vite, Playwright and related devDependencies execute during build, code
generation or release verification. Do not add `--omit=dev`, `--only=prod` or
an equivalent production-only filter.

## Failure handling

Block publication on any audit command failure, including inability to resolve
dependencies or reach the configured vulnerability service. Record the advisory,
affected dependency surface, approved remediation and rerun evidence. Do not
silence a result with `continue-on-error`, an ignored exit code or a replacement
no-op command.

## Signoff evidence

Record the workflow run URL, commit and UTC completion time; attach the runtime,
test, desktop-build and full frontend dependency audit results. Link any approved
exception to its owner, expiry and compensating control.

Repository verification proves the workflows retain these fail-closed commands;
it does not query live vulnerability databases. A local or CI structural pass is
therefore preflight only and must record `production_acceptance=false` until the
networked audit run and independent review are complete.

## 2026-08-30 online gate remediation

Security Gate run #57 for commit `4f795bcd8c856419243793997395b0e81b7a5d85`
failed closed before release. `pip-audit` identified four advisories against
`cryptography 46.0.7`; the container reports independently identified
`libcrypto3` and `libssl3` 3.5.7-r0, whose scanner-fixed version is 3.5.8-r0.
The API image also contained the same vulnerable Python package. The repository
remediation raises the runtime dependency floor to `cryptography>=50.0.1,<51.0`,
updates the Node and Nginx multi-platform image digest pins, and applies the
scanner-required `libcrypto3`/`libssl3` security updates while constructing all
three digest-pinned runtime images. Updating only the Nginx base digest was not
sufficient because the current image still resolved both packages to 3.5.7-r0.

The SARIF annotation helper now has a direct-script import regression test so
`python scripts/report_trivy_sarif.py ...` works on the Linux runner. This helper
remains non-authoritative: the original Trivy step alone decides pass or fail.
Retain the failed run URL and all three SARIF artifacts with the replacement
run; do not approve a release until the replacement CI and Security Gate runs
both finish successfully for the exact remediation commit.

The first replacement run for commit `dc7d7ec942e4db90bdcc15944ae4538bd5bc4ac4`
proved the dependency audit, Vault Linux gate and SARIF annotations, then failed
closed on the remaining Nginx package versions and a POSIX materialization
regression. The latter used the 64-character SHA-256 validator for a
32-character random claim ID. The follow-up repair gives claim IDs their own
closed validator and retains all owner, mode, identity, link-count and digest
checks. Retain both failed replacement run URLs with the final green run.
