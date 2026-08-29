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
