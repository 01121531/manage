# CI checkout token hygiene

GitHub creates a job-scoped `GITHUB_TOKEN` for every Actions job. The pinned
`actions/checkout` version persists that credential for later Git commands by
default, so every checkout in CI, security and release workflows must set the
YAML boolean `persist-credentials: false`.

## Required control

Run all three repository workflow verifiers before merge:

- `python scripts/verify_ci_workflow.py`
- `python scripts/verify_security_workflow.py`
- `python scripts/verify_release_workflow.py`

The verifiers inspect every `actions/checkout@...` step. Missing values,
`persist-credentials: true` and the string `"false"` all fail closed. Other
reviewed checkout inputs such as `fetch-depth` may coexist with the required
boolean value.

No build, test, scan or repository script may depend on an authenticated Git
remote. A later operation that genuinely needs GitHub authorization must receive
the minimum token explicitly in that single step, as the release publication and
container registry login steps do. Never restore an `http.extraheader`, credential
helper or remote URL containing a token for the remainder of the job.

## Evidence and boundary

Record the workflow commit, verifier output and the three workflow-run URLs in
the production signoff. Review logs for unexpected authenticated Git writes.
This repository control prevents checkout from retaining its credential; it
does not prove GitHub organization rules, environment protection or runner isolation.
Those target controls require separate evidence, so static verification records
`production_acceptance=false`.
