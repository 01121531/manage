# Non-production data boundary

Use this gate for every development, test, demo, training, and CI environment.

1. Record the source environment, target environment, data owner, import method,
   and change ticket before creating or refreshing a non-production data set.
2. Do not import a production database snapshot, database clone, backup object,
   Vault export, Redis backup, mailbox credential, mail connector, raw card
   number, CVV, verification code, email message, or production audit export.
   Masking after a production copy has entered non-production is not acceptable.
3. Seed demos only from reviewed synthetic fixtures. Card examples contain only
   a synthetic token and masked last four digits; email addresses use the
   reserved `.invalid` domain. Fixtures must not contain mailbox secrets or live
   connector endpoints.
4. Attach target IAM and storage-policy evidence showing that non-production
   principals cannot read production backup buckets, snapshots, clone APIs, or
   Vault paths. Attach a denied-access trace for each production data source.
5. Run secret scanning and fixture validation before use. An independent privacy
   or security reviewer signs the fixture digest, provenance record, IAM evidence,
   and denied-access traces. Any unknown provenance or production-derived input
   blocks the refresh and requires deletion under the incident process.

The repository gate verifies the required procedure and signoff fields; it does not claim that a local manifest proves target data provenance.
Production acceptance requires external IAM, storage, denial, and reviewer evidence.
