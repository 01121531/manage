# Independent mailbox importer: it cannot read, list, update, or delete credentials.
# KV v2 does not support policy parameter constraints; the importer separately sends cas=0.
path "secret/data/mailboxes/imports/*" {
  capabilities = ["create"]
}

path "transit/sign/email-platform-mailbox-import-receipt" {
  capabilities = ["update"]
}
