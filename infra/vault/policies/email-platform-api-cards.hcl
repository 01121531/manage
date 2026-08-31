# Card reveal runs in the API process. It may read card material only.
path "secret/data/cards/*" {
  capabilities = ["read"]
}

# The API may verify, but never create, secure pool-import receipts.
path "transit/verify/email-platform-card-import-receipt" {
  capabilities = ["update"]
}

path "transit/verify/email-platform-mailbox-import-receipt" {
  capabilities = ["update"]
}
