# The mail worker resolves tenant mailbox connector credentials only.
path "secret/data/mailboxes/*" {
  capabilities = ["read"]
}
