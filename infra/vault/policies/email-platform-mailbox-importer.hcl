# Independent mailbox importer: it cannot read, list, update, or delete credentials.
path "secret/data/mailboxes/imports/*" {
  capabilities = ["create"]
  required_parameters = ["data", "options"]
}

path "transit/sign/email-platform-mailbox-import-receipt" {
  capabilities = ["update"]
}
