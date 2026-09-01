path "auth/approle/role/email-platform-mailbox-importer/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/email-platform-mailbox-importer/secret-id" {
  capabilities = ["update"]
}
