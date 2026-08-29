# The mail broker identity may issue only the mail-worker AppRole credential.
path "auth/approle/role/email-platform-mail/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/email-platform-mail/secret-id" {
  capabilities = ["update"]
}
