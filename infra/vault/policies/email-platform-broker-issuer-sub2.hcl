# The Sub2 broker identity may issue only the Sub2-worker AppRole credential.
path "auth/approle/role/email-platform-sub2/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/email-platform-sub2/secret-id" {
  capabilities = ["update"]
}
