# The API broker identity may issue only the API card-service AppRole credential.
path "auth/approle/role/email-platform-api-cards/role-id" {
  capabilities = ["read"]
}

path "auth/approle/role/email-platform-api-cards/secret-id" {
  capabilities = ["update"]
}
