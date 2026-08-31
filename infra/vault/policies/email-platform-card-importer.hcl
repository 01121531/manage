# Independent card importer: create-only prevents overwriting existing PAN data.
path "secret/data/cards/imports/*" {
  capabilities = ["create"]
  required_parameters = ["data", "options"]
}

path "transit/sign/email-platform-card-import-receipt" {
  capabilities = ["update"]
}
