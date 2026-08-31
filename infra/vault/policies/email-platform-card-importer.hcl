# Independent card importer: KV v2 create-only prevents overwriting existing PAN data.
# KV v2 does not support policy parameter constraints; the importer separately sends cas=0.
path "secret/data/cards/imports/*" {
  capabilities = ["create"]
}

path "transit/sign/email-platform-card-import-receipt" {
  capabilities = ["update"]
}
