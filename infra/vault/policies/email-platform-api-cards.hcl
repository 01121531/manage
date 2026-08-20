# Card reveal runs in the API process. It may read card material only.
path "secret/data/cards/*" {
  capabilities = ["read"]
}
