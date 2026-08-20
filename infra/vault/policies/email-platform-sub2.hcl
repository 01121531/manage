# The Sub2 worker receives only its reviewed credential and proxy objects.
path "secret/data/sub2/credential" {
  capabilities = ["read"]
}

path "secret/data/sub2/proxy" {
  capabilities = ["read"]
}

# Upload payload construction resolves the allocated card snapshot in-process.
path "secret/data/cards/*" {
  capabilities = ["read"]
}
