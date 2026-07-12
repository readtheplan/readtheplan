ui = true
api_addr = "http://vault.example.com:8200"
cluster_addr = "https://vault.internal:8201"
disable_mlock = true
raw_storage_endpoint = true
plugin_directory = "/opt/vault/plugins"

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = true
  tls_min_version = "tls11"
  unauthenticated_metrics_access = true
  x_forwarded_for_authorized_addrs = "0.0.0.0/0"
}

storage "file" {
  path = "/vault/data"
}

ha_storage "consul" {
  address = "consul.internal:8500"
  token = "${CONSUL_TOKEN}"
}

seal "awskms" {
  region = "us-east-1"
  kms_key_id = "${KMS_KEY_ID}"
}

telemetry {
  statsite_address = "stats.internal:8125"
  unauthenticated_metrics_access = true
}

service_registration "consul" {
  address = "consul.internal:8500"
  token = "${CONSUL_TOKEN}"
}

user_lockout "userpass" {
  disable_lockout = true
}
