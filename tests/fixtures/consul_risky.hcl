server = true
bootstrap_expect = 1
client_addr = "0.0.0.0"
enable_script_checks = true
disable_remote_exec = false
encrypt = "${CONSUL_GOSSIP_KEY}"
encrypt_verify_incoming = false
encrypt_verify_outgoing = false

addresses {
  http = "0.0.0.0"
}

ports {
  http = 8500
  https = -1
}

acl {
  enabled = false
  default_policy = "allow"
  tokens {
    agent = "${CONSUL_AGENT_TOKEN}"
  }
}

tls {
  defaults {
    verify_incoming = false
    verify_outgoing = false
    verify_server_hostname = false
    ca_file = "/consul/tls/ca.pem"
    cert_file = "/consul/tls/agent.pem"
    key_file = "/consul/tls/agent-key.pem"
  }
}

connect {
  enabled = true
}

retry_join = ["provider=aws tag_name=consul"]
retry_join_wan = ["provider=gce tag_name=consul-wan"]
recursors = ["1.1.1.1"]

ui_config {
  enabled = true
}

services {
  name = "api"
  check {
    args = ["/usr/local/bin/check-api"]
    interval = "10s"
  }
}

telemetry {
  statsd_address = "stats.internal:8125"
}

auto_encrypt {
  allow_tls = true
}
