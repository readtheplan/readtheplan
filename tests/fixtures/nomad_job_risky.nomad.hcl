job "platform-agent" {
  type        = "system"
  datacenters = ["*"]

  periodic {
    cron             = "*/5 * * * *"
    prohibit_overlap = false
  }

  group "agents" {
    network {
      mode = "host"
      port "http" {
        static = 8080
      }
    }

    volume "host-data" {
      type   = "host"
      source = "/srv/platform"
    }

    update {
      max_parallel = 10
      auto_revert  = false
    }

    service {
      name     = "platform-agent"
      provider = "consul"
      port     = "http"
      connect {
        sidecar_service {}
      }
    }

    task "agent" {
      driver = "raw_exec"
      user   = "root"

      config {
        command      = "/bin/sh"
        args         = ["-c", "./agent"]
        network_mode = "host"
        devices      = ["/dev/kvm"]
      }

      env {
        DEPLOY_TOKEN = "literal-example"
      }

      artifact {
        source = "http://downloads.example.test/agent.tgz"
      }

      template {
        data = <<-EOT
        {{ with secret "secret/data/platform" }}
        API_TOKEN={{ .Data.data.token }}
        {{ end }}
        EOT
        destination = "/etc/platform/agent.env"
        env         = true
        change_mode = "script"
        change_script {
          command = "/bin/reload-agent"
        }
      }

      vault {
        policies = ["root"]
      }

      consul {}

      identity {
        env  = true
        file = true
      }

      lifecycle {
        hook    = "prestart"
        sidecar = true
      }
    }

    task "web" {
      driver = "docker"
      config {
        image      = "nginx:latest"
        privileged = true
        cap_add    = ["SYS_ADMIN"]
        volumes    = ["/:/host"]
      }
    }
  }
}
