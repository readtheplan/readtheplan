packer {
  required_version = ">= 1.9.0"
  required_plugins {
    amazon = {
      source  = "github.com/hashicorp/amazon"
      version = ">= 1.0.0"
    }
    custom = {
      source  = "github.com/example/custom"
      version = ">= 0.1.0"
    }
  }
}

variable "api_token" {
  type      = string
  sensitive = false
  default   = "literal-example"
}

variable "region" {
  type = string
}

local "signing_secret" {
  expression = var.api_token
  sensitive  = false
}

locals {
  credential_path = file("./credential.txt")
}

data "amazon-ami" "base" {
  most_recent = true
  owners      = ["self"]
}

source "amazon-ebs" "base" {
  communicator             = "ssh"
  most_recent              = true
  insecure_skip_tls_verify = true
  ssh_password             = "literal-example"
  iso_url                  = "http://images.example.test/base.iso"
}

build {
  name    = "publish"
  sources = ["source.amazon-ebs.base"]

  provisioner "shell-local" {
    inline       = ["./prepare-host.sh"]
    elevated_user = "root"
    environment_vars = ["API_TOKEN=${var.api_token}"]
  }

  provisioner "shell" {
    scripts = ["scripts/install.sh", "scripts/harden.sh"]
  }

  provisioner "file" {
    source      = "./config"
    destination = "/tmp/config"
  }

  post-processor "docker-push" {
    login          = true
    login_username = "publisher"
    login_password = "literal-example"
  }

  post-processor "checksum" {
    checksum_types = ["md5", "sha256"]
  }
}
