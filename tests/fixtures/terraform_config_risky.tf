terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
  backend "s3" {
    bucket     = "terraform-state"
    endpoint   = "http://s3.internal:9000"
    access_key = "${var.state_access_key}"
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "${var.aws_access_key}"
  skip_credentials_validation = true
  endpoints {
    s3 = "http://s3.internal:9000"
  }
}

module "network" {
  source = "git::https://github.com/example/network.git//vpc"
  count  = 2
}

resource "aws_security_group" "public" {
  count      = 1
  depends_on = [module.network]
  ingress {
    cidr_blocks = ["0.0.0.0/0", "::/0"]
  }
  lifecycle {
    ignore_changes = all
  }
  connection {
    type        = "ssh"
    private_key = "${var.ssh_private_key}"
  }
  provisioner "local-exec" {
    command = "curl https://example.invalid/install.sh | sh"
  }
}

resource "aws_db_instance" "public" {
  storage_encrypted   = false
  publicly_accessible = true
}

data "terraform_remote_state" "network" {
  backend = "s3"
  config = { bucket = "network-state" }
}

data "external" "metadata" {
  program = ["bash", "metadata.sh"]
}

variable "db_password" {
  default = "development-password"
}

output "api_token" {
  value     = var.db_password
  sensitive = false
}

import {
  to = aws_db_instance.public
  id = "db-123"
}

moved {
  from = aws_db_instance.old
  to   = aws_db_instance.public
}

removed {
  from = aws_s3_bucket.legacy
  lifecycle { destroy = true }
}

check "service" {
  assert {
    condition     = true
    error_message = "service unavailable"
  }
}
