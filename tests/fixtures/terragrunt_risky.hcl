terraform {
  source = "git::https://github.com/example/infrastructure-modules.git//service"

  before_hook "bootstrap" {
    commands = ["apply"]
    execute  = ["sh", "-c", "curl https://example.invalid/bootstrap | sh"]
  }

  after_hook "notify" {
    commands     = ["apply"]
    execute      = ["notify-deploy"]
    run_on_error = true
  }

  error_hook "recover" {
    commands  = ["apply"]
    execute   = ["recover-infrastructure"]
    on_errors = [".*"]
  }

  extra_arguments "automation" {
    commands  = ["apply", "destroy"]
    arguments = ["-auto-approve", "-lock=false", "-target=module.service"]
    env_vars = {
      API_TOKEN = "${get_env(\"DEPLOY_TOKEN\")}"
    }
  }
}

remote_state {
  backend = "s3"
  config = {
    bucket     = "terraform-state"
    endpoint   = "http://s3.internal:9000"
    access_key = "${get_env(\"STATE_ACCESS_KEY\")}"
  }
  generate = {
    path      = "backend.tf"
    if_exists = "overwrite"
  }
  encryption = {
    key_provider = "pbkdf2"
  }
}

include "root" {
  path   = find_in_parent_folders("root.hcl")
  expose = true
}

dependency "network" {
  config_path  = "../network"
  skip_outputs = true
  mock_outputs = { vpc_id = "mock-vpc" }
}

dependencies {
  paths = ["../database"]
}

generate "provider" {
  path      = "provider.tf"
  if_exists = "overwrite_terragrunt"
  contents  = "provider \"aws\" {}"
}

locals {
  generated_value = run_cmd("sh", "-c", "generate-config")
  secrets         = sops_decrypt_file("secrets.yaml")
  shared          = read_terragrunt_config("../shared.hcl")
}

inputs = {
  db_password       = "${local.secrets.password}"
  allowed_cidr      = "0.0.0.0/0"
  encryption_enabled = false
}

iam_role               = "arn:aws:iam::123456789012:role/deployer"
iam_web_identity_token = "${get_env(\"AWS_WEB_IDENTITY_TOKEN\")}"
terraform_binary       = "/usr/local/bin/custom-tofu"

engine { source = "custom-engine" }
errors { retry "transient" { retryable_errors = ["timeout"] } }
exclude { if = true actions = ["all"] }
feature "new_flow" { default = true }
unit "service" { source = "./unit" }
stack "production" { source = "./stack" }
catalog { urls = ["https://catalog.example.com"] }
