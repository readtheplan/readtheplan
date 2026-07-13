identity_token "aws" {
  audience = ["aws.workload.identity"]
}

store "varset" "production_secrets" {
  name     = "production"
  category = "terraform"
}

deployment_auto_approve "everything" {
  check {
    condition = true
    reason    = "all plans are approved"
  }
}

deployment_group "production" {
  auto_approve_checks = [deployment_auto_approve.everything]
}

deployment "production" {
  inputs = {
    api_token = "not-a-real-token"
    oidc_jwt  = identity_token.aws.jwt
  }
  deployment_group = deployment_group.production
  destroy          = true
  import           = true
}

deployment "staging" {
  inputs = {
    api_token = store.varset.production_secrets.api_token
  }
}

publish_output "database_password" {
  description = "downstream credential"
  value       = deployment.production.database_password
}

upstream_input "network" {
  type   = "stack"
  source = "app.terraform.io/example/platform/network"
}
