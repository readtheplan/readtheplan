required_providers {
  aws = {
    source  = "hashicorp/aws"
    version = "~> 5.0"
  }
  random = {
    source = "hashicorp/random"
  }
}

provider "aws" "production" {
  for_each = var.regions
  config = {
    region     = each.value
    access_key = "not-a-real-key"
  }
}

component "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  for_each = var.regions
  inputs = {
    api_token = "not-a-real-token"
  }
  providers = {
    aws = provider.aws.production[each.key]
  }
}

component "remote" {
  source = "git::https://example.invalid/modules/service.git"
  inputs = {}
  providers = {
    aws = provider.aws.production["us-east-1"]
  }
}

removed {
  source = "./modules/legacy"
  from   = component.legacy
  providers = {
    aws = provider.aws.production["us-east-1"]
  }
}

variable "api_token" {
  type      = string
  default   = "not-a-real-token"
  sensitive = false
}

variable "regions" {
  type    = set(string)
  default = ["us-east-1", "us-west-2"]
}

output "database_password" {
  type      = string
  value     = var.api_token
  sensitive = false
}
