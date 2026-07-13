policy "public-network" {
  source = "git::https://github.com/example/policies.git//network.sentinel"
  enforcement_level = "advisory"
  params = {
    deploy_token = "literal-example"
  }
}

import "plugin" "organization" {
  source = "/opt/sentinel/custom-import"
  args = ["--network"]
  env = {
    API_TOKEN = "literal-example"
  }
}

import "module" "helpers" {
  source = "../shared/helpers.sentinel"
}

mock "tfplan/v2" {
  module {
    source = "../mocks/tfplan.sentinel"
  }
}

param "break_glass" {
  value = true
}

test {
  rules = {
    helper_rule = true
  }
}

sentinel {
  features = {
    terraform = true
  }
}
