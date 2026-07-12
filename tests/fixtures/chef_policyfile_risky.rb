name "production-web"
default_source :supermarket, "http://supermarket.example.test"
run_list "recipe[base::default]", "recipe[web::default]"

cookbook "nginx"
cookbook "application", "~> 2.0"
cookbook "audit", "1.2.3"
cookbook "deploy", git: "https://github.com/example/deploy.git", branch: "main"
cookbook "hardening", git: "https://github.com/example/hardening.git", revision: "0123456789abcdef0123456789abcdef01234567"
cookbook "local-secrets", path: "cookbooks/local-secrets"

include_policy "base", git: "https://github.com/example/policies.git", revision: "main"
include_policy "emergency", path: "policies"

default["database"]["password"] = "literal-production-password"
override["feature"]["enabled"] = true

system "./generate-policy-fragment"
