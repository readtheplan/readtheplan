variable "API_TOKEN" {
  default = "literal-build-token-must-not-leak"
}

variable "TAG" {
  default = "latest"
}

function "image_tag" {
  params = [name]
  result = "registry.example.com/${name}:${TAG}"
}

group "default" {
  targets = ["app"]
}

target "base" {
  context    = "."
  dockerfile = "Dockerfile"
  cache-from = ["type=registry,ref=registry.example.com/app:cache"]
}

target "app" {
  inherits = ["base"]
  context  = "https://github.com/example/app.git#main"
  contexts = {
    source = "target:missing"
  }
  dockerfile-inline = <<-EOT
    FROM alpine:latest
    RUN echo build
  EOT
  entitlements = ["network.host", "security.insecure"]
  network      = "host"
  extra-hosts = {
    metadata = "host-gateway"
  }
  args = {
    API_TOKEN = "literal-build-arg-must-not-leak"
  }
  secret = [
    {
      type = "file"
      id   = "aws"
      src  = "/root/.aws/credentials"
    }
  ]
  ssh = [{ id = "default" }]
  cache-to = [
    {
      type   = "s3"
      bucket = "shared-build-cache"
      mode   = "max"
    }
  ]
  output = [
    {
      type = "registry"
      name = "registry.example.com/app:latest"
      push = true
    }
  ]
  attest = [
    { type = "provenance", disabled = true },
    { type = "sbom" },
  ]
  policy = [{ filename = "Dockerfile.rego", disabled = true }]
  matrix = {
    platform = ["linux/amd64", "linux/arm64"]
    mode     = ["debug", "release"]
  }
  name = "app-${platform}-${mode}"
  tags = ["registry.example.com/app:latest"]
}
