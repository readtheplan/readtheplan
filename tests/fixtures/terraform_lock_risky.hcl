# This file is maintained automatically by "terraform init".
# Manual edits may be lost in future updates.

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.80.0"
  constraints = ">= 0.0.0"
  hashes = [
    "h1:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
  ]
}

provider "localhost/acme/private" {
  version = "0.9.0-beta.1"
  hashes = [
    "zh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "future:opaque-checksum-format",
  ]
}

provider "registry.opentofu.org/opentofu/random" {
  version     = "3.6.0"
  constraints = "~> 2.0"
  hashes      = []
}
