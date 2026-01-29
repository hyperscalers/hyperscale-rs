terraform {
  required_version = ">= 1.0.0"

  required_providers {

    aws = {
      source  = "hashicorp/aws"
      version = ">= 4"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = ">= 3.4.0"
    }
  }
}