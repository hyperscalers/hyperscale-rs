terraform {
  backend "s3" {
    # Name of the S3 bucket to store the state
    bucket       = "radixdlt-babylon-hyperscalers-state"
    key          = "hyperscale-rs-aws/hyperscale-rs-aws-nodes-terraform.tfstate"
    region       = "eu-west-1"
    use_lockfile = true
    encrypt      = true
  }
}
