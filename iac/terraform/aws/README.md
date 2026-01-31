# Hyperscale-RS AWS Terraform Module

This Terraform module provisions EC2 instances across multiple AWS regions for running Hyperscale-RS nodes.

## Prerequisites

- Terraform >= 1.0.0 (tested with 1.13.5)
- AWS account with appropriate permissions
- AWS CLI configured (optional, for verification)

## Quick Start

### 1. Set Up AWS Credentials

Navigate to the terraform directory and export your AWS credentials:

```sh
cd iac/terraform/aws

export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
```

Alternatively, you can use AWS profiles:

```sh
export AWS_PROFILE="your-profile-name"
```

### 2. Add Your SSH Key (Optional)

To add your SSH public key for instance access, edit `locals.tf` and add your key to the `additional_ssh_keys` list:

```hcl
additional_ssh_keys = [
  "ssh-rsa AAAAB3NzaC1yc2E...== existing-key@example",
  "ssh-rsa AAAAB3NzaC1yc2E...== your-new-key@example",  # Add your key here
]
```

### 3. Configure Node Distribution

Edit `vars-scale-up.tfvars` to define:
- **Instance types** for your nodes
- **Number of nodes** per region

Example configuration:

```hcl
# Instance types
COMMON_INSTANCE_TYPE = "t3.micro"
SPAM_INSTANCE_TYPE   = "t3.micro"

# Ireland (eu-west-1)
eu_west_1_bootstrap_nodes = "2"
eu_west_1_spam_nodes      = "0"
eu_west_1_validator_nodes = "3"

# North Virginia (us-east-1)
us_east_1_bootstrap_nodes = "1"
us_east_1_spam_nodes      = "0"
us_east_1_validator_nodes = "0"

# Frankfurt (eu-central-1)
eu_central_1_bootstrap_nodes = "0"
eu_central_1_spam_nodes      = "0"
eu_central_1_validator_nodes = "0"

# Mumbai (ap-south-1)
ap_south_1_bootstrap_nodes = "0"
ap_south_1_spam_nodes      = "0"
ap_south_1_validator_nodes = "0"

# North California (us-west-1)
us_west_1_bootstrap_nodes = "0"
us_west_1_spam_nodes      = "0"
us_west_1_validator_nodes = "0"
```

### 4. Enable/Disable Regions

In `locals.tf`, toggle which regions should be active:

```hcl
create_ireland_nodes   = true   # eu-west-1
create_frankfurt_nodes = false  # eu-central-1
create_mumbai_nodes    = false  # ap-south-1
create_us_east_nodes   = false  # us-east-1
create_us_west_nodes   = false  # us-west-1
```

### 5. Deploy

```sh
# Initialize Terraform
terraform init

# Preview changes
terraform plan -var-file=vars-scale-up.tfvars

# Apply changes
terraform apply -var-file=vars-scale-up.tfvars
```

### 6. Tear Down

To destroy all nodes:

```sh
terraform apply -var-file=vars-scale-down.tfvars
```

Or destroy everything:

```sh
terraform destroy -var-file=vars-scale-up.tfvars
```

## Node Types

For Hyperscale-RS, there is currently no functional distinction between node types:

| Node Type   | Description                                                    |
|-------------|----------------------------------------------------------------|
| Bootstrap   | Nodes that participate in genesis generation                   |
| Validator   | Identical to bootstrap nodes, but not tagged as bootstrap      |
| Spam        | Nodes designated for spam/load testing (same underlying setup) |

All node types use the same AMI and configuration. The distinction is purely for organizational and tagging purposes.

## Available Regions

| Region         | Location          | Variable Prefix    |
|----------------|-------------------|--------------------|
| eu-west-1      | Ireland           | `eu_west_1_*`      |
| eu-central-1   | Frankfurt         | `eu_central_1_*`   |
| ap-south-1     | Mumbai            | `ap_south_1_*`     |
| us-east-1      | North Virginia    | `us_east_1_*`      |
| us-west-1      | North California  | `us_west_1_*`      |

## Advanced Configuration

### Per-Node Customization

To customize individual nodes (e.g., different instance type, enable metrics), edit the regional `.tf` file (e.g., `eu-west-1.tf`):

```hcl
# In the locals {} section of eu-west-1.tf
eu_west_1_individual_bootstrap = {
  4 = {
    bootstrap = {
      "node" = {
        explicit_instance_type = "m6i.8xlarge"
        collect_metrics        = true
        collect_logs           = true
      }
    }
  }
}
```

This overrides the default configuration for bootstrap node #4 in Ireland.

## Useful Commands

List all Elastic IPs across regions:

```sh
./scripts/list-eips.sh
```

## File Reference

| File                    | Purpose                                         |
|-------------------------|-------------------------------------------------|
| `vars-scale-up.tfvars`  | Production node counts and instance types       |
| `vars-scale-down.tfvars`| Zero-node configuration for teardown            |
| `locals.tf`             | SSH keys, region toggles, storage configuration |
| `vars.tf`               | Variable definitions with defaults              |
| `provider.tf`           | AWS provider configuration for all regions      |
| `eu-west-1.tf`, etc.    | Region-specific node configurations             |
| `outputs.tf`            | Outputs (AMI IDs, public IPs)                   |
