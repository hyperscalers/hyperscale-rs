<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 4 |
| <a name="requirement_cloudflare"></a> [cloudflare](#requirement\_cloudflare) | >= 3.4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 4 |
| <a name="provider_template"></a> [template](#provider\_template) | n/a |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_bootstrap_nodes"></a> [bootstrap\_nodes](#module\_bootstrap\_nodes) | ../aws-radix-core-node | n/a |
| <a name="module_spam_nodes"></a> [spam\_nodes](#module\_spam\_nodes) | ../aws-radix-core-node | n/a |
| <a name="module_tags-names"></a> [tags-names](#module\_tags-names) | ../cassandra-tags-names | n/a |
| <a name="module_validator_nodes"></a> [validator\_nodes](#module\_validator\_nodes) | ../aws-radix-core-node | n/a |
| <a name="module_vpc_resources"></a> [vpc\_resources](#module\_vpc\_resources) | ../aws-radix-vpc | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_security_group.cassandra_validators_sg](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [template_cloudinit_config.cloudinit-config](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/cloudinit_config) | data source |
| [template_file.shell-script](https://registry.terraform.io/providers/hashicorp/template/latest/docs/data-sources/file) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_BOOTSTRAP_AMI"></a> [BOOTSTRAP\_AMI](#input\_BOOTSTRAP\_AMI) | n/a | `string` | `""` | no |
| <a name="input_BOOTSTRAP_INSTANCE_TYPE"></a> [BOOTSTRAP\_INSTANCE\_TYPE](#input\_BOOTSTRAP\_INSTANCE\_TYPE) | n/a | `string` | `""` | no |
| <a name="input_COMMON_AMI"></a> [COMMON\_AMI](#input\_COMMON\_AMI) | n/a | `string` | n/a | yes |
| <a name="input_COMMON_INSTANCE_TYPE"></a> [COMMON\_INSTANCE\_TYPE](#input\_COMMON\_INSTANCE\_TYPE) | n/a | `string` | n/a | yes |
| <a name="input_SPAM_AMI"></a> [SPAM\_AMI](#input\_SPAM\_AMI) | n/a | `string` | `""` | no |
| <a name="input_SPAM_INSTANCE_TYPE"></a> [SPAM\_INSTANCE\_TYPE](#input\_SPAM\_INSTANCE\_TYPE) | n/a | `string` | `""` | no |
| <a name="input_VALIDATOR_AMI"></a> [VALIDATOR\_AMI](#input\_VALIDATOR\_AMI) | n/a | `string` | `""` | no |
| <a name="input_VALIDATOR_INSTANCE_TYPE"></a> [VALIDATOR\_INSTANCE\_TYPE](#input\_VALIDATOR\_INSTANCE\_TYPE) | n/a | `string` | `""` | no |
| <a name="input_bootstrap"></a> [bootstrap](#input\_bootstrap) | n/a | `any` | n/a | yes |
| <a name="input_core_node_var_volume_detach_instance_stop"></a> [core\_node\_var\_volume\_detach\_instance\_stop](#input\_core\_node\_var\_volume\_detach\_instance\_stop) | n/a | `bool` | `false` | no |
| <a name="input_create_nat_gateway"></a> [create\_nat\_gateway](#input\_create\_nat\_gateway) | n/a | `bool` | `false` | no |
| <a name="input_ebs_block_devices"></a> [ebs\_block\_devices](#input\_ebs\_block\_devices) | n/a | `map(map(any))` | `{}` | no |
| <a name="input_ec2_instance_profile"></a> [ec2\_instance\_profile](#input\_ec2\_instance\_profile) | n/a | `string` | `""` | no |
| <a name="input_enable_vpc_flow_logs"></a> [enable\_vpc\_flow\_logs](#input\_enable\_vpc\_flow\_logs) | Control enabling/disabling vpc flow logs | `bool` | `false` | no |
| <a name="input_first_external_device_info"></a> [first\_external\_device\_info](#input\_first\_external\_device\_info) | n/a | `any` | n/a | yes |
| <a name="input_ipv4_cidr_blocks"></a> [ipv4\_cidr\_blocks](#input\_ipv4\_cidr\_blocks) | n/a | `list` | `[]` | no |
| <a name="input_ipv6_cidr_blocks"></a> [ipv6\_cidr\_blocks](#input\_ipv6\_cidr\_blocks) | n/a | `list` | `[]` | no |
| <a name="input_key_pair"></a> [key\_pair](#input\_key\_pair) | n/a | `any` | `null` | no |
| <a name="input_network"></a> [network](#input\_network) | n/a | `string` | n/a | yes |
| <a name="input_node_tags"></a> [node\_tags](#input\_node\_tags) | n/a | `map` | `{}` | no |
| <a name="input_primary_availability_zone"></a> [primary\_availability\_zone](#input\_primary\_availability\_zone) | n/a | `string` | n/a | yes |
| <a name="input_private_subnet_cidr"></a> [private\_subnet\_cidr](#input\_private\_subnet\_cidr) | "10.0.2.0/24" | `string` | n/a | yes |
| <a name="input_public_subnet_cidr"></a> [public\_subnet\_cidr](#input\_public\_subnet\_cidr) | "10.0.1.0/24" | `string` | n/a | yes |
| <a name="input_region"></a> [region](#input\_region) | n/a | `string` | n/a | yes |
| <a name="input_root_block_device"></a> [root\_block\_device](#input\_root\_block\_device) | Customize details about the root block device of the instance | `list(map(string))` | n/a | yes |
| <a name="input_running_or_stopped"></a> [running\_or\_stopped](#input\_running\_or\_stopped) | n/a | `string` | `"running"` | no |
| <a name="input_spam"></a> [spam](#input\_spam) | n/a | `any` | n/a | yes |
| <a name="input_validator"></a> [validator](#input\_validator) | n/a | `any` | n/a | yes |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | n/a | `string` | n/a | yes |
| <a name="input_vpc_tags"></a> [vpc\_tags](#input\_vpc\_tags) | n/a | `map` | `{}` | no |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_BOOTSTRAP_TAGS"></a> [BOOTSTRAP\_TAGS](#output\_BOOTSTRAP\_TAGS) | n/a |
| <a name="output_SPAM_TAGS"></a> [SPAM\_TAGS](#output\_SPAM\_TAGS) | n/a |
| <a name="output_VALIDATOR_TAGS"></a> [VALIDATOR\_TAGS](#output\_VALIDATOR\_TAGS) | n/a |
| <a name="output_all_instance_ips"></a> [all\_instance\_ips](#output\_all\_instance\_ips) | n/a |
| <a name="output_cloudinit_config"></a> [cloudinit\_config](#output\_cloudinit\_config) | n/a |
| <a name="output_public_bootstrap_instance_ips"></a> [public\_bootstrap\_instance\_ips](#output\_public\_bootstrap\_instance\_ips) | n/a |
| <a name="output_public_spam_instance_ips"></a> [public\_spam\_instance\_ips](#output\_public\_spam\_instance\_ips) | n/a |
| <a name="output_public_validator_instance_ips"></a> [public\_validator\_instance\_ips](#output\_public\_validator\_instance\_ips) | n/a |
<!-- END_TF_DOCS -->