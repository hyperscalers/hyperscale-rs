<!-- BEGIN_TF_DOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.0.0 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | ~> 6 |
| <a name="requirement_cloudflare"></a> [cloudflare](#requirement\_cloudflare) | >= 3.4.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | ~> 6 |
| <a name="provider_cloudflare"></a> [cloudflare](#provider\_cloudflare) | >= 3.4.0 |

## Modules

| Name | Source | Version |
|------|--------|---------|
| <a name="module_public_bootstrap_instances"></a> [public\_bootstrap\_instances](#module\_public\_bootstrap\_instances) | ./tags-vars | n/a |
| <a name="module_public_fullnode_instances"></a> [public\_fullnode\_instances](#module\_public\_fullnode\_instances) | ./tags-vars | n/a |
| <a name="module_public_fullnode_instances_archive_nodes"></a> [public\_fullnode\_instances\_archive\_nodes](#module\_public\_fullnode\_instances\_archive\_nodes) | ./tags-vars | n/a |
| <a name="module_public_spam_instances"></a> [public\_spam\_instances](#module\_public\_spam\_instances) | ./tags-vars | n/a |
| <a name="module_public_validator_instances"></a> [public\_validator\_instances](#module\_public\_validator\_instances) | ./tags-vars | n/a |
| <a name="module_var_tags_bootstrap"></a> [var\_tags\_bootstrap](#module\_var\_tags\_bootstrap) | ./var-tags | n/a |
| <a name="module_var_tags_fullnodes"></a> [var\_tags\_fullnodes](#module\_var\_tags\_fullnodes) | ./var-tags | n/a |
| <a name="module_var_tags_spam"></a> [var\_tags\_spam](#module\_var\_tags\_spam) | ./var-tags | n/a |
| <a name="module_var_tags_validator"></a> [var\_tags\_validator](#module\_var\_tags\_validator) | ./var-tags | n/a |

## Resources

| Name | Type |
|------|------|
| [aws_cloudwatch_log_group.vpc-flow-logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudwatch_log_group) | resource |
| [aws_eip.nat_eip](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.public_bootstrap_instances](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.public_fullnode_instances](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.public_spam_instances](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.public_validator_instances](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_eip.public_witnessnode_instances](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eip) | resource |
| [aws_flow_log.vpc-flow-log](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/flow_log) | resource |
| [aws_iam_role.vpc-flow-logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role) | resource |
| [aws_iam_role_policy.vpc-flow-logs](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_role_policy) | resource |
| [aws_internet_gateway.igw](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/internet_gateway) | resource |
| [aws_nat_gateway.gw](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/nat_gateway) | resource |
| [aws_route.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route) | resource |
| [aws_route_table.public_route](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table) | resource |
| [aws_route_table_association.additional_public_subnet_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_route_table_association.public_subnet_association](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/route_table_association) | resource |
| [aws_security_group.allow-gossip-port](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.allow-ssh-http-https](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_security_group.core_security_group](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/security_group) | resource |
| [aws_subnet.additional_public_subnet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_subnet.private_subnet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_subnet.public_subnet](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet) | resource |
| [aws_vpc.vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/vpc) | resource |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_route_table.main](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/route_table) | data source |
| [cloudflare_ip_ranges.cloudflare](https://registry.terraform.io/providers/cloudflare/cloudflare/latest/docs/data-sources/ip_ranges) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_additional_public_subnets"></a> [additional\_public\_subnets](#input\_additional\_public\_subnets) | n/a | `map` | `{}` | no |
| <a name="input_create_nat_gateway"></a> [create\_nat\_gateway](#input\_create\_nat\_gateway) | n/a | `bool` | `true` | no |
| <a name="input_devops_ipv4_cidr"></a> [devops\_ipv4\_cidr](#input\_devops\_ipv4\_cidr) | n/a | `list` | `[]` | no |
| <a name="input_devops_ipv6_cidr"></a> [devops\_ipv6\_cidr](#input\_devops\_ipv6\_cidr) | n/a | `list` | `[]` | no |
| <a name="input_enable_dns_hostnames"></a> [enable\_dns\_hostnames](#input\_enable\_dns\_hostnames) | n/a | `string` | `"true"` | no |
| <a name="input_enable_dns_support"></a> [enable\_dns\_support](#input\_enable\_dns\_support) | n/a | `string` | `"true"` | no |
| <a name="input_enable_vpc_flow_logs"></a> [enable\_vpc\_flow\_logs](#input\_enable\_vpc\_flow\_logs) | Control enabling/disabling vpc flow logs | `bool` | `false` | no |
| <a name="input_igw_tags"></a> [igw\_tags](#input\_igw\_tags) | Additional tags for the internet gateway | `map(string)` | `{}` | no |
| <a name="input_ipv4_cidr_blocks"></a> [ipv4\_cidr\_blocks](#input\_ipv4\_cidr\_blocks) | n/a | `list` | `[]` | no |
| <a name="input_ipv6_cidr_blocks"></a> [ipv6\_cidr\_blocks](#input\_ipv6\_cidr\_blocks) | n/a | `list` | `[]` | no |
| <a name="input_network_name"></a> [network\_name](#input\_network\_name) | n/a | `string` | n/a | yes |
| <a name="input_private_subnet_availability_zone"></a> [private\_subnet\_availability\_zone](#input\_private\_subnet\_availability\_zone) | n/a | `string` | n/a | yes |
| <a name="input_private_subnet_cidr"></a> [private\_subnet\_cidr](#input\_private\_subnet\_cidr) | n/a | `any` | n/a | yes |
| <a name="input_private_subnet_tags"></a> [private\_subnet\_tags](#input\_private\_subnet\_tags) | n/a | `any` | n/a | yes |
| <a name="input_public_bootstrap_instances"></a> [public\_bootstrap\_instances](#input\_public\_bootstrap\_instances) | n/a | `map` | `{}` | no |
| <a name="input_public_fullnode_instances"></a> [public\_fullnode\_instances](#input\_public\_fullnode\_instances) | n/a | `map` | `{}` | no |
| <a name="input_public_spam_instances"></a> [public\_spam\_instances](#input\_public\_spam\_instances) | n/a | `map` | `{}` | no |
| <a name="input_public_subnet_availability_zone"></a> [public\_subnet\_availability\_zone](#input\_public\_subnet\_availability\_zone) | n/a | `string` | n/a | yes |
| <a name="input_public_subnet_cidr"></a> [public\_subnet\_cidr](#input\_public\_subnet\_cidr) | n/a | `any` | n/a | yes |
| <a name="input_public_subnet_tags"></a> [public\_subnet\_tags](#input\_public\_subnet\_tags) | n/a | `any` | n/a | yes |
| <a name="input_public_validator_instances"></a> [public\_validator\_instances](#input\_public\_validator\_instances) | n/a | `any` | n/a | yes |
| <a name="input_public_witnessnode_instances"></a> [public\_witnessnode\_instances](#input\_public\_witnessnode\_instances) | n/a | `map` | `{}` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | A map of tags to add to all resources | `map(string)` | `{}` | no |
| <a name="input_tenacy"></a> [tenacy](#input\_tenacy) | n/a | `string` | `"default"` | no |
| <a name="input_vpc_cidr"></a> [vpc\_cidr](#input\_vpc\_cidr) | n/a | `any` | n/a | yes |
| <a name="input_vpc_tags"></a> [vpc\_tags](#input\_vpc\_tags) | n/a | `any` | n/a | yes |

## Outputs

| Name | Description |
|------|-------------|
| <a name="output_additional_public_subnets"></a> [additional\_public\_subnets](#output\_additional\_public\_subnets) | n/a |
| <a name="output_gateway_node_instance_ips"></a> [gateway\_node\_instance\_ips](#output\_gateway\_node\_instance\_ips) | n/a |
| <a name="output_ipv4"></a> [ipv4](#output\_ipv4) | n/a |
| <a name="output_ipv6"></a> [ipv6](#output\_ipv6) | n/a |
| <a name="output_public_bootstrap_instance_ips"></a> [public\_bootstrap\_instance\_ips](#output\_public\_bootstrap\_instance\_ips) | n/a |
| <a name="output_public_fullnode_instance_ips"></a> [public\_fullnode\_instance\_ips](#output\_public\_fullnode\_instance\_ips) | n/a |
| <a name="output_public_non_archive_instance_ips"></a> [public\_non\_archive\_instance\_ips](#output\_public\_non\_archive\_instance\_ips) | n/a |
| <a name="output_public_spam_instance_ips"></a> [public\_spam\_instance\_ips](#output\_public\_spam\_instance\_ips) | n/a |
| <a name="output_public_subnet_id"></a> [public\_subnet\_id](#output\_public\_subnet\_id) | n/a |
| <a name="output_public_validator_instance_ips"></a> [public\_validator\_instance\_ips](#output\_public\_validator\_instance\_ips) | n/a |
| <a name="output_public_witnessnode_instance_ips"></a> [public\_witnessnode\_instance\_ips](#output\_public\_witnessnode\_instance\_ips) | n/a |
| <a name="output_sg_allow_gossip_port_id"></a> [sg\_allow\_gossip\_port\_id](#output\_sg\_allow\_gossip\_port\_id) | n/a |
| <a name="output_sg_allow_ssh_https_id"></a> [sg\_allow\_ssh\_https\_id](#output\_sg\_allow\_ssh\_https\_id) | n/a |
| <a name="output_sg_core_security_group"></a> [sg\_core\_security\_group](#output\_sg\_core\_security\_group) | n/a |
| <a name="output_vpc_id"></a> [vpc\_id](#output\_vpc\_id) | n/a |
<!-- END_TF_DOCS -->