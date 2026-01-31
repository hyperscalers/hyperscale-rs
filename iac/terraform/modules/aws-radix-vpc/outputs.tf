output "vpc_id" {
  value = aws_vpc.vpc.id
}
output "public_subnet_id" {
  value = aws_subnet.public_subnet.id
}

output "additional_public_subnets" {
  value = {
    for key, val in aws_subnet.additional_public_subnet : key => val.id
  }
}
output "sg_allow_ssh_8080_id" {
  value = aws_security_group.allow-ssh-8080.id
}

output "sg_allow_gossip_port_id" {
  value = aws_security_group.allow-gossip-port.id
}

output "sg_core_security_group" {
  value = aws_security_group.core_security_group.id
}

# Transform AWS EIP tags back to snake_case vars
locals {
  validator_vars = {
    for key, val in aws_eip.public_validator_instances :
    key => merge(
      { public_ip = val.public_ip },
      { for field in module.field_mapping.fields :
        field => lookup(val.tags, module.field_mapping.tag_mapping[field], null)
      }
    )
  }

  fullnode_vars = {
    for key, val in aws_eip.public_fullnode_instances :
    key => merge(
      { public_ip = val.public_ip },
      { for field in module.field_mapping.fields :
        field => lookup(val.tags, module.field_mapping.tag_mapping[field], null)
      }
    )
  }

  bootstrap_vars = {
    for key, val in aws_eip.public_bootstrap_instances :
    key => merge(
      { public_ip = val.public_ip },
      { for field in module.field_mapping.fields :
        field => lookup(val.tags, module.field_mapping.tag_mapping[field], null)
      }
    )
  }

  spam_vars = {
    for key, val in aws_eip.public_spam_instances :
    key => merge(
      { public_ip = val.public_ip },
      { for field in module.field_mapping.fields :
        field => lookup(val.tags, module.field_mapping.tag_mapping[field], null)
      }
    )
  }
}

output "public_validator_instance_ips" {
  value      = local.validator_vars
  depends_on = [aws_eip.public_validator_instances]
}

output "public_fullnode_instance_ips" {
  value      = local.fullnode_vars
  depends_on = [aws_eip.public_fullnode_instances]
}

output "public_witnessnode_instance_ips" {
  value = {
    for key, val in aws_eip.public_witnessnode_instances : key => {
      public_ip = val.public_ip
    }
  }
  depends_on = [aws_eip.public_witnessnode_instances]
}

####################################################################
# CASSANDRA OUTPUTS
####################################################################

output "public_bootstrap_instance_ips" {
  value      = local.bootstrap_vars
  depends_on = [aws_eip.public_bootstrap_instances]
}

output "public_spam_instance_ips" {
  value      = local.spam_vars
  depends_on = [aws_eip.public_spam_instances]
}