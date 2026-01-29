########################################
# CREATE TAGS FOR NODES
########################################

module "tags-names" {
  source = "../cassandra-tags-names"

  region = replace(var.region, "-", "_")

  bootstrap_nodes = var.bootstrap
  spam_nodes      = var.spam
  validator_nodes = var.validator
}

output "BOOTSTRAP_TAGS" {
  value = module.tags-names.BOOTSTRAP_TAGS
}

output "SPAM_TAGS" {
  value = module.tags-names.SPAM_TAGS
}

output "VALIDATOR_TAGS" {
  value = module.tags-names.VALIDATOR_TAGS
}

####################################################################
# USE TAGS AND CREATE ALL RELEVANT VPC RESOURCES PER NODE GROUP
####################################################################

module "vpc_resources" {
  source = "../aws-radix-vpc"

  vpc_cidr = var.vpc_cidr

  public_subnet_availability_zone = var.primary_availability_zone

  public_subnet_cidr               = var.public_subnet_cidr
  create_nat_gateway               = var.create_nat_gateway
  private_subnet_cidr              = var.private_subnet_cidr
  private_subnet_availability_zone = var.primary_availability_zone


  public_bootstrap_instances = module.tags-names.BOOTSTRAP_TAGS
  public_spam_instances      = module.tags-names.SPAM_TAGS
  public_validator_instances = module.tags-names.VALIDATOR_TAGS

  ipv4_cidr_blocks = var.ipv4_cidr_blocks
  ipv6_cidr_blocks = var.ipv6_cidr_blocks

  enable_vpc_flow_logs = var.enable_vpc_flow_logs
  network_name         = var.network

  public_subnet_tags = {
    Name = "${var.public_subnet_cidr}-${var.primary_availability_zone}"
  }
  private_subnet_tags = {
    Name = "${var.private_subnet_cidr}-${var.primary_availability_zone}"
  }
  tags = merge(var.vpc_tags, {
    "radixdlt:region"  = var.region
    "radixdlt:network" = var.network
    }
  )
  vpc_tags = {
    Name = "vpc-${var.network}-${var.region}"
  }
}

####################################################################
# TAKE VPC MODULE OUTPUTS AND CREATE BOOTSTRAP NODES
####################################################################

output "public_bootstrap_instance_ips" {
  value = module.vpc_resources.public_bootstrap_instance_ips
}

module "bootstrap_nodes" {
  source            = "../aws-radix-core-node"
  availability_zone = var.primary_availability_zone
  ami               = var.BOOTSTRAP_AMI != "" ? var.BOOTSTRAP_AMI : var.COMMON_AMI
  instance_type     = var.BOOTSTRAP_INSTANCE_TYPE != "" ? var.BOOTSTRAP_INSTANCE_TYPE : var.COMMON_INSTANCE_TYPE
  subnet_id         = module.vpc_resources.public_subnet_id

  nodes = module.vpc_resources.public_bootstrap_instance_ips
  node_tags = merge(
    var.node_tags, {
      "radixdlt:region"           = var.region
      "radixdlt:network"          = var.network
      "radixdlt:application"      = "bootstrap"
      "radixdlt:environment-type" = var.network
      "radixdlt:team"             = "devops"
      "radixdlt:managed_by"       = "terraform"
    }
  )
  radix_network_name = var.network
  key_name           = var.key_pair != null ? var.key_pair.key_name : null
  vpc_security_group_ids = [
    aws_security_group.cassandra_validators_sg.id,
    module.vpc_resources.sg_allow_ssh_https_id,
    module.vpc_resources.sg_allow_gossip_port_id
  ]
  root_block_device           = var.root_block_device
  associate_eip               = true
  user_data                   = data.template_cloudinit_config.cloudinit-config.rendered
  ebs_block_devices           = var.ebs_block_devices
  iam_instance_profile        = var.ec2_instance_profile
  volume_detach_instance_stop = var.core_node_var_volume_detach_instance_stop
  ec2_tenancy                 = var.ec2_tenancy
}

####################################################################
# TAKE VPC MODULE OUTPUTS AND CREATE SPAM NODES
####################################################################

output "public_spam_instance_ips" {
  value = module.vpc_resources.public_spam_instance_ips
}

module "spam_nodes" {
  source            = "../aws-radix-core-node"
  availability_zone = var.primary_availability_zone
  ami               = var.SPAM_AMI != "" ? var.SPAM_AMI : var.COMMON_AMI
  instance_type     = var.SPAM_INSTANCE_TYPE != "" ? var.SPAM_INSTANCE_TYPE : var.COMMON_INSTANCE_TYPE
  subnet_id         = module.vpc_resources.public_subnet_id

  nodes = module.vpc_resources.public_spam_instance_ips
  node_tags = merge(
    var.node_tags, {
      "radixdlt:region"           = var.region
      "radixdlt:network"          = var.network
      "radixdlt:application"      = "spam"
      "radixdlt:environment-type" = var.network
      "radixdlt:team"             = "devops"
      "radixdlt:managed_by"       = "terraform"
    }
  )
  radix_network_name = var.network
  key_name           = var.key_pair != null ? var.key_pair.key_name : null
  vpc_security_group_ids = [
    aws_security_group.cassandra_validators_sg.id,
    module.vpc_resources.sg_allow_ssh_https_id,
    module.vpc_resources.sg_allow_gossip_port_id
  ]
  root_block_device           = var.root_block_device
  associate_eip               = true
  user_data                   = data.template_cloudinit_config.cloudinit-config.rendered
  ebs_block_devices           = var.ebs_block_devices
  iam_instance_profile        = var.ec2_instance_profile
  volume_detach_instance_stop = var.core_node_var_volume_detach_instance_stop
  ec2_tenancy                 = var.ec2_tenancy
}

####################################################################
# TAKE VPC MODULE OUTPUTS AND CREATE VALIDATOR NODES
####################################################################

output "public_validator_instance_ips" {
  value = module.vpc_resources.public_validator_instance_ips
}

module "validator_nodes" {
  source            = "../aws-radix-core-node"
  availability_zone = var.primary_availability_zone
  ami               = var.VALIDATOR_AMI != "" ? var.VALIDATOR_AMI : var.COMMON_AMI
  instance_type     = var.VALIDATOR_INSTANCE_TYPE != "" ? var.VALIDATOR_INSTANCE_TYPE : var.COMMON_INSTANCE_TYPE
  subnet_id         = module.vpc_resources.public_subnet_id
  nodes             = module.vpc_resources.public_validator_instance_ips
  node_tags = merge(
    var.node_tags, {
      "radixdlt:region"           = var.region
      "radixdlt:network"          = var.network
      "radixdlt:application"      = "validator"
      "radixdlt:environment-type" = var.network
      "radixdlt:team"             = "devops"
      "radixdlt:managed_by"       = "terraform"
    }
  )
  radix_network_name = var.network
  key_name           = var.key_pair != null ? var.key_pair.key_name : null
  vpc_security_group_ids = [
    module.vpc_resources.sg_allow_ssh_https_id,
    module.vpc_resources.sg_allow_gossip_port_id,
    aws_security_group.cassandra_validators_sg.id
  ]
  root_block_device           = var.root_block_device
  associate_eip               = true
  user_data                   = data.template_cloudinit_config.cloudinit-config.rendered
  ebs_block_devices           = var.ebs_block_devices
  iam_instance_profile        = var.ec2_instance_profile
  volume_detach_instance_stop = var.core_node_var_volume_detach_instance_stop
  running_or_stopped          = var.running_or_stopped
  ec2_tenancy                 = var.ec2_tenancy
}

output "all_instance_ips" {
  value = merge(
    module.vpc_resources.public_bootstrap_instance_ips,
    module.vpc_resources.public_spam_instance_ips,
    module.vpc_resources.public_validator_instance_ips
  )
}

####################################################################
# CREATE SECURITY GROUP USED BY ALL NODES (SHARED SG)
####################################################################

resource "aws_security_group" "cassandra_validators_sg" {
  name        = "${var.network}-${var.region}-nodes-sg"
  description = "Security group with custom port ranges for TCP and UDP communications, API, and Websockets"

  vpc_id = module.vpc_resources.vpc_id # Replace with your actual VPC ID

  # Ingress rules for TCP & UDP communications (30000-30010)
  # ingress {
  #   from_port   = 30000
  #   to_port     = 30010
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # ingress {
  #   from_port   = 30000
  #   to_port     = 30010
  #   protocol    = "udp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # # Ingress rules for API (8080-8090, TCP only)
  # ingress {
  #   from_port   = 8080
  #   to_port     = 8090
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # # Ingress rules for Websockets (8880-8900, TCP only)
  # ingress {
  #   from_port   = 8880
  #   to_port     = 8900
  #   protocol    = "tcp"
  #   cidr_blocks = ["0.0.0.0/0"]
  # }

  # Ingress rules for SSM (22, TCP only)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Egress rule (allowing all outbound traffic)
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name               = "${var.network}-${var.region}-nodes-sg"
    "radixdlt:network" = var.network
  }
}
