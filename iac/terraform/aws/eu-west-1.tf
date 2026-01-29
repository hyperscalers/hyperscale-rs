data "aws_ami" "eu_west_1" {
  provider    = aws.eu-west-1
  most_recent = true
  name_regex  = local.ami_filter_prefix
  owners      = ["482406383367"]
}

locals {
  eu_west_1 = {
    region                 = "eu-west-1"
    availability_zone      = "eu-west-1a"
    AMI_UBUNTU_22_04LTS    = data.aws_ami.eu_west_1.id
    num_of_bootstrap_nodes = var.eu_west_1_bootstrap_nodes
    num_of_spam_nodes      = var.eu_west_1_spam_nodes
    num_of_validator_nodes = var.eu_west_1_validator_nodes
  }

  # This local defines all nodes that need to have different EBS configuration
  # from the ones created using for loop
  eu_west_1_individual_ebs_devices = {
    "eu_west_1_bootstrap0" = {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
      # "${local.second_external_device_info.physical_volume_name}" = local.second_external_device_info.config
    }
    "eu_west_1_spam0" = {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }

  eu_west_1_bootstrap_ebs_devices = {
    for idx in range(local.eu_west_1.num_of_bootstrap_nodes) :
    "eu_west_1_bootstrap${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }
  eu_west_1_spam_ebs_devices = {
    for idx in range(local.eu_west_1.num_of_spam_nodes) :
    "eu_west_1_spam${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }
  eu_west_1_validator_ebs_devices = {
    for idx in range(local.eu_west_1.num_of_validator_nodes) :
    "eu_west_1_validator${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }

  }
  merged_eu_west_1_ebs_devices = merge(local.eu_west_1_bootstrap_ebs_devices, local.eu_west_1_individual_ebs_devices, local.eu_west_1_spam_ebs_devices, local.eu_west_1_validator_ebs_devices)

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  eu_west_1_individual_bootstrap = {
    0 = {
      bootstrap = {
        "node" = {
          collect_metrics = true
        }
      }
    }
    1 = {
      bootstrap = {
        "node" = {
          collect_metrics = true
        }
      }
    }
  }
  eu_west_1_bootstrap = {
    for idx in range(local.eu_west_1.num_of_bootstrap_nodes) :
    idx => {
      bootstrap = {
        "node" = {
        }
      }
    }
  }

  filtered_eu_west_1_individual_bootstrap = {
    for idx, cfg in local.eu_west_1_individual_bootstrap :
    idx => cfg
    if idx < local.eu_west_1.num_of_bootstrap_nodes
  }

  merged_eu_west_1_bootstraps = (
    local.eu_west_1.num_of_bootstrap_nodes > 0 ?
    merge(local.eu_west_1_bootstrap, local.filtered_eu_west_1_individual_bootstrap) :
    {}
  )

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  eu_west_1_individual_spams = {
    0 = {
      spam = {
        "node" = {
          collect_metrics = true
        }
      }
    }
    1 = {
      spam = {
        "node" = {
          collect_metrics = true
        }
      }
    }
  }
  eu_west_1_spams = {
    for idx in range(local.eu_west_1.num_of_spam_nodes) :
    idx => {
      spam = {
        "node" = {
        }
      }
    }
  }

  filtered_eu_west_1_individual_spams = {
    for idx, cfg in local.eu_west_1_individual_spams :
    idx => cfg
    if idx < local.eu_west_1.num_of_spam_nodes
  }

  merged_eu_west_1_spams = (
    local.eu_west_1.num_of_spam_nodes > 0 ?
    merge(local.eu_west_1_spams, local.filtered_eu_west_1_individual_spams) :
    {}
  )

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  eu_west_1_individual_validators = {
    0 = {
      validator = {
        "node" = {
          collect_metrics = true
        }
      }
    }
    1 = {
      validator = {
        "node" = {
          collect_metrics = true
        }
      }
    }
  }
  eu_west_1_validators = {
    for idx in range(local.eu_west_1.num_of_validator_nodes) :
    idx => {
      validator = {
        "node" = {
        }
      }
    }
  }

  filtered_eu_west_1_individual_validators = {
    for idx, cfg in local.eu_west_1_individual_validators :
    idx => cfg
    if idx < local.eu_west_1.num_of_validator_nodes
  }

  merged_eu_west_1_validators = (
    local.eu_west_1.num_of_validator_nodes > 0 ?
    merge(local.eu_west_1_validators, local.filtered_eu_west_1_individual_validators) :
    {}
  )
}

data "aws_key_pair" "eu_west_1_key_pair" {
  key_name = aws_key_pair.cassandra_eu_west_1_key_pair.key_name
  provider = aws.eu-west-1
}

resource "aws_key_pair" "cassandra_eu_west_1_key_pair" {
  key_name   = "cassandra-test-eu-west-1-key"
  public_key = local.casandra_key.public_key
  provider   = aws.eu-west-1

  tags = {
    "radixdlt:managed_by" = "terraform"
  }
}

module "eu_west_1" {
  count = local.create_ireland_nodes ? 1 : 0

  source = "../modules/aws-cassandra-babylon-network-region"
  providers = {
    aws = aws.eu-west-1
  }
  COMMON_AMI           = local.eu_west_1.AMI_UBUNTU_22_04LTS
  COMMON_INSTANCE_TYPE = var.COMMON_INSTANCE_TYPE
  SPAM_INSTANCE_TYPE   = var.SPAM_INSTANCE_TYPE

  bootstrap = local.merged_eu_west_1_bootstraps
  spam      = local.merged_eu_west_1_spams
  validator = local.merged_eu_west_1_validators

  network                                   = var.network_name
  primary_availability_zone                 = local.eu_west_1.availability_zone
  region                                    = local.eu_west_1.region
  root_block_device                         = local.default_root_block_device
  vpc_cidr                                  = "10.50.0.0/16"
  public_subnet_cidr                        = "10.50.0.0/23"
  private_subnet_cidr                       = "10.50.2.0/23"
  key_pair                                  = data.aws_key_pair.eu_west_1_key_pair
  ebs_block_devices                         = local.merged_eu_west_1_ebs_devices
  create_nat_gateway                        = false
  first_external_device_info                = local.first_external_device_info
  ipv4_cidr_blocks                          = ["0.0.0.0/0"]
  ipv6_cidr_blocks                          = ["::/0"]
  ec2_instance_profile                      = data.aws_iam_instance_profile.role_testnets_ec2_iam_profile.name
  core_node_var_volume_detach_instance_stop = true
  running_or_stopped                        = var.running_or_stopped
  node_tags = {
    "radixdlt:cloud_provider" = "AWS"
  }
  vpc_tags = {
    "radixdlt:managed_by" = "terraform"
  }
}
