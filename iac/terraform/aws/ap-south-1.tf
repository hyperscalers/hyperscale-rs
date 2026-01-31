data "aws_ami" "ap_south_1" {
  provider    = aws.ap-south-1
  most_recent = true
  name_regex  = local.ami_filter_prefix
  owners      = ["471354728008"]
}

locals {
  ap_south_1 = {
    region                 = "ap-south-1"
    availability_zone      = "ap-south-1a"
    AMI_UBUNTU_22_04LTS    = data.aws_ami.ap_south_1.id
    num_of_bootstrap_nodes = var.ap_south_1_bootstrap_nodes
    num_of_spam_nodes      = var.ap_south_1_spam_nodes
    num_of_validator_nodes = var.ap_south_1_validator_nodes
  }

  # This local defines all nodes that need to have different EBS configuration
  # from the ones created using for loop
  ap_south_1_individual_ebs_devices = {
    "ap_south_1_bootstrap0" = {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
      # "${local.second_external_device_info.physical_volume_name}" = local.second_external_device_info.config
    }
    "ap_south_1_spam0" = {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }

  ap_south_1_bootstrap_ebs_devices = {
    for idx in range(local.ap_south_1.num_of_bootstrap_nodes) :
    "ap_south_1_bootstrap${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }
  ap_south_1_spam_ebs_devices = {
    for idx in range(local.ap_south_1.num_of_spam_nodes) :
    "ap_south_1_spam${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }
  }
  ap_south_1_validator_ebs_devices = {
    for idx in range(local.ap_south_1.num_of_validator_nodes) :
    "ap_south_1_validator${idx}" => {
      "${local.first_external_device_info.physical_volume_name}" = local.first_external_device_info.config
    }

  }
  merged_ap_south_1_ebs_devices = merge(local.ap_south_1_bootstrap_ebs_devices, local.ap_south_1_individual_ebs_devices, local.ap_south_1_spam_ebs_devices, local.ap_south_1_validator_ebs_devices)

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  ap_south_1_individual_bootstrap = {
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
  ap_south_1_bootstrap = {
    for idx in range(local.ap_south_1.num_of_bootstrap_nodes) :
    idx => {
      bootstrap = {
        "node" = {
        }
      }
    }
  }

  filtered_ap_south_1_individual_bootstrap = {
    for idx, cfg in local.ap_south_1_individual_bootstrap :
    idx => cfg
    if idx < local.ap_south_1.num_of_bootstrap_nodes
  }

  merged_ap_south_1_bootstraps = (
    local.ap_south_1.num_of_bootstrap_nodes > 0 ?
    merge(local.ap_south_1_bootstrap, local.filtered_ap_south_1_individual_bootstrap) :
    {}
  )

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  ap_south_1_individual_spams = {
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
  ap_south_1_spams = {
    for idx in range(local.ap_south_1.num_of_spam_nodes) :
    idx => {
      spam = {
        "node" = {
        }
      }
    }
  }

  filtered_ap_south_1_individual_spams = {
    for idx, cfg in local.ap_south_1_individual_spams :
    idx => cfg
    if idx < local.ap_south_1.num_of_spam_nodes
  }

  merged_ap_south_1_spams = (
    local.ap_south_1.num_of_spam_nodes > 0 ?
    merge(local.ap_south_1_spams, local.filtered_ap_south_1_individual_spams) :
    {}
  )

  # This local defines all nodes that need to have different configuration
  # from the ones created using for loop
  ap_south_1_individual_validators = {
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
  ap_south_1_validators = {
    for idx in range(local.ap_south_1.num_of_validator_nodes) :
    idx => {
      validator = {
        "node" = {
        }
      }
    }
  }

  filtered_ap_south_1_individual_validators = {
    for idx, cfg in local.ap_south_1_individual_validators :
    idx => cfg
    if idx < local.ap_south_1.num_of_validator_nodes
  }

  merged_ap_south_1_validators = (
    local.ap_south_1.num_of_validator_nodes > 0 ?
    merge(local.ap_south_1_validators, local.filtered_ap_south_1_individual_validators) :
    {}
  )
}

data "aws_key_pair" "ap_south_1_key_pair" {
  key_name = aws_key_pair.hyperscalers_ap_south_1_key_pair.key_name
  provider = aws.ap-south-1
}

resource "aws_key_pair" "hyperscalers_ap_south_1_key_pair" {
  key_name   = "hyperscalers-test-ap-south-1-key"
  public_key = local.casandra_key.public_key
  provider   = aws.ap-south-1

  tags = {
    "radixdlt:managed_by" = "terraform"
  }
}

module "ap_south_1" {
  count = local.create_mumbai_nodes ? 1 : 0

  source = "../modules/aws-cassandra-babylon-network-region"
  providers = {
    aws = aws.ap-south-1
  }
  COMMON_AMI           = local.ap_south_1.AMI_UBUNTU_22_04LTS
  COMMON_INSTANCE_TYPE = var.COMMON_INSTANCE_TYPE
  SPAM_INSTANCE_TYPE   = var.SPAM_INSTANCE_TYPE

  bootstrap = local.merged_ap_south_1_bootstraps
  spam      = local.merged_ap_south_1_spams
  validator = local.merged_ap_south_1_validators

  network                                   = var.network_name
  primary_availability_zone                 = local.ap_south_1.availability_zone
  region                                    = local.ap_south_1.region
  root_block_device                         = local.default_root_block_device
  vpc_cidr                                  = "10.52.0.0/16"
  public_subnet_cidr                        = "10.52.0.0/23"
  private_subnet_cidr                       = "10.52.2.0/23"
  key_pair                                  = data.aws_key_pair.ap_south_1_key_pair
  ebs_block_devices                         = local.merged_ap_south_1_ebs_devices
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
  additional_ssh_keys = local.additional_ssh_keys
}
