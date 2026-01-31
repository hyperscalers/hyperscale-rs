terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6"
    }
  }
}

locals {
  is_instance_type_of_t = replace(var.instance_type, "/^t(2|3|3a){1}\\..*$/", "1") == "1" ? true : false

  flat_node_vols = flatten([
    for name, cfg in var.nodes : [
      for dev, dev_cfg in lookup(var.ebs_block_devices, name, {}) : {
        format("%s%s", name, dev) = merge(cfg, {
          node_name   = name,
          device_name = dev,
          dev_cfg     = merge(dev_cfg, { az = var.availability_zone })
        })
      }
    ]
  ])
  node_vols = { for item in local.flat_node_vols : keys(item)[0] => values(item)[0] }
}

resource "aws_ec2_instance_state" "start_stop" {
  for_each    = aws_instance.nodes
  instance_id = each.value.id
  state       = var.running_or_stopped
}

resource "aws_instance" "nodes" {
  for_each = var.nodes
  ami      = lookup(each.value, "explicit_ami", null) == null ? var.ami : each.value["explicit_ami"]
  //  instance_type     = var.instance_type
  instance_type     = lookup(each.value, "explicit_instance_type", null) == null ? var.instance_type : each.value["explicit_instance_type"]
  availability_zone = var.availability_zone
  //  subnet_id              = "${data.aws_subnet.testnet_main_private_1.id}"
  subnet_id              = var.subnet_id
  key_name               = var.key_name != "" ? var.key_name : null
  vpc_security_group_ids = var.vpc_security_group_ids
  tags = merge(
    {
      Name                              = "${var.radix_network_name}_${each.key}"
      "radixdlt:node-regional-index"    = "${each.key}"
      "radixdlt:core-private-ip"        = lookup(each.value, "core_private_ip", null)
      "radixdlt:enable-health-api"      = lookup(each.value, "enable_health", null)
      "radixdlt:enable-metrics-api"     = lookup(each.value, "enable_metrics", null)
      "radixdlt:enable-validation-api"  = lookup(each.value, "enable_validation", null)
      "radixdlt:enable-version-api"     = lookup(each.value, "enable_version", null)
      "radixdlt:enable-jmx-exporter"    = lookup(each.value, "enable_jmx_exporter", null)
      "radixdlt:extra-archive"          = lookup(each.value, "extra_archive", null)
      "radixdlt:dns-subdomain"          = lookup(each.value, "dns_subdomain", null)
      "radixdlt:explicit-instance-type" = lookup(each.value, "explicit_instance_type", null)
      "radixdlt:genesis-validator"      = lookup(each.value, "genesis_validator", null)
      "radixdlt:migration-aux-node"     = lookup(each.value, "migration_aux_node", null)
      "radixdlt:access-type"            = lookup(each.value, "access_type", null)
      "radixdlt:collect-metrics"        = lookup(each.value, "collect_metrics", null)
      "radixdlt:collect-logs"           = lookup(each.value, "collect_logs", null)
    },
    var.node_tags
  )
  user_data = var.user_data
  dynamic "root_block_device" {
    for_each = var.root_block_device
    content {
      delete_on_termination = lookup(root_block_device.value, "delete_on_termination", null)
      encrypted             = lookup(root_block_device.value, "encrypted", null)
      iops                  = lookup(root_block_device.value, "iops", null)
      kms_key_id            = lookup(root_block_device.value, "kms_key_id", null)
      volume_size           = lookup(root_block_device.value, "volume_size", null)
      volume_type           = lookup(root_block_device.value, "volume_type", null)
      tags                  = merge(var.node_tags, { Name = "${var.radix_network_name}_${each.key}/dev/sda1" })
    }
  }

  dynamic "ebs_block_device" {
    for_each = var.ebs_block_device
    content {
      delete_on_termination = lookup(ebs_block_device.value, "delete_on_termination", null)
      device_name           = ebs_block_device.value.device_name
      encrypted             = lookup(ebs_block_device.value, "encrypted", null)
      iops                  = lookup(ebs_block_device.value, "iops", null)
      kms_key_id            = lookup(ebs_block_device.value, "kms_key_id", null)
      snapshot_id           = lookup(ebs_block_device.value, "snapshot_id", null)
      volume_size           = lookup(ebs_block_device.value, "volume_size", null)
      volume_type           = lookup(ebs_block_device.value, "volume_type", null)
    }
  }
  iam_instance_profile = var.iam_instance_profile
  credit_specification {
    cpu_credits = local.is_instance_type_of_t ? var.cpu_credits : null
  }
  private_ip = var.private_ip != null ? each.value["private_ip"] : null
  tenancy    = var.ec2_tenancy
}


resource "aws_eip_association" "aws_eip" {
  for_each    = var.associate_eip ? var.nodes : {}
  instance_id = aws_instance.nodes[each.key].id
  public_ip   = each.value["public_ip"]
}

resource "aws_volume_attachment" "this" {
  for_each = local.node_vols

  device_name = each.value.device_name
  volume_id   = aws_ebs_volume.this[each.key].id
  instance_id = aws_instance.nodes[each.value.node_name].id

  stop_instance_before_detaching = var.volume_detach_instance_stop
}

resource "aws_ebs_volume" "this" {
  for_each = local.node_vols

  encrypted         = each.value.dev_cfg.encrypted
  type              = each.value.dev_cfg.volume_type
  size              = each.value.dev_cfg.volume_size
  availability_zone = each.value.dev_cfg.az

  tags = merge(var.node_tags, { Name = "${var.radix_network_name}_${each.key}" })
}
