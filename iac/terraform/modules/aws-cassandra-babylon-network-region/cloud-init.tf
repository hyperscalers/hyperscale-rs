data "template_file" "shell-script" {
  template = file("${path.module}/scripts/volumes.sh")
  vars = {
    DEVICE      = var.first_external_device_info.nvm_devicename
    VOLUME_NAME = var.first_external_device_info.volume_name
  }
}

locals {
  ssh_keys_cloud_config = length(var.additional_ssh_keys) > 0 ? yamlencode({
    ssh_authorized_keys = var.additional_ssh_keys
  }) : ""
}

data "template_cloudinit_config" "cloudinit-config" {
  gzip          = false
  base64_encode = false

  dynamic "part" {
    for_each = length(var.additional_ssh_keys) > 0 ? [1] : []
    content {
      content_type = "text/cloud-config"
      content      = "#cloud-config\n${local.ssh_keys_cloud_config}"
    }
  }

  part {
    content_type = "text/x-shellscript"
    content      = data.template_file.shell-script.rendered
  }
}

output "cloudinit_config" {
  value = data.template_cloudinit_config.cloudinit-config
}