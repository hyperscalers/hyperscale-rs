
data "template_file" "shell-script" {
  template = file("${path.module}/scripts/volumes.sh")
  vars = {
    DEVICE      = var.first_external_device_info.nvm_devicename
    VOLUME_NAME = var.first_external_device_info.volume_name
  }
}

data "template_cloudinit_config" "cloudinit-config" {
  gzip          = false
  base64_encode = false
  part {
    content_type = "text/x-shellscript"
    content      = data.template_file.shell-script.rendered
  }
}

output "cloudinit_config" {
  value = data.template_cloudinit_config.cloudinit-config
}