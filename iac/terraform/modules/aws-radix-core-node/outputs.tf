output "public_ip" {
  value = { for key, val in aws_instance.nodes : key => val.public_ip }
}

output "instance" {
  value = { for key, val in aws_instance.nodes : key => val.id }
}

output "instance_ips" {
  value = { for key, val in aws_instance.nodes : key => val.public_ip }
}

output "private_instance_ips" {
  value = { for key, val in aws_instance.nodes : key => { private_ip : val.private_ip } }
}

output "instance_details" {
  value = {
    for key, val in aws_instance.nodes : key => val
    //    if val.enable_archive == "true" && val.extra_archive == "true"
  }
}
