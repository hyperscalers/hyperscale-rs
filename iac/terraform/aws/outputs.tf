output "regional_ami" {
  value = {
    #"us_east_1"    = data.aws_ami.us_east_1.name
    #"us_west_1"    = data.aws_ami.us_west_1.name
    "eu_west_1" = data.aws_ami.eu_west_1.name
    #  "eu_central_1" = data.aws_ami.eu_central_1.name
    # "ap_south_1"   = data.aws_ami.ap_south_1.name
  }
}

output "eu_west_1_all_public_ips" {
  value = local.create_ireland_nodes ? merge(
    try({
      for k, v in module.eu_west_1[0].public_bootstrap_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.eu_west_1[0].public_spam_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.eu_west_1[0].public_validator_instance_ips :
      k => v.public_ip
    }, {})
  ) : {}
}

output "eu_central_1_public_ips" {
  value = local.create_frankfurt_nodes ? merge(
    try({
      for k, v in module.eu_central_1[0].public_bootstrap_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.eu_central_1[0].public_spam_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.eu_central_1[0].public_validator_instance_ips :
      k => v.public_ip
    }, {})
  ) : {}
}

output "us_west_1_public_ips" {
  value = local.create_us_west_nodes ? merge(
    try({
      for k, v in module.us_west_1[0].public_bootstrap_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.us_west_1[0].public_spam_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.us_west_1[0].public_validator_instance_ips :
      k => v.public_ip
    }, {})
  ) : {}
}

output "us_east_1_public_ips" {
  value = local.create_us_east_nodes ? merge(
    try({
      for k, v in module.us_east_1[0].public_bootstrap_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.us_east_1[0].public_spam_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.us_east_1[0].public_validator_instance_ips :
      k => v.public_ip
    }, {})
  ) : {}
}

output "ap_south_1_public_ips" {
  value = local.create_mumbai_nodes ? merge(
    try({
      for k, v in module.ap_south_1[0].public_bootstrap_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.ap_south_1[0].public_spam_instance_ips :
      k => v.public_ip
    }, {}),

    try({
      for k, v in module.ap_south_1[0].public_validator_instance_ips :
      k => v.public_ip
    }, {})
  ) : {}
}
