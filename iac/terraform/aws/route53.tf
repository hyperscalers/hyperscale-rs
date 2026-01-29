# data "aws_route53_zone" "this" {
#   name = "sandbox.extratools.works."
# }

# resource "aws_route53_record" "eu_west_1" {
#   for_each = local.create_ireland_nodes ? module.eu_west_1[0].all_instance_ips : {}

#   zone_id = data.aws_route53_zone.this.zone_id
#   name    = join(".", [join("-", ["hyperscalers-test", replace(each.key, "_", "-")]), "sandbox.extratools.works"])
#   type    = "A"
#   ttl     = 300
#   records = [each.value.public_ip]
# }

# resource "aws_route53_record" "eu_central_1" {
#   for_each = local.create_frankfurt_nodes ? module.eu_central_1[0].all_instance_ips : {}

#   zone_id = data.aws_route53_zone.this.zone_id
#   name    = join(".", [join("-", ["hyperscalers-test", replace(each.key, "_", "-")]), "sandbox.extratools.works"])
#   type    = "A"
#   ttl     = 300
#   records = [each.value.public_ip]
# }

# resource "aws_route53_record" "ap_south_1" {
#   for_each = local.create_mumbai_nodes ? module.ap_south_1[0].all_instance_ips : {}

#   zone_id = data.aws_route53_zone.this.zone_id
#   name    = join(".", [join("-", ["hyperscalers-test", replace(each.key, "_", "-")]), "sandbox.extratools.works"])
#   type    = "A"
#   ttl     = 300
#   records = [each.value.public_ip]
# }

# resource "aws_route53_record" "us_east_1" {
#   for_each = local.create_us_east_nodes ? module.us_east_1[0].all_instance_ips : {}

#   zone_id = data.aws_route53_zone.this.zone_id
#   name    = join(".", [join("-", ["hyperscalers-test", replace(each.key, "_", "-")]), "sandbox.extratools.works"])
#   type    = "A"
#   ttl     = 300
#   records = [each.value.public_ip]
# }

# resource "aws_route53_record" "us_west_1" {
#   for_each = local.create_us_west_nodes ? module.us_west_1[0].all_instance_ips : {}
#   zone_id  = data.aws_route53_zone.this.zone_id
#   name     = join(".", [join("-", ["hyperscalers-test", replace(each.key, "_", "-")]), "sandbox.extratools.works"])
#   type     = "A"
#   ttl      = 300
#   records  = [each.value.public_ip]
# }