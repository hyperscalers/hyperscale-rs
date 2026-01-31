# data "aws_secretsmanager_secret" "cloudflare_extratools_dot_works" {
#   name     = "cloudflare/extratools.works"
#   provider = aws.eu-west-2
# }

# data "aws_secretsmanager_secret_version" "current_extratools_dot_works_details" {
#   secret_id = data.aws_secretsmanager_secret.cloudflare_extratools_dot_works.id
#   provider  = aws.eu-west-2
# }
