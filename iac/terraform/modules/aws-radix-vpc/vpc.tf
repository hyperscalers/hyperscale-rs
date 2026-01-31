resource "aws_vpc" "vpc" {
  cidr_block           = var.vpc_cidr
  instance_tenancy     = var.tenacy
  enable_dns_support   = var.enable_dns_support
  enable_dns_hostnames = var.enable_dns_hostnames
  tags                 = merge(var.tags, var.vpc_tags)
}

resource "aws_subnet" "public_subnet" {
  cidr_block              = var.public_subnet_cidr
  vpc_id                  = aws_vpc.vpc.id
  map_public_ip_on_launch = true
  availability_zone       = var.public_subnet_availability_zone
  tags                    = merge(var.tags, var.public_subnet_tags)
}

resource "aws_subnet" "additional_public_subnet" {
  for_each                = var.additional_public_subnets
  cidr_block              = each.value["subnet_cidr"]
  vpc_id                  = aws_vpc.vpc.id
  map_public_ip_on_launch = true
  availability_zone       = each.value["availability_zone"]
  tags                    = merge(merge(var.tags, var.public_subnet_tags), lookup(each.value, "tags", {}))
}

resource "aws_subnet" "private_subnet" {
  count = var.create_nat_gateway ? 1 : 0

  cidr_block              = var.private_subnet_cidr
  vpc_id                  = aws_vpc.vpc.id
  map_public_ip_on_launch = false
  availability_zone       = var.private_subnet_availability_zone
  tags                    = merge(var.tags, var.private_subnet_tags)
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id

  tags = merge(var.tags, {
    Name = "${var.network_name}-igw"
  })
}

data "aws_route_table" "main" {
  filter {
    name   = "association.main"
    values = [true]
  }
  vpc_id = aws_vpc.vpc.id
}

resource "aws_route_table" "public_route" {
  vpc_id = aws_vpc.vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  route {
    ipv6_cidr_block = "::/0"
    gateway_id      = aws_internet_gateway.igw.id
  }

  tags = merge(var.tags, {
    Name                  = "${var.network_name}-vpc-public-rt"
    "radixdlt:managed_by" = "terraform"
  })
}


resource "aws_route" "main" {
  count = var.create_nat_gateway ? 1 : 0

  route_table_id         = data.aws_route_table.main.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.gw[0].id
}

resource "aws_route_table_association" "public_subnet_association" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_route.id
}

resource "aws_route_table_association" "additional_public_subnet_association" {
  for_each       = aws_subnet.additional_public_subnet
  subnet_id      = each.value.id
  route_table_id = aws_route_table.public_route.id
}

# Centralized field mapping for tag transformations
module "field_mapping" {
  source = "../tag-field-mapping"
}

# Transform snake_case vars to AWS tags
locals {
  validator_tags = {
    for key, val in var.public_validator_instances :
    key => merge(
      { Name = key },
      { for field in module.field_mapping.fields :
        module.field_mapping.tag_mapping[field] => lookup(val, field, null)
      }
    )
  }

  fullnode_tags = {
    for key, val in var.public_fullnode_instances :
    key => merge(
      { Name = key },
      { for field in module.field_mapping.fields :
        module.field_mapping.tag_mapping[field] => lookup(val, field, null)
      }
    )
  }

  bootstrap_tags = {
    for key, val in var.public_bootstrap_instances :
    key => merge(
      { Name = key },
      { for field in module.field_mapping.fields :
        module.field_mapping.tag_mapping[field] => lookup(val, field, null)
      }
    )
  }

  spam_tags = {
    for key, val in var.public_spam_instances :
    key => merge(
      { Name = key },
      { for field in module.field_mapping.fields :
        module.field_mapping.tag_mapping[field] => lookup(val, field, null)
      }
    )
  }
}

resource "aws_eip" "public_validator_instances" {
  for_each   = local.validator_tags
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(merge(var.tags, each.value), { Name = "${var.network_name}_${each.key}" })
}

resource "aws_eip" "public_fullnode_instances" {
  for_each   = local.fullnode_tags
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(merge(var.tags, each.value), { Name = "${var.network_name}_${each.key}" })
}

resource "aws_eip" "public_witnessnode_instances" {
  for_each   = var.public_witnessnode_instances
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(var.tags, { Name = "${var.network_name}-${each.key}" })
}

resource "aws_eip" "nat_eip" {
  count = var.create_nat_gateway ? 1 : 0

  depends_on = [aws_internet_gateway.igw]
  tags       = var.tags
}

resource "aws_nat_gateway" "gw" {
  count = var.create_nat_gateway ? 1 : 0

  allocation_id = aws_eip.nat_eip[0].id
  subnet_id     = aws_subnet.public_subnet.id

  tags = merge(var.tags, { Name = "${var.network_name}-${data.aws_region.current.name}-nat" })
}

resource "aws_flow_log" "vpc-flow-log" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.vpc-flow-logs[0].arn
  log_destination = aws_cloudwatch_log_group.vpc-flow-logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.vpc.id
  tags            = merge(var.tags, var.vpc_tags)
}

resource "aws_cloudwatch_log_group" "vpc-flow-logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name = "${aws_vpc.vpc.id}-flow-logs-cw-log-group"
}

resource "aws_iam_role" "vpc-flow-logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name = "${aws_vpc.vpc.id}-vpc-flow-logs-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Principal": {
        "Service": "vpc-flow-logs.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy" "vpc-flow-logs" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  name = "${aws_vpc.vpc.id}-vpc-flow-logs-role-policy"
  role = aws_iam_role.vpc-flow-logs[0].id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}


####################################################################
# CASSANDRA NODES RESOURCES
####################################################################

resource "aws_eip" "public_bootstrap_instances" {
  for_each   = local.bootstrap_tags
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(merge(var.tags, each.value), { Name = "${var.network_name}_${each.key}" })
}

resource "aws_eip" "public_spam_instances" {
  for_each   = local.spam_tags
  depends_on = [aws_internet_gateway.igw]
  tags       = merge(merge(var.tags, each.value), { Name = "${var.network_name}_${each.key}" })
}