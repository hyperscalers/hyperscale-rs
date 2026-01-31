data "aws_region" "current" {}

variable "ipv4_cidr_blocks" {
  description = "IPv4 CIDR blocks allowed for ingress"
  default     = ["0.0.0.0/0"]
}

variable "ipv6_cidr_blocks" {
  description = "IPv6 CIDR blocks allowed for ingress"
  default     = ["::/0"]
}

variable "devops_ipv4_cidr" {
  default = []
}

variable "devops_ipv6_cidr" {
  default = []
}

locals {
  ipv4_cidr_merged = concat(var.devops_ipv4_cidr, var.ipv4_cidr_blocks)
  ipv6_cidr_merged = concat(var.devops_ipv6_cidr, var.ipv6_cidr_blocks)
}
resource "aws_security_group" "allow-ssh-8080" {
  vpc_id      = aws_vpc.vpc.id
  name        = "${var.network_name}-${data.aws_region.current.name}-allow-ssh-8080"
  description = "security group that allows ssh and 8080 and all egress traffic"
  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = [
    "0.0.0.0/0"]
  }

  ingress {
    from_port        = 8080
    to_port          = 8080
    protocol         = "tcp"
    cidr_blocks      = local.ipv4_cidr_merged
    ipv6_cidr_blocks = local.ipv6_cidr_merged
  }

  tags = merge(var.tags, { Name = "${var.network_name}-${data.aws_region.current.name}-allow-ssh-8080" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "allow-gossip-port" {
  vpc_id      = aws_vpc.vpc.id
  name        = "${var.network_name}-${data.aws_region.current.name}-allow-gossip-port"
  description = "security group nodes to communicate with each other"

  ingress {
    from_port = 30000
    to_port   = 30000
    protocol  = "tcp"
    cidr_blocks = [
    "0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.network_name}-${data.aws_region.current.name}-allow-gossip-port" })

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "core_security_group" {
  vpc_id = aws_vpc.vpc.id
  name   = "${var.network_name}-${data.aws_region.current.name}-core-security-group"

  ingress {
    from_port = 8080
    protocol  = "tcp"
    to_port   = 8080
    cidr_blocks = [
    var.public_subnet_cidr]
  }
  ingress {

    from_port = -1
    protocol  = "icmp"
    to_port   = -1
    cidr_blocks = [
    var.public_subnet_cidr]
  }
  ingress {
    from_port = 22
    to_port   = 22
    protocol  = "tcp"
    cidr_blocks = [
    "0.0.0.0/0"]
  }

  tags = merge(var.tags, { Name = "${var.network_name}-${data.aws_region.current.name}-core-security-group" })

  lifecycle {
    create_before_destroy = true
  }
}