variable "vpc_cidr" {}
variable "public_subnet_cidr" {}
variable "private_subnet_cidr" {}
variable "additional_public_subnets" {
  default = {}
}

variable "tenacy" {
  default = "default"
}

variable "tags" {
  description = "A map of tags to add to all resources"
  type        = map(string)
  default     = {}
}
variable "public_validator_instances" {}
variable "public_fullnode_instances" {
  default = {}
}

variable "public_witnessnode_instances" {
  default = {}
}

variable "enable_dns_support" {
  default = "true"
}
variable "enable_dns_hostnames" {
  default = "true"
}

variable "igw_tags" {
  description = "Additional tags for the internet gateway"
  type        = map(string)
  default     = {}
}



variable "public_subnet_availability_zone" {
  type = string
}
variable "private_subnet_availability_zone" {
  type = string
}
variable "public_subnet_tags" {}
variable "private_subnet_tags" {}
variable "vpc_tags" {}

variable "create_nat_gateway" {
  type    = bool
  default = true
}

variable "enable_vpc_flow_logs" {
  default     = false
  type        = bool
  description = "Control enabling/disabling vpc flow logs"
}

variable "network_name" {
  type = string
}

########################################
# CASSANDRA VARIABLES
########################################

variable "public_bootstrap_instances" {
  default = {}
}

variable "public_spam_instances" {
  default = {}
}
