variable "vpc_tags" {
  default = {}
}

variable "node_tags" {
  default = {}
}

variable "vpc_cidr" {
  type = string
}

variable "region" {
  type = string
}

variable "primary_availability_zone" {
  type = string
}

// "10.0.1.0/24"
variable "public_subnet_cidr" {
  type = string
}

//"10.0.2.0/24"
variable "private_subnet_cidr" {
  type = string
}

########################################
# NODE VARIABLES
########################################

variable "COMMON_AMI" {
  type = string
}

variable "COMMON_INSTANCE_TYPE" {
  type = string
}

variable "bootstrap" {
}

variable "BOOTSTRAP_AMI" {
  default = ""
  type    = string
}

variable "BOOTSTRAP_INSTANCE_TYPE" {
  default = ""
  type    = string
}

variable "spam" {
}

variable "SPAM_AMI" {
  default = ""
  type    = string
}

variable "SPAM_INSTANCE_TYPE" {
  default = ""
  type    = string
}

variable "validator" {
}

variable "VALIDATOR_AMI" {
  default = ""
  type    = string
}

variable "VALIDATOR_INSTANCE_TYPE" {
  default = ""
  type    = string
}

variable "network" {
  type = string
}


variable "root_block_device" {
  description = "Customize details about the root block device of the instance"
  type        = list(map(string))

}

variable "first_external_device_info" {
}

variable "ebs_block_devices" {
  type    = map(map(any))
  default = {}
}

variable "key_pair" {
  default = null
}

variable "ipv4_cidr_blocks" {
  default = []
}

variable "ipv6_cidr_blocks" {
  default = []
}
variable "ec2_instance_profile" {
  default = ""
}

variable "create_nat_gateway" {
  type    = bool
  default = false
}

variable "core_node_var_volume_detach_instance_stop" {
  default = false
}

variable "enable_vpc_flow_logs" {
  default     = false
  type        = bool
  description = "Control enabling/disabling vpc flow logs"
}

variable "running_or_stopped" {
  default = "running"
  type    = string
}

variable "ec2_tenancy" {
  default = "dedicated"
}

variable "additional_ssh_keys" {
  description = "List of additional SSH public keys to add to instances"
  type        = list(string)
  default     = []
}