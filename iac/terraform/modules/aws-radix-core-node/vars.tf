variable "nodes" {
  description = "Map variable containing bootnodes and corresponding details"
  //  type        = map(string)
  default = {}
}

variable "node_tags" {
  description = "Tags for radix core node instances"
  type        = map(string)
  default     = {}
}

variable "ami" {

}
variable "availability_zone" {
}

variable "radix_network_name" {
  default = "testnet"
}

variable "instance_type" {
  default = "t2.medium"
}

variable "user_data" {
  description = "The user data to provide when launching the instance. Do not pass gzip-compressed data via this argument; see user_data_base64 instead."
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "The VPC Subnet ID to launch in"
  type        = string
}

variable "key_name" {
  description = "The key name to use for the instance"
  type        = string
}

variable "vpc_security_group_ids" {
  description = "A list of security group IDs to associate with"
  type        = list(string)
}

variable "root_block_device" {
  description = "Customize details about the root block device of the instance. See Block Devices below for details"
  type        = list(map(string))
  default     = []
}

variable "ebs_block_device" {
  description = "Additional EBS block devices to attach to the instance"
  type        = list(map(string))
  default     = []
}

variable "iam_instance_profile" {
  description = "The IAM Instance Profile to launch the instance with. Specified as the name of the Instance Profile."
  type        = string
  default     = ""
}

variable "cpu_credits" {
  description = "The credit option for CPU usage (unlimited or standard)"
  type        = string
  default     = "unlimited"
}

variable "associate_eip" {
  default = false
}

variable "volume_detach_instance_stop" {
  default = false
}

variable "private_ip" {
  default = null
}

variable "ebs_block_devices" {
  type    = map(map(any))
  default = {}
}

variable "running_or_stopped" {
  type    = string
  default = "running"
}

variable "ec2_tenancy" {
  type    = string
  default = "dedicated"
}