variable "COMMON_INSTANCE_TYPE" {
  default = "t3a.micro" #"c6i.2xlarge"
}

variable "SPAM_INSTANCE_TYPE" {
  default = ""
}

variable "network_name" {
  default = "cassandra_test"
}
variable "running_or_stopped" {
  default = "running"
}

#####################################
# IRELAND NODES
#####################################

variable "eu_west_1_bootstrap_nodes" {
  default = 0
}

variable "eu_west_1_spam_nodes" {
  default = 0
}

variable "eu_west_1_validator_nodes" {
  default = 0
}

#####################################
# FRANKFURT NODES
#####################################

variable "eu_central_1_bootstrap_nodes" {
  default = 0
}

variable "eu_central_1_spam_nodes" {
  default = 0
}

variable "eu_central_1_validator_nodes" {
  default = 0
}

#####################################
# MUMBAI NODES
#####################################

variable "ap_south_1_bootstrap_nodes" {
  default = 0
}

variable "ap_south_1_spam_nodes" {
  default = 0
}

variable "ap_south_1_validator_nodes" {
  default = 0
}

#####################################
# NORTH VIRGINIA NODES
#####################################

variable "us_east_1_bootstrap_nodes" {
  default = 0
}

variable "us_east_1_spam_nodes" {
  default = 0
}

variable "us_east_1_validator_nodes" {
  default = 0
}

#####################################
# NORTH CALIFORNIA NODES
#####################################

variable "us_west_1_bootstrap_nodes" {
  default = 0
}

variable "us_west_1_spam_nodes" {
  default = 0
}

variable "us_west_1_validator_nodes" {
  default = 0
}