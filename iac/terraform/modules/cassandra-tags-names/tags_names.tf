# Creates tag maps for bootstrap, spam, and validator nodes
# Uses centralized field mapping for consistency

variable "bootstrap_nodes" {
  default = {}
}

variable "spam_nodes" {
  default = {}
}

variable "validator_nodes" {
  default = {}
}

variable "region" {
}

module "field_mapping" {
  source = "../tag-field-mapping"
}

locals {
  # Helper function to extract node tags from nested config
  # Flattens the nested structure and creates a map keyed by tag name
  BOOTSTRAP_TAGS = {
    for item in flatten([
      for bootstrap, node_types in var.bootstrap_nodes :
      flatten([
        for node_type, nodes in node_types :
        flatten([
          for node, values in nodes : {
            tag    = "${replace(var.region, "-", "_")}_${node_type}${bootstrap}"
            values = values
        }
      ])
      if node_type == "bootstrap"
    ])
    ]) :
    item.tag => { for field in module.field_mapping.fields : field => lookup(item.values, field, null) }
  }

  SPAM_TAGS = {
    for item in flatten([
      for spam, node_types in var.spam_nodes :
      flatten([
        for node_type, nodes in node_types :
        flatten([
          for node, values in nodes : {
            tag    = "${replace(var.region, "-", "_")}_${node_type}${spam}"
            values = values
        }
      ])
      if node_type == "spam"
    ])
    ]) :
    item.tag => { for field in module.field_mapping.fields : field => lookup(item.values, field, null) }
  }

  VALIDATOR_TAGS = {
    for item in flatten([
      for validator, node_types in var.validator_nodes :
      flatten([
        for node_type, nodes in node_types :
        flatten([
          for node, values in nodes : {
            tag    = "${replace(var.region, "-", "_")}_${node_type}${validator}"
            values = values
        }
      ])
      if node_type == "validator"
    ])
    ]) :
    item.tag => { for field in module.field_mapping.fields : field => lookup(item.values, field, null) }
  }
}

output "BOOTSTRAP_TAGS" {
  value = local.BOOTSTRAP_TAGS
}

output "SPAM_TAGS" {
  value = local.SPAM_TAGS
}

output "VALIDATOR_TAGS" {
  value = local.VALIDATOR_TAGS
}
