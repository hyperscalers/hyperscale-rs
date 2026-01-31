# Centralized tag field mapping module
# This module provides a single source of truth for field names and their
# corresponding AWS tag mappings (snake_case <-> radixdlt:* format)

locals {
  # List of all supported fields
  fields = [
    "core_private_ip",
    "enable_health",
    "enable_metrics",
    "enable_validation",
    "enable_version",
    "enable_jmx_exporter",
    "extra_archive",
    "dns_subdomain",
    "explicit_instance_type",
    "explicit_ami",
    "genesis_validator",
    "migration_aux_node",
    "access_type",
    "collect_metrics",
    "collect_logs",
  ]

  # Mapping from snake_case field names to AWS radixdlt:* tag names
  tag_mapping = {
    core_private_ip        = "radixdlt:core-private-ip"
    enable_health          = "radixdlt:enable-health-api"
    enable_metrics         = "radixdlt:enable-metrics-api"
    enable_validation      = "radixdlt:enable-validation-api"
    enable_version         = "radixdlt:enable-version-api"
    enable_jmx_exporter    = "radixdlt:enable-jmx-exporter"
    extra_archive          = "radixdlt:extra-archive"
    dns_subdomain          = "radixdlt:dns-subdomain"
    explicit_instance_type = "radixdlt:explicit-instance-type"
    explicit_ami           = "radixdlt:explicit-ami"
    genesis_validator      = "radixdlt:genesis-validator"
    migration_aux_node     = "radixdlt:migration-aux-node"
    access_type            = "radixdlt:access-type"
    collect_metrics        = "radixdlt:collect-metrics"
    collect_logs           = "radixdlt:collect-logs"
  }

  # Reverse mapping from AWS tag names to snake_case field names
  reverse_tag_mapping = { for k, v in local.tag_mapping : v => k }
}

output "fields" {
  description = "List of all supported field names in snake_case format"
  value       = local.fields
}

output "tag_mapping" {
  description = "Mapping from snake_case field names to AWS radixdlt:* tag names"
  value       = local.tag_mapping
}

output "reverse_tag_mapping" {
  description = "Mapping from AWS radixdlt:* tag names to snake_case field names"
  value       = local.reverse_tag_mapping
}
