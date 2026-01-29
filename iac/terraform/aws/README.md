```sh
# ================= HOW TO PROVIDE NODE SPECIFIC CONFIG =================
# Nodes are separated in 3 groups: bootstrap, spam and validator. 
# We create them using 3 separate variables, all of which are per region.
# Following example is for Ireland region:
# eu_west_1_bootstrap_nodes = "10"
# eu_west_1_spam_nodes      = "10"
# eu_west_1_validator_nodes = "10"
# And their instance type is defined by: COMMON_INSTANCE_TYPE (ie all instances have same resources)
# Let's say we need to bootstrap node 4 to be of larger instance type and we want to collect 
# metrics and logs from it:

# eu-west-1.tf file locals {} section

eu_west_1_individual_bootstrap = {
  4 = {
    bootstrap = {
      "node" = {
        explicit_instance_type = "m6i.8xlarge"
        collect_metrics        = true
        collect_logs           = true
      }
    }
  }

}

# So terraform will see that it needs to create 10 instances but instance 4 has some specific/different config 
# and will override default one.
# Same goes for other nodes in same region and generally any node in any region.

# In locals.tf file we control which region to enable or disable. 
# Specifying 100 nodes in one region which is disabled won't do anything.

create_ireland_nodes   = true
create_frankfurt_nodes = false
create_mumbai_nodes    = false
create_us_east_nodes   = false
create_us_west_nodes   = false

# Since nodes have built-in dashboard when app is running we create Route53 records so it's easier to remember
# node name to access dashboard rather than remembering public IP that gets destroyed with node.
# Format is:

{network_name}-{region}-{node_type}{node_number}.sandbox.extratools.works

cassandra-test-eu-west-1-bootstrap0.sandbox.extratools.works
cassandra-test-ap-south-1-spam20.sandbox.extratools.works
cassandra-test-us-wast-1-validator39.sandbox.extratools.works ...
```