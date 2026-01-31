#!/bin/bash

# List all Elastic IPs across specified AWS regions (comma-separated)

REGIONS="ap-south-1 eu-central-1 eu-west-1 us-east-1 us-west-1"

all_ips=""
for region in $REGIONS; do
  ips=$(aws ec2 describe-addresses --region "$region" --query 'Addresses[*].PublicIp' --output text 2>/dev/null)
  if [ -n "$ips" ]; then
    all_ips="$all_ips $ips"
  fi
done

# Convert spaces to commas and trim
echo "$all_ips" | xargs | tr ' ' ','
