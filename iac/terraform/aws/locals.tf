locals {
  ebs_block_device = []
  default_root_block_device = [
    {
      volume_type = "gp3"
      volume_size = "20"
  }]
  default_addon_block_device = [
    {
      delete_on_termination = false
      device_name           = "/dev/xvdf"
      encrypted             = true
      volume_type           = "gp3"
      volume_size           = "1"
      volume_name           = "data"
      nvm_devicename        = "/dev/nvme1n1"
  }]
  first_external_device_info = {
    physical_volume_name = "/dev/sdf"
    config = {
      encrypted   = "true"
      volume_size = "150"
      volume_type = "gp3"
    }
    nvm_devicename = "/dev/nvme1n1"
    volume_name    = "data"
  }

  casandra_key = {
    public_key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCTPdva65LNnQdFDZ9Jiez9a9fN1Ot66dVFzJaVt+ycd2Zju30cV4dNR6PZ2DzqgxyaUqZSdzHriJw/fRWZcok1w97GwUQ8P2UZguM9PUgfoXMVTkk6RMBrMw+nEu2tQKpL6SuKSDShdL3Q+kgVYGxP7ISsqKwX9UXB4TKfrjfrCILN7Hd4Q12qoR81rmeTW2YKQPly9wRUmPJQOM7EjPcMg737suWbNXeus7iWFDN9QUUBM9sqhg10h18wTu6hQMgqWYgQ4YAAneXFENb7NP0lu7DSj7IdPZ8Z6QspbaU/A1zIniWPO5gN9wGokqLF0nwAerhj/ZsSrz70gVfOOqD4oya+/y+1YS9QPEPkXBK2EM16Bhb/Lm4TB7xFO80WXwRgrfHPcrWhEbsk71q44aqcRBxRxr2EZrtFwhUk3YR1Xfp3nuJc83SE5kYRaNwry/kmFVGb0SvXpURDcp7mdBsu6HyBkHBabVChwvWrHKz5vvigSLghHTzayS/eCBUwAo9b1uQRogIkEPOh/WgXTbPIRrsRt1sF3QjRzoFU/sovBHT1iqbm0UvuZUwijG/7YIHwGTA5+mD7qRqtCvd5x8qYfbVgFN/pJfZhmhcs+hT1vw2O/ImpgKt04PRj0TsYkOu5Nmx64ps2alJLikGU9ufbkKShzA3zgOTkdP8z5LA3pQ== devops-team-hetzner"
  }

  ami_filter_prefix = "RadixDLT-hyperscalers-v1*"

  create_ireland_nodes   = true
  create_frankfurt_nodes = false
  create_mumbai_nodes    = false
  create_us_east_nodes   = false
  create_us_west_nodes   = false

  network = "hyperscalerstpstest"

  additional_ssh_keys = [
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDuuloDA0XJ3u7ElzVDo5d2KJLDMxDkX91QUPgE8JOfyPc4F7Yx6bZaW7PQn9oiK5C7IEBU8BE01uhcjgGFFZzubQUzOWZdU9IRcom9kvb93XArlMCZ55rjMjcjs4fssGYfvKqyVv4abaZXxnWIGl9R6ehCNbxHhx36GSpt9HLZXoR1FaANwd1YnYhF+PbCbE8oLbvbPnI7F1KHw0ZLSglkWn9cu+xMOLWnzxTZoLfQgcFhH1tBJR9KgRE5ShhRhAuFgB8oEdGT+cQruRJIpBR6sfJlZig6KGf0cLHVvvDGvetNL5Y0ZZhtRhKiSyXF9cAaRDoFBOxOgZ36EQRIZVBYowRiKgDuGoSQeAy0Y9JXa6g2GTt8n0fFYAiMWfHn5XZS+VJ51Uq1zMqGC/Ru2zyQAkIvuIVzl75Z7v1vSSwsh2WMWHc0wV5rUfc6/FRSDYeoDna5OFZ5e8NN7PTA7uTkGSXoE+3pE0DLPvIGS4k7XEJ0PzIy2mjiYR857YRK6uiWJ63qrpuKsexT7czwMRA7THMT0i7y+wiQ4fsB6hBB0nar6TT4tAzbHJT9GEspYqg6gPKHyO6ZluMTkx5CzAAsPJk/4uTZoBFWa5rfprWs2xU8mHSGHT7i8hzb84w4m0eNZfrE7mxNqJf/FcJgtGyNZNF85c9p437c5KG4qLou1Q== shambu@users-MBP",
  ]
}

data "aws_iam_instance_profile" "role_testnets_ec2_iam_profile" {
  name     = "role_testnets_ec2_iam_profile"
  provider = aws.us-east-1
}
