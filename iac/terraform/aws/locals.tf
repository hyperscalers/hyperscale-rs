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
}

data "aws_iam_instance_profile" "role_testnets_ec2_iam_profile" {
  name     = "role_testnets_ec2_iam_profile"
  provider = aws.us-east-1
}
