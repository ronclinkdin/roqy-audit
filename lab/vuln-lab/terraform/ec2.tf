data "aws_ssm_parameter" "al2023_arm" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64"
}

############################################################
# SG plants (always created, free)
############################################################
resource "aws_security_group" "open_admin" {
  name        = "roqy-lab-legacy-admin"
  description = "PLANT sg-open-admin-ports + sg-all-traffic"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "roqy-lab-legacy-admin", "roqy-plant" = "sg-open-admin-ports sg-all-traffic" }
}

locals {
  admin_ports = { ssh = 22, rdp = 3389, redis = 6379, elasticsearch = 9200 }
}

resource "aws_vpc_security_group_ingress_rule" "admin_v4" {
  for_each          = local.admin_ports
  security_group_id = aws_security_group.open_admin.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
  description       = "PLANT ${each.key} open to the world"
}

resource "aws_vpc_security_group_ingress_rule" "admin_v6" {
  for_each          = local.admin_ports
  security_group_id = aws_security_group.open_admin.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "tcp"
  from_port         = each.value
  to_port           = each.value
  description       = "PLANT ${each.key} open to the world (IPv6)"
}

resource "aws_vpc_security_group_ingress_rule" "all_traffic" {
  security_group_id = aws_security_group.open_admin.id
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
  description       = "PLANT all traffic from anywhere"
}

# IPv6-ONLY open SG: catches the W2 CidrIp-vs-CidrIpv6 query bug.
resource "aws_security_group" "ipv6_only" {
  name        = "roqy-lab-ipv6-bastion"
  description = "PLANT sg-ipv6-open (IPv6 only, no IPv4 rule)"
  vpc_id      = aws_vpc.lab.id
  tags        = { Name = "roqy-lab-ipv6-bastion", "roqy-plant" = "sg-ipv6-open" }
}

resource "aws_vpc_security_group_ingress_rule" "ipv6_ssh" {
  security_group_id = aws_security_group.ipv6_only.id
  cidr_ipv6         = "::/0"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  description       = "PLANT ssh from any IPv6"
}

############################################################
# c2  IMDSv1 launch template + optional instance; c14 user-data with fake secret
############################################################
resource "aws_launch_template" "imdsv1" {
  name          = "roqy-lab-imdsv1"
  image_id      = data.aws_ssm_parameter.al2023_arm.value
  instance_type = "t4g.nano"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional" # IMDSv1 allowed
    http_put_response_hop_limit = 2          # reachable from containers on the host
  }

  iam_instance_profile {
    name = aws_iam_instance_profile.wildcard_admin.name
  }

  vpc_security_group_ids = [aws_security_group.open_admin.id]

  user_data = base64encode(<<-EOT
    #!/bin/bash
    # PLANT ec2-userdata-secret (FAKE values)
    export DB_PASSWORD='${local.fake.db_pass}'
    export STRIPE_SECRET_KEY='${local.fake.stripe}'
    echo "roqy lab instance - does nothing"
  EOT
  )

  tag_specifications {
    resource_type = "instance"
    tags          = { Name = "roqy-lab-imdsv1", "roqy-lab" = "true", "roqy-plant" = "ec2-imdsv1-instance" }
  }

  tags = { "roqy-plant" = "ec2-imdsv1-launch-template ec2-userdata-secret" }
}

resource "aws_instance" "imdsv1" {
  count     = var.instance_state == "none" ? 0 : 1
  subnet_id = aws_subnet.public[0].id
  launch_template {
    id      = aws_launch_template.imdsv1.id
    version = "$Latest"
  }
  root_block_device {
    volume_size = 8
    encrypted   = false
  }
  tags = { Name = "roqy-lab-imdsv1", "roqy-plant" = "ec2-imdsv1-instance sg-open-admin-ports" }
}

resource "aws_ec2_instance_state" "imdsv1" {
  count       = var.instance_state == "none" ? 0 : 1
  instance_id = aws_instance.imdsv1[0].id
  state       = var.instance_state
}

############################################################
# c5  Unencrypted EBS snapshot, optional public / cross-account share, AMI
############################################################
resource "aws_ebs_volume" "plain" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = false
  tags              = { Name = "roqy-lab-db-backup-vol", "roqy-plant" = "ebs-unencrypted-snapshot" }
}

resource "aws_ebs_snapshot" "plain" {
  volume_id   = aws_ebs_volume.plain.id
  description = "roqy-lab prod-db-backup (empty 1GiB volume, FAKE)"
  tags        = { Name = "roqy-lab-prod-db-backup", "roqy-plant" = "ebs-unencrypted-snapshot ebs-snapshot-public ebs-snapshot-shared-foreign" }
}

resource "aws_snapshot_create_volume_permission" "foreign" {
  count       = local.has_foreign ? 1 : 0
  snapshot_id = aws_ebs_snapshot.plain.id
  account_id  = var.foreign_account_id
}

# Public share: CLI because provider resource only accepts account IDs. Reverted on destroy.
resource "terraform_data" "snapshot_public" {
  count = var.allow_public ? 1 : 0
  input = {
    snapshot = aws_ebs_snapshot.plain.id
    region   = var.region
    profile  = var.aws_profile
  }
  provisioner "local-exec" {
    command = "aws ec2 modify-snapshot-attribute --snapshot-id ${self.input.snapshot} --attribute createVolumePermission --operation-type add --group-names all --region ${self.input.region} --profile ${self.input.profile}"
  }
  provisioner "local-exec" {
    when       = destroy
    on_failure = continue
    command    = "aws ec2 modify-snapshot-attribute --snapshot-id ${self.input.snapshot} --attribute createVolumePermission --operation-type remove --group-names all --region ${self.input.region} --profile ${self.input.profile}"
  }
}

resource "aws_ami" "from_snapshot" {
  name                = "roqy-lab-golden-image-${local.sfx}"
  virtualization_type = "hvm"
  root_device_name    = "/dev/xvda"
  architecture        = "arm64"
  ena_support         = true
  ebs_block_device {
    device_name = "/dev/xvda"
    snapshot_id = aws_ebs_snapshot.plain.id
    volume_size = 1
  }
  tags = { "roqy-plant" = "ami-public" }
}

resource "aws_ami_launch_permission" "public" {
  count    = var.allow_public ? 1 : 0
  image_id = aws_ami.from_snapshot.id
  group    = "all"
}

# Absence plants: EBS encryption-by-default OFF, snapshot/image Block Public Access OFF,
# Allowed AMIs OFF, instance metadata account defaults unset. This lab never enables them.
