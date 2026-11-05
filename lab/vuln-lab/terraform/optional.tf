############################################################
# RDS (enable_rds=false by default): public, unencrypted, old engine
############################################################
resource "random_password" "rds" {
  count   = var.enable_rds ? 1 : 0
  length  = 24
  special = false
}

resource "aws_db_subnet_group" "lab" {
  count      = var.enable_rds ? 1 : 0
  name       = "roqy-lab-db"
  subnet_ids = aws_subnet.public[*].id
}

resource "aws_security_group" "rds" {
  count       = var.enable_rds ? 1 : 0
  name        = "roqy-lab-rds"
  description = "PLANT rds-public-unencrypted-old (world-open only when allow_public)"
  vpc_id      = aws_vpc.lab.id
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = var.allow_public ? ["0.0.0.0/0"] : [aws_vpc.lab.cidr_block]
  }
}

resource "aws_db_instance" "old_public" {
  count                      = var.enable_rds ? 1 : 0
  identifier                 = "roqy-lab-legacy-db"
  engine                     = "postgres"
  engine_version             = var.rds_engine_version
  instance_class             = "db.t4g.micro"
  allocated_storage          = 20
  storage_encrypted          = false
  publicly_accessible        = true
  username                   = "roqyadmin"
  password                   = random_password.rds[0].result
  db_subnet_group_name       = aws_db_subnet_group.lab[0].name
  vpc_security_group_ids     = [aws_security_group.rds[0].id]
  backup_retention_period    = 0
  skip_final_snapshot        = true
  deletion_protection        = false
  apply_immediately          = true
  auto_minor_version_upgrade = false
  tags                       = { "roqy-plant" = "rds-public-unencrypted-old" }
}

############################################################
# EKS (enable_eks=false by default): public endpoint, CONFIG_MAP auth, creator admin, old version
############################################################
resource "aws_iam_role" "eks" {
  count = var.enable_eks ? 1 : 0
  name  = "roqy-lab-eks-cluster"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
      Action    = ["sts:AssumeRole", "sts:TagSession"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks" {
  count      = var.enable_eks ? 1 : 0
  role       = aws_iam_role.eks[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_eks_cluster" "public" {
  count    = var.enable_eks ? 1 : 0
  name     = "roqy-lab-eks"
  version  = var.eks_version
  role_arn = aws_iam_role.eks[0].arn

  vpc_config {
    subnet_ids              = aws_subnet.public[*].id
    endpoint_public_access  = true
    endpoint_private_access = false
    public_access_cidrs     = ["0.0.0.0/0"]
  }

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = true
  }

  tags       = { "roqy-plant" = "eks-public-endpoint eks-creator-admin eks-old-version" }
  depends_on = [aws_iam_role_policy_attachment.eks]
}

# Broad admin mapping: an IAM principal that is NOT an operator gets cluster-admin on the whole cluster.
# Mapped principal = roqy-lab-intern (the privesc user, which has NO credentials) so it is not
# reachable from outside. Never map the GitHub-OIDC role here: the deny-all boundary does not
# stop EKS authentication (it only needs sts:GetCallerIdentity).
resource "aws_eks_access_entry" "broad_admin" {
  count         = var.enable_eks ? 1 : 0
  cluster_name  = aws_eks_cluster.public[0].name
  principal_arn = aws_iam_user.privesc.arn
  type          = "STANDARD"
  tags          = { "roqy-plant" = "eks-broad-access-entry" }
}

resource "aws_eks_access_policy_association" "broad_admin" {
  count         = var.enable_eks ? 1 : 0
  cluster_name  = aws_eks_cluster.public[0].name
  principal_arn = aws_iam_user.privesc.arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope {
    type = "cluster"
  }
  depends_on = [aws_eks_access_entry.broad_admin]
}

resource "aws_iam_role" "eks_node" {
  count = var.enable_eks ? 1 : 0
  name  = "roqy-lab-eks-node"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  for_each = var.enable_eks ? toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
  ]) : toset([])
  role       = aws_iam_role.eks_node[0].name
  policy_arn = each.value
}

# One small node in a PUBLIC subnet (no NAT gateway). Nodes get public IPv4s via map_public_ip_on_launch.
resource "aws_eks_node_group" "one" {
  count           = var.enable_eks ? 1 : 0
  cluster_name    = aws_eks_cluster.public[0].name
  node_group_name = "roqy-lab-ng"
  node_role_arn   = aws_iam_role.eks_node[0].arn
  subnet_ids      = aws_subnet.public[*].id
  ami_type        = "AL2023_ARM_64_STANDARD"
  instance_types  = [var.eks_node_instance_type]
  capacity_type   = "ON_DEMAND"
  disk_size       = 20

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 1
  }

  tags       = { "roqy-plant" = "infra" }
  depends_on = [aws_iam_role_policy_attachment.eks_node]
}
