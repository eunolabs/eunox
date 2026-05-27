# ---------------------------------------------------------------------------
# Eunox compute module — EKS cluster, Fargate profile, IRSA OIDC provider
# ---------------------------------------------------------------------------

locals {
  common_tags = merge(var.tags, { environment = var.environment })
}

# ── IAM role for EKS control plane ───────────────────────────────────────────

data "aws_iam_policy_document" "eks_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_cluster" {
  name               = "${var.name_prefix}-eks-cluster-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.eks_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_cluster" {
  for_each = toset([
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
  ])
  role       = aws_iam_role.eks_cluster.name
  policy_arn = each.value
}

# ── EKS cluster ───────────────────────────────────────────────────────────────

resource "aws_eks_cluster" "main" {
  name     = var.cluster_name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = concat(var.public_subnet_ids, var.private_subnet_ids)
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.eks_cluster]
}

# ── OIDC provider (IRSA) ─────────────────────────────────────────────────────

data "tls_certificate" "eks_oidc" {
  url = aws_eks_cluster.main.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_oidc.certificates[0].sha1_fingerprint]
  url             = aws_eks_cluster.main.identity[0].oidc[0].issuer
  tags            = local.common_tags
}

# ── EKS managed node group (optional — skip for Fargate-only deployments) ─────

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "eks_node" {
  count              = var.use_fargate ? 0 : 1
  name               = "${var.name_prefix}-eks-node-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "eks_node" {
  for_each = var.use_fargate ? toset([]) : toset([
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
    "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy",
  ])
  role       = aws_iam_role.eks_node[0].name
  policy_arn = each.value
}

resource "aws_eks_node_group" "system" {
  count           = var.use_fargate ? 0 : 1
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "system"
  node_role_arn   = aws_iam_role.eks_node[0].arn
  subnet_ids      = var.private_subnet_ids
  instance_types  = [var.node_instance_type]

  scaling_config {
    desired_size = var.node_desired_size
    max_size     = var.node_max_size
    min_size     = var.node_desired_size
  }

  update_config {
    max_unavailable = 1
  }

  tags       = local.common_tags
  depends_on = [aws_iam_role_policy_attachment.eks_node]
}

# ── Fargate profile for eunox-system namespace ─────────────────────────────────

data "aws_iam_policy_document" "fargate_assume" {
  count = var.use_fargate ? 1 : 0
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["eks-fargate-pods.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "fargate_pod" {
  count              = var.use_fargate ? 1 : 0
  name               = "${var.name_prefix}-fargate-pod-role-${var.environment}"
  assume_role_policy = data.aws_iam_policy_document.fargate_assume[0].json
  tags               = local.common_tags
}

resource "aws_iam_role_policy_attachment" "fargate_pod" {
  count      = var.use_fargate ? 1 : 0
  role       = aws_iam_role.fargate_pod[0].name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"
}

resource "aws_eks_fargate_profile" "eunox_system" {
  count                  = var.use_fargate ? 1 : 0
  cluster_name           = aws_eks_cluster.main.name
  fargate_profile_name   = "eunox-system"
  pod_execution_role_arn = aws_iam_role.fargate_pod[0].arn
  subnet_ids             = var.private_subnet_ids

  selector {
    namespace = "eunox-system"
  }

  selector {
    namespace = "eunox-monitoring"
  }

  tags = local.common_tags

  depends_on = [aws_iam_role_policy_attachment.fargate_pod]
}
