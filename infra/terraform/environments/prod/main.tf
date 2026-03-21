# ============================================================
# CyberArmor — Production Environment
# Composes all AI Identity Control Plane services
# ============================================================

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm",       version = "~> 2.11" }
    aws        = { source = "hashicorp/aws",         version = "~> 5.0"  }
  }

  backend "s3" {
    bucket = "cyberarmor-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
    encrypt        = true
    dynamodb_table = "cyberarmor-tf-lock"
  }
}

# ────────────────────────────────────────────────────────────
# Data sources
# ────────────────────────────────────────────────────────────
data "aws_eks_cluster"      "main" { name = var.eks_cluster_name }
data "aws_eks_cluster_auth" "main" { name = var.eks_cluster_name }

provider "kubernetes" {
  host                   = data.aws_eks_cluster.main.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.main.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.main.token
}

# ────────────────────────────────────────────────────────────
# Namespace
# ────────────────────────────────────────────────────────────
resource "kubernetes_namespace" "cyberarmor" {
  metadata {
    name = "cyberarmor"
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "environment"                  = "prod"
    }
  }
}

# ────────────────────────────────────────────────────────────
# Secrets (from AWS SSM Parameter Store)
# ────────────────────────────────────────────────────────────
data "aws_ssm_parameter" "db_url"       { name = "/cyberarmor/prod/DATABASE_URL";         with_decryption = true }
data "aws_ssm_parameter" "redis_url"    { name = "/cyberarmor/prod/REDIS_URL";             with_decryption = true }
data "aws_ssm_parameter" "jwt_secret"   { name = "/cyberarmor/prod/JWT_SECRET";            with_decryption = true }
data "aws_ssm_parameter" "hmac_secret"  { name = "/cyberarmor/prod/HMAC_SECRET";           with_decryption = true }
data "aws_ssm_parameter" "fernet_key"   { name = "/cyberarmor/prod/AI_ROUTER_FERNET_KEY";  with_decryption = true }

# ────────────────────────────────────────────────────────────
# Module: Agent Identity Service
# ────────────────────────────────────────────────────────────
module "agent_identity" {
  source = "../../modules/agent-identity"

  namespace        = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag        = var.image_tag
  replicas         = 3
  db_url           = data.aws_ssm_parameter.db_url.value
  redis_url        = data.aws_ssm_parameter.redis_url.value
  jwt_secret       = data.aws_ssm_parameter.jwt_secret.value
  hmac_secret      = data.aws_ssm_parameter.hmac_secret.value
  hpa_max_replicas = 15
  labels           = { environment = "prod" }
}

# ────────────────────────────────────────────────────────────
# Module: AI Router
# ────────────────────────────────────────────────────────────
module "ai_router" {
  source = "../../modules/ai-router"

  namespace          = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag          = var.image_tag
  replicas           = 3
  db_url             = data.aws_ssm_parameter.db_url.value
  fernet_key         = data.aws_ssm_parameter.fernet_key.value
  agent_identity_url = module.agent_identity.cluster_internal_url
  policy_url         = "http://policy.${kubernetes_namespace.cyberarmor.metadata[0].name}.svc.cluster.local:8001"
  audit_url          = module.audit.cluster_internal_url
  hpa_max_replicas   = 30
  labels             = { environment = "prod" }
}

# ────────────────────────────────────────────────────────────
# Module: Audit Graph Service
# ────────────────────────────────────────────────────────────
module "audit" {
  source = "../../modules/audit"

  namespace        = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag        = var.image_tag
  replicas         = 3
  db_url           = data.aws_ssm_parameter.db_url.value
  redis_url        = data.aws_ssm_parameter.redis_url.value
  hmac_secret      = data.aws_ssm_parameter.hmac_secret.value
  retention_days   = 365
  hpa_max_replicas = 12
  labels           = { environment = "prod" }
}

# ────────────────────────────────────────────────────────────
# Outputs
# ────────────────────────────────────────────────────────────
output "agent_identity_url" { value = module.agent_identity.cluster_internal_url }
output "ai_router_url"      { value = module.ai_router.cluster_internal_url }
output "audit_url"          { value = module.audit.cluster_internal_url }
