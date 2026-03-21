terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google     = { source = "hashicorp/google", version = "~> 5.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm", version = "~> 2.11" }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

data "google_container_cluster" "main" {
  name     = var.gke_cluster_name
  location = var.location
}

data "google_client_config" "default" {}

provider "kubernetes" {
  host                   = "https://${data.google_container_cluster.main.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(data.google_container_cluster.main.master_auth[0].cluster_ca_certificate)
}

resource "kubernetes_namespace" "cyberarmor" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "environment"                  = "prod"
      "cloud"                        = "gcp"
    }
  }
}

module "agent_identity" {
  source = "../../modules/agent-identity"

  namespace        = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag        = var.image_tag
  replicas         = 3
  db_url           = var.database_url
  redis_url        = var.redis_url
  jwt_secret       = var.jwt_secret
  hmac_secret      = var.hmac_secret
  hpa_max_replicas = 15
  labels           = { environment = "prod", cloud = "gcp" }
}

module "audit" {
  source = "../../modules/audit"

  namespace        = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag        = var.image_tag
  replicas         = 3
  db_url           = var.database_url
  redis_url        = var.redis_url
  hmac_secret      = var.hmac_secret
  retention_days   = 365
  hpa_max_replicas = 12
  labels           = { environment = "prod", cloud = "gcp" }
}

module "ai_router" {
  source = "../../modules/ai-router"

  namespace          = kubernetes_namespace.cyberarmor.metadata[0].name
  image_tag          = var.image_tag
  replicas           = 3
  db_url             = var.database_url
  fernet_key         = var.fernet_key
  agent_identity_url = module.agent_identity.cluster_internal_url
  policy_url         = var.policy_url
  audit_url          = module.audit.cluster_internal_url
  hpa_max_replicas   = 30
  labels             = { environment = "prod", cloud = "gcp" }
}

output "agent_identity_url" { value = module.agent_identity.cluster_internal_url }
output "ai_router_url" { value = module.ai_router.cluster_internal_url }
output "audit_url" { value = module.audit.cluster_internal_url }
