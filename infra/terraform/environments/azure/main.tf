terraform {
  required_version = ">= 1.6.0"
  required_providers {
    azurerm    = { source = "hashicorp/azurerm", version = "~> 3.0" }
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm", version = "~> 2.11" }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

data "azurerm_kubernetes_cluster" "main" {
  name                = var.aks_cluster_name
  resource_group_name = var.resource_group_name
}

provider "kubernetes" {
  host                   = data.azurerm_kubernetes_cluster.main.kube_config[0].host
  client_certificate     = base64decode(data.azurerm_kubernetes_cluster.main.kube_config[0].client_certificate)
  client_key             = base64decode(data.azurerm_kubernetes_cluster.main.kube_config[0].client_key)
  cluster_ca_certificate = base64decode(data.azurerm_kubernetes_cluster.main.kube_config[0].cluster_ca_certificate)
}

resource "kubernetes_namespace" "cyberarmor" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
      "environment"                  = "prod"
      "cloud"                        = "azure"
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
  labels           = { environment = "prod", cloud = "azure" }
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
  labels           = { environment = "prod", cloud = "azure" }
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
  labels             = { environment = "prod", cloud = "azure" }
}

output "agent_identity_url" { value = module.agent_identity.cluster_internal_url }
output "ai_router_url" { value = module.ai_router.cluster_internal_url }
output "audit_url" { value = module.audit.cluster_internal_url }
