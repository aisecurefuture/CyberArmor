# ============================================================
# CyberArmor — AI Router Service Terraform Module
# Unified AI provider gateway with encrypted credential vault
# ============================================================

terraform {
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
  }
}

variable "namespace"        { type = string; default = "cyberarmor" }
variable "image_repository" { type = string; default = "ghcr.io/cyberarmor-ai/ai-router" }
variable "image_tag"        { type = string; default = "2.0.0" }
variable "replicas"         { type = number; default = 2 }
variable "db_url"           { type = string; sensitive = true }
variable "fernet_key"       { type = string; sensitive = true;
                              description = "Fernet symmetric key for encrypting stored provider API keys" }
variable "agent_identity_url" { type = string; description = "Internal URL of the agent-identity service" }
variable "policy_url"         { type = string; description = "Internal URL of the policy service" }
variable "audit_url"          { type = string; description = "Internal URL of the audit service" }
variable "port"             { type = number; default = 8009 }
variable "resources" {
  type = object({ requests = object({ cpu = string; memory = string }); limits = object({ cpu = string; memory = string }) })
  default = { requests = { cpu = "500m"; memory = "512Mi" }; limits = { cpu = "2"; memory = "1Gi" } }
}
variable "hpa_enabled"      { type = bool;   default = true  }
variable "hpa_min_replicas" { type = number; default = 2     }
variable "hpa_max_replicas" { type = number; default = 20    }
variable "extra_env"        { type = map(string); default = {} }
variable "labels"           { type = map(string); default = {} }

resource "kubernetes_secret" "ai_router" {
  metadata {
    name      = "ai-router-secrets"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/component" = "ai-router" }, var.labels)
  }
  data = {
    DATABASE_URL        = var.db_url
    AI_ROUTER_FERNET_KEY = var.fernet_key
  }
}

resource "kubernetes_deployment" "ai_router" {
  metadata {
    name      = "ai-router"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/name" = "ai-router", "app.kubernetes.io/component" = "ai-router" }, var.labels)
  }

  spec {
    replicas = var.replicas
    selector { match_labels = { "app.kubernetes.io/name" = "ai-router" } }

    template {
      metadata {
        labels = merge({ "app.kubernetes.io/name" = "ai-router" }, var.labels)
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = tostring(var.port)
          "prometheus.io/path"   = "/metrics"
        }
      }

      spec {
        security_context { run_as_non_root = true; run_as_user = 1000; fs_group = 1000 }

        container {
          name  = "ai-router"
          image = "${var.image_repository}:${var.image_tag}"
          port { container_port = var.port }
          resources { requests = var.resources.requests; limits = var.resources.limits }

          env_from { secret_ref { name = kubernetes_secret.ai_router.metadata[0].name } }

          dynamic "env" {
            for_each = merge({
              PORT                 = tostring(var.port)
              AGENT_IDENTITY_URL   = var.agent_identity_url
              POLICY_SERVICE_URL   = var.policy_url
              AUDIT_SERVICE_URL    = var.audit_url
            }, var.extra_env)
            content { name = env.key; value = env.value }
          }

          liveness_probe  { http_get { path = "/health"; port = var.port }; initial_delay_seconds = 15; period_seconds = 10 }
          readiness_probe { http_get { path = "/ready";  port = var.port }; initial_delay_seconds = 5;  period_seconds = 5  }
        }
      }
    }
  }
}

resource "kubernetes_service" "ai_router" {
  metadata { name = "ai-router"; namespace = var.namespace; labels = merge({ "app.kubernetes.io/component" = "ai-router" }, var.labels) }
  spec {
    selector = { "app.kubernetes.io/name" = "ai-router" }
    port { name = "http"; port = var.port; target_port = var.port; protocol = "TCP" }
    type = "ClusterIP"
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "ai_router" {
  count = var.hpa_enabled ? 1 : 0
  metadata { name = "ai-router"; namespace = var.namespace }
  spec {
    scale_target_ref { api_version = "apps/v1"; kind = "Deployment"; name = kubernetes_deployment.ai_router.metadata[0].name }
    min_replicas = var.hpa_min_replicas
    max_replicas = var.hpa_max_replicas
    metric { type = "Resource"; resource { name = "cpu"; target { type = "Utilization"; average_utilization = 60 } } }
    metric { type = "Resource"; resource { name = "memory"; target { type = "Utilization"; average_utilization = 75 } } }
  }
}

output "service_name"         { value = kubernetes_service.ai_router.metadata[0].name }
output "service_port"         { value = var.port }
output "cluster_internal_url" { value = "http://ai-router.${var.namespace}.svc.cluster.local:${var.port}" }
