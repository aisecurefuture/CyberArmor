# ============================================================
# CyberArmor — Agent Identity Service Terraform Module
# Deploys the AI agent identity microservice to Kubernetes
# ============================================================

terraform {
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
    helm       = { source = "hashicorp/helm",       version = "~> 2.11" }
  }
}

# ────────────────────────────────────────────────────────────
# Variables
# ────────────────────────────────────────────────────────────
variable "namespace"        { type = string; default = "cyberarmor" }
variable "image_repository" { type = string; default = "ghcr.io/cyberarmor-ai/agent-identity" }
variable "image_tag"        { type = string; default = "2.0.0" }
variable "replicas"         { type = number; default = 2 }
variable "db_url"           { type = string; sensitive = true }
variable "redis_url"        { type = string; sensitive = true }
variable "jwt_secret"       { type = string; sensitive = true }
variable "hmac_secret"      { type = string; sensitive = true }
variable "port"             { type = number; default = 8008 }
variable "resources" {
  type = object({
    requests = object({ cpu = string; memory = string })
    limits   = object({ cpu = string; memory = string })
  })
  default = {
    requests = { cpu = "250m"; memory = "512Mi" }
    limits   = { cpu = "1";    memory = "1Gi"   }
  }
}
variable "hpa_enabled"         { type = bool;   default = true }
variable "hpa_min_replicas"    { type = number; default = 2    }
variable "hpa_max_replicas"    { type = number; default = 10   }
variable "spiffe_enabled"      { type = bool;   default = false }
variable "spiffe_trust_domain" { type = string; default = "cyberarmor.ai" }
variable "extra_env"           { type = map(string); default = {} }
variable "labels"              { type = map(string); default = {} }

# ────────────────────────────────────────────────────────────
# Kubernetes Secret
# ────────────────────────────────────────────────────────────
resource "kubernetes_secret" "agent_identity" {
  metadata {
    name      = "agent-identity-secrets"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/component" = "agent-identity" }, var.labels)
  }
  data = {
    DATABASE_URL                 = var.db_url
    REDIS_URL                    = var.redis_url
    AGENT_IDENTITY_JWT_SECRET    = var.jwt_secret
    AGENT_IDENTITY_HMAC_SECRET   = var.hmac_secret
  }
}

# ────────────────────────────────────────────────────────────
# Deployment
# ────────────────────────────────────────────────────────────
resource "kubernetes_deployment" "agent_identity" {
  metadata {
    name      = "agent-identity"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/name" = "agent-identity", "app.kubernetes.io/component" = "agent-identity" }, var.labels)
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = { "app.kubernetes.io/name" = "agent-identity" }
    }

    template {
      metadata {
        labels = merge({ "app.kubernetes.io/name" = "agent-identity" }, var.labels)
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = tostring(var.port)
          "prometheus.io/path"   = "/metrics"
        }
      }

      spec {
        security_context {
          run_as_non_root = true
          run_as_user     = 1000
          fs_group        = 1000
        }

        container {
          name  = "agent-identity"
          image = "${var.image_repository}:${var.image_tag}"

          port { container_port = var.port; protocol = "TCP" }

          resources {
            requests = var.resources.requests
            limits   = var.resources.limits
          }

          env_from {
            secret_ref { name = kubernetes_secret.agent_identity.metadata[0].name }
          }

          dynamic "env" {
            for_each = merge({
              PORT                      = tostring(var.port)
              SPIFFE_ENABLED            = tostring(var.spiffe_enabled)
              SPIFFE_TRUST_DOMAIN       = var.spiffe_trust_domain
            }, var.extra_env)
            content {
              name  = env.key
              value = env.value
            }
          }

          liveness_probe {
            http_get { path = "/health"; port = var.port }
            initial_delay_seconds = 15
            period_seconds        = 10
            failure_threshold     = 3
          }

          readiness_probe {
            http_get { path = "/ready"; port = var.port }
            initial_delay_seconds = 5
            period_seconds        = 5
            failure_threshold     = 3
          }
        }
      }
    }
  }
}

# ────────────────────────────────────────────────────────────
# Service
# ────────────────────────────────────────────────────────────
resource "kubernetes_service" "agent_identity" {
  metadata {
    name      = "agent-identity"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/component" = "agent-identity" }, var.labels)
  }
  spec {
    selector = { "app.kubernetes.io/name" = "agent-identity" }
    port {
      name        = "http"
      port        = var.port
      target_port = var.port
      protocol    = "TCP"
    }
    type = "ClusterIP"
  }
}

# ────────────────────────────────────────────────────────────
# HPA (optional)
# ────────────────────────────────────────────────────────────
resource "kubernetes_horizontal_pod_autoscaler_v2" "agent_identity" {
  count = var.hpa_enabled ? 1 : 0

  metadata {
    name      = "agent-identity"
    namespace = var.namespace
  }

  spec {
    scale_target_ref {
      api_version = "apps/v1"
      kind        = "Deployment"
      name        = kubernetes_deployment.agent_identity.metadata[0].name
    }

    min_replicas = var.hpa_min_replicas
    max_replicas = var.hpa_max_replicas

    metric {
      type = "Resource"
      resource {
        name = "cpu"
        target { type = "Utilization"; average_utilization = 70 }
      }
    }
    metric {
      type = "Resource"
      resource {
        name = "memory"
        target { type = "Utilization"; average_utilization = 80 }
      }
    }
  }
}

# ────────────────────────────────────────────────────────────
# Outputs
# ────────────────────────────────────────────────────────────
output "service_name"       { value = kubernetes_service.agent_identity.metadata[0].name }
output "service_port"       { value = var.port }
output "cluster_internal_url" {
  value = "http://${kubernetes_service.agent_identity.metadata[0].name}.${var.namespace}.svc.cluster.local:${var.port}"
}
