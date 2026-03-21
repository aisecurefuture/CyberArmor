# ============================================================
# CyberArmor — Audit & Action Graph Service Terraform Module
# Immutable signed audit events + directed action graph
# ============================================================

terraform {
  required_providers {
    kubernetes = { source = "hashicorp/kubernetes", version = "~> 2.23" }
  }
}

variable "namespace"        { type = string; default = "cyberarmor" }
variable "image_repository" { type = string; default = "ghcr.io/cyberarmor-ai/audit" }
variable "image_tag"        { type = string; default = "2.0.0" }
variable "replicas"         { type = number; default = 2 }
variable "db_url"           { type = string; sensitive = true }
variable "redis_url"        { type = string; sensitive = true }
variable "hmac_secret"      { type = string; sensitive = true; description = "HMAC-SHA256 key for signing audit events" }
variable "port"             { type = number; default = 8011 }
variable "retention_days"   { type = number; default = 365 }
variable "resources" {
  type = object({ requests = object({ cpu = string; memory = string }); limits = object({ cpu = string; memory = string }) })
  default = { requests = { cpu = "250m"; memory = "512Mi" }; limits = { cpu = "1"; memory = "1Gi" } }
}
variable "hpa_enabled"      { type = bool;   default = true }
variable "hpa_min_replicas" { type = number; default = 2    }
variable "hpa_max_replicas" { type = number; default = 8    }
variable "export_enabled"   { type = bool;   default = true }
variable "extra_env"        { type = map(string); default = {} }
variable "labels"           { type = map(string); default = {} }

resource "kubernetes_secret" "audit" {
  metadata {
    name      = "audit-secrets"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/component" = "audit" }, var.labels)
  }
  data = {
    DATABASE_URL         = var.db_url
    REDIS_URL            = var.redis_url
    AUDIT_HMAC_SECRET    = var.hmac_secret
  }
}

resource "kubernetes_deployment" "audit" {
  metadata {
    name      = "audit"
    namespace = var.namespace
    labels    = merge({ "app.kubernetes.io/name" = "audit", "app.kubernetes.io/component" = "audit" }, var.labels)
  }

  spec {
    replicas = var.replicas
    selector { match_labels = { "app.kubernetes.io/name" = "audit" } }

    template {
      metadata {
        labels = merge({ "app.kubernetes.io/name" = "audit" }, var.labels)
        annotations = {
          "prometheus.io/scrape" = "true"
          "prometheus.io/port"   = tostring(var.port)
          "prometheus.io/path"   = "/metrics"
        }
      }

      spec {
        security_context { run_as_non_root = true; run_as_user = 1000; fs_group = 1000 }

        container {
          name  = "audit"
          image = "${var.image_repository}:${var.image_tag}"
          port { container_port = var.port }
          resources { requests = var.resources.requests; limits = var.resources.limits }

          env_from { secret_ref { name = kubernetes_secret.audit.metadata[0].name } }

          dynamic "env" {
            for_each = merge({
              PORT                 = tostring(var.port)
              AUDIT_RETENTION_DAYS = tostring(var.retention_days)
              AUDIT_EXPORT_ENABLED = tostring(var.export_enabled)
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

resource "kubernetes_service" "audit" {
  metadata { name = "audit"; namespace = var.namespace; labels = merge({ "app.kubernetes.io/component" = "audit" }, var.labels) }
  spec {
    selector = { "app.kubernetes.io/name" = "audit" }
    port { name = "http"; port = var.port; target_port = var.port; protocol = "TCP" }
    type = "ClusterIP"
  }
}

resource "kubernetes_horizontal_pod_autoscaler_v2" "audit" {
  count = var.hpa_enabled ? 1 : 0
  metadata { name = "audit"; namespace = var.namespace }
  spec {
    scale_target_ref { api_version = "apps/v1"; kind = "Deployment"; name = kubernetes_deployment.audit.metadata[0].name }
    min_replicas = var.hpa_min_replicas
    max_replicas = var.hpa_max_replicas
    metric { type = "Resource"; resource { name = "cpu"; target { type = "Utilization"; average_utilization = 70 } } }
    metric { type = "Resource"; resource { name = "memory"; target { type = "Utilization"; average_utilization = 80 } } }
  }
}

output "service_name"         { value = kubernetes_service.audit.metadata[0].name }
output "service_port"         { value = var.port }
output "cluster_internal_url" { value = "http://audit.${var.namespace}.svc.cluster.local:${var.port}" }
