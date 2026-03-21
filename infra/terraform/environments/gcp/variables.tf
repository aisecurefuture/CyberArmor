variable "project_id" {
  type        = string
  description = "Google Cloud project ID for deployment"
}

variable "region" {
  type        = string
  description = "GCP region for provider operations"
  default     = "us-central1"
}

variable "location" {
  type        = string
  description = "GKE cluster location (zone or region)"
  default     = "us-central1"
}

variable "gke_cluster_name" {
  type        = string
  description = "Name of the GKE cluster"
}

variable "namespace" {
  type        = string
  description = "Kubernetes namespace to deploy CyberArmor into"
  default     = "cyberarmor"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to deploy for all CyberArmor services"
  default     = "2.0.0"
}

variable "database_url" {
  type        = string
  description = "Shared database DSN"
  sensitive   = true
}

variable "redis_url" {
  type        = string
  description = "Redis connection URL"
  sensitive   = true
}

variable "jwt_secret" {
  type        = string
  description = "Agent identity JWT secret"
  sensitive   = true
}

variable "hmac_secret" {
  type        = string
  description = "Audit signature HMAC secret"
  sensitive   = true
}

variable "fernet_key" {
  type        = string
  description = "Router credential encryption key"
  sensitive   = true
}

variable "policy_url" {
  type        = string
  description = "Internal URL for policy service"
  default     = "http://policy.cyberarmor.svc.cluster.local:8001"
}
