variable "eks_cluster_name" {
  type        = string
  description = "Name of the EKS cluster to deploy into"
  default     = "cyberarmor-prod"
}

variable "image_tag" {
  type        = string
  description = "Docker image tag to deploy for all CyberArmor services"
  default     = "2.0.0"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}
