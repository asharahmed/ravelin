variable "project" {
  description = "Short project name used as a prefix for resource names (lowercase alphanumeric)."
  type        = string
  default     = "ravelin"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,11}$", var.project))
    error_message = "project must be 3-12 chars, lowercase letters/digits, starting with a letter."
  }
}

variable "environment" {
  description = "Deployment environment name (e.g. dev, prod)."
  type        = string
  default     = "dev"
}

variable "location" {
  description = "Azure region for all resources."
  type        = string
  default     = "canadacentral"
}

variable "container_image" {
  description = "Initial container image. A public placeholder is used on first apply; the CI/CD pipeline updates the running revision to the ACR-hosted Ravelin image."
  type        = string
  default     = "mcr.microsoft.com/k8se/quickstart:latest"
}

variable "container_cpu" {
  description = "vCPU allocated to the app container."
  type        = number
  default     = 0.25
}

variable "container_memory" {
  description = "Memory allocated to the app container (must pair validly with CPU)."
  type        = string
  default     = "0.5Gi"
}

variable "target_port" {
  description = "Port the container listens on (matches ASPNETCORE_HTTP_PORTS in the Dockerfile)."
  type        = number
  default     = 8080
}

variable "min_replicas" {
  description = "Minimum replicas. 0 enables scale-to-zero (cost saving; cold start on first request)."
  type        = number
  default     = 0
}

variable "max_replicas" {
  description = "Maximum replicas."
  type        = number
  default     = 1
}

variable "sql_admin_login" {
  description = "Azure SQL administrator login name."
  type        = string
  default     = "ravelinadmin"
}

variable "seed_admin_email" {
  description = "Email for the seeded Admin user."
  type        = string
  default     = "admin@ravelin.local"
}

variable "seed_demo_email" {
  description = "Email for the seeded read-only Viewer (demo) user."
  type        = string
  default     = "demo@ravelin.local"
}

variable "client_ip_address" {
  description = "Optional public IP allowed through the SQL firewall (for running migrations from a workstation). Empty disables the rule."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    project   = "ravelin"
    managedBy = "terraform"
  }
}
