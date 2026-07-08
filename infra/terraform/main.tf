locals {
  # Suffix keeps globally-unique names (ACR) collision-free.
  name_prefix = "${var.project}-${var.environment}"
  tags        = merge(var.tags, { environment = var.environment })
}

resource "random_string" "suffix" {
  length  = 6
  upper   = false
  special = false
}

# JWT signing key (HMAC-SHA256) for user auth tokens.
resource "random_password" "jwt_signing" {
  length  = 64
  special = false
}

# Seeded user passwords (meet Identity complexity: upper/lower/digit/special).
resource "random_password" "admin" {
  length           = 20
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = "!#%-_=+"
}

resource "random_password" "demo" {
  length           = 20
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
  override_special = "!#%-_=+"
}

resource "azurerm_resource_group" "main" {
  name     = "rg-${local.name_prefix}"
  location = var.location
  tags     = local.tags
}

# --- Observability ------------------------------------------------------------
resource "azurerm_log_analytics_workspace" "main" {
  name                = "log-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "PerGB2018"
  retention_in_days   = 30
  tags                = local.tags
}

# --- Container registry -------------------------------------------------------
# Admin user disabled: images are pulled via managed identity (no static creds).
resource "azurerm_container_registry" "main" {
  name                = "acr${var.project}${var.environment}${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  sku                 = "Basic"
  admin_enabled       = false
  tags                = local.tags
}

# --- Managed identity for credential-less ACR pulls ---------------------------
resource "azurerm_user_assigned_identity" "app" {
  name                = "id-${local.name_prefix}"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = local.tags
}

resource "azurerm_role_assignment" "acr_pull" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPull"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# --- Container Apps environment + app -----------------------------------------
resource "azurerm_container_app_environment" "main" {
  name                       = "cae-${local.name_prefix}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
  tags                       = local.tags
}

resource "azurerm_container_app" "main" {
  name                         = "ca-${local.name_prefix}"
  container_app_environment_id = azurerm_container_app_environment.main.id
  resource_group_name          = azurerm_resource_group.main.name
  revision_mode                = "Single"
  tags                         = local.tags

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.app.id]
  }

  registry {
    server   = azurerm_container_registry.main.login_server
    identity = azurerm_user_assigned_identity.app.id
  }

  # Secrets are sourced from Key Vault and fetched at runtime via the app's managed
  # identity — no secret values are embedded in this Container App definition (or its
  # Terraform state) any more. versionless_id lets rotated secret versions flow through
  # on the Container App's periodic Key Vault sync. See keyvault.tf.
  secret {
    name                = "db-connection"
    key_vault_secret_id = azurerm_key_vault_secret.db_connection.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }

  secret {
    name                = "jwt-signing-key"
    key_vault_secret_id = azurerm_key_vault_secret.jwt_signing_key.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }

  secret {
    name                = "seed-admin-password"
    key_vault_secret_id = azurerm_key_vault_secret.seed_admin_password.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }

  secret {
    name                = "seed-demo-password"
    key_vault_secret_id = azurerm_key_vault_secret.seed_demo_password.versionless_id
    identity            = azurerm_user_assigned_identity.app.id
  }

  # Shared secret the scheduled re-evaluation cron Job presents to /api/internal/reevaluate.
  secret {
    name  = "reeval-token"
    value = random_password.reeval.result
  }

  ingress {
    external_enabled = true
    target_port      = var.target_port
    transport        = "auto"

    traffic_weight {
      latest_revision = true
      percentage      = 100
    }
  }

  template {
    min_replicas = var.min_replicas
    max_replicas = var.max_replicas

    container {
      name   = var.project
      image  = var.container_image
      cpu    = var.container_cpu
      memory = var.container_memory

      env {
        name        = "ConnectionStrings__RavelinDb"
        secret_name = "db-connection"
      }

      env {
        name        = "Jwt__SigningKey"
        secret_name = "jwt-signing-key"
      }
      env {
        name  = "Jwt__Issuer"
        value = "ravelin"
      }
      env {
        name  = "Jwt__Audience"
        value = "ravelin"
      }
      env {
        name  = "Seed__AdminEmail"
        value = var.seed_admin_email
      }
      env {
        name        = "Seed__AdminPassword"
        secret_name = "seed-admin-password"
      }
      env {
        name  = "Seed__DemoEmail"
        value = var.seed_demo_email
      }
      env {
        name        = "Seed__DemoPassword"
        secret_name = "seed-demo-password"
      }

      # Seed realistic demo data for the public showcase (idempotent; skips existing projects).
      env {
        name  = "Seed__DemoData"
        value = "true"
      }

      # Public demo: allow self-service signup (read-only Viewer). Defaults to Disabled otherwise.
      # Demo projects are seeded public, so a new Viewer immediately sees the showcase data.
      env {
        name  = "Registration__Mode"
        value = "Open"
      }

      env {
        name        = "Reeval__Token"
        secret_name = "reeval-token"
      }

      # Exploitation-intelligence enrichment: pull CISA KEV + FIRST EPSS and drive the
      # risk-adjusted SLA (actively-exploited findings get a tighter deadline). Uses only public
      # feeds (no secret); the hourly re-evaluation refreshes it. Inert unless Enabled=true.
      env {
        name  = "VulnIntel__Enabled"
        value = "true"
      }

      # DataProtection key persistence — blob read via the app's managed identity.
      env {
        name  = "DataProtection__BlobUri"
        value = "https://${azurerm_storage_account.dp.name}.blob.core.windows.net/${azurerm_storage_container.dp.name}/keys.xml"
      }
      env {
        name  = "DataProtection__IdentityClientId"
        value = azurerm_user_assigned_identity.app.client_id
      }

      liveness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = var.target_port
      }

      readiness_probe {
        transport = "HTTP"
        path      = "/health"
        port      = var.target_port
      }
    }
  }

  # The CI/CD pipeline updates the running image out-of-band; don't let Terraform
  # revert it back to the placeholder on subsequent applies.
  lifecycle {
    ignore_changes = [template[0].container[0].image]
  }

  depends_on = [
    azurerm_role_assignment.acr_pull,
    # The app identity must be able to read Key Vault secrets before this revision starts.
    azurerm_role_assignment.app_kv_secrets_user,
  ]
}
