# --- Azure Key Vault: central, audited secret store (Stage 8 hardening) --------
# Moves the app's secrets (DB connection, JWT signing key, seeded passwords) out of
# inline Container App secrets and into Key Vault. The Container App reads them at
# runtime through its user-assigned managed identity (RBAC role "Key Vault Secrets
# User"), so secret values are no longer embedded in the Container App resource.
#
# Permission model: Azure RBAC, not legacy access policies. Writing secrets is a
# data-plane action, and subscription Owner is control-plane only — so the deployer
# (the principal running `terraform apply`) is granted "Key Vault Secrets Officer".
#
# DELIBERATELY NOT here (higher risk, deferred): switching SQL auth from the admin
# login to the app's managed identity + a least-privilege contained DB user. That
# needs a T-SQL user-provisioning step and can lock the app out of the database if
# mis-ordered. The connection string is still secret-managed — now in Key Vault
# rather than inline — which is the bulk of the hardening with none of that risk.

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "main" {
  name                       = "kv-${local.name_prefix}-${random_string.suffix.result}"
  resource_group_name        = azurerm_resource_group.main.name
  location                   = azurerm_resource_group.main.location
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  rbac_authorization_enabled = true
  purge_protection_enabled   = false # dev: allow clean teardown/recreate
  soft_delete_retention_days = 7     # minimum retention
  tags                       = local.tags
}

# The app's managed identity may READ secrets (used by the Container App at runtime).
resource "azurerm_role_assignment" "app_kv_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}

# The Terraform deployer may WRITE secrets (data-plane; Owner alone can't, under RBAC).
resource "azurerm_role_assignment" "deployer_kv_officer" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets Officer"
  principal_id         = data.azurerm_client_config.current.object_id
}

# Azure RBAC is eventually consistent. Let the role assignments propagate before the
# data-plane secret writes (and the app's first read), otherwise they 403 intermittently.
resource "time_sleep" "kv_rbac_propagation" {
  depends_on = [
    azurerm_role_assignment.app_kv_secrets_user,
    azurerm_role_assignment.deployer_kv_officer,
  ]
  create_duration = "120s"
}

resource "azurerm_key_vault_secret" "db_connection" {
  name         = "db-connection"
  value        = local.sql_connection_string
  key_vault_id = azurerm_key_vault.main.id
  content_type = "ADO.NET connection string"
  tags         = local.tags
  depends_on   = [time_sleep.kv_rbac_propagation]
}

resource "azurerm_key_vault_secret" "jwt_signing_key" {
  name         = "jwt-signing-key"
  value        = random_password.jwt_signing.result
  key_vault_id = azurerm_key_vault.main.id
  tags         = local.tags
  depends_on   = [time_sleep.kv_rbac_propagation]
}

resource "azurerm_key_vault_secret" "seed_admin_password" {
  name         = "seed-admin-password"
  value        = random_password.admin.result
  key_vault_id = azurerm_key_vault.main.id
  tags         = local.tags
  depends_on   = [time_sleep.kv_rbac_propagation]
}

resource "azurerm_key_vault_secret" "seed_demo_password" {
  name         = "seed-demo-password"
  value        = random_password.demo.result
  key_vault_id = azurerm_key_vault.main.id
  tags         = local.tags
  depends_on   = [time_sleep.kv_rbac_propagation]
}
