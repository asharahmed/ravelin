# --- DataProtection key-ring persistence --------------------------------------------------
# ASP.NET Core DataProtection keys (antiforgery + password-reset tokens) are persisted to an
# encrypted blob, read at runtime via the app's user-assigned managed identity — so the keys
# survive restarts/redeploys instead of regenerating in-memory each boot (which would
# invalidate antiforgery tokens and outstanding reset tokens).

resource "azurerm_storage_account" "dp" {
  name                            = "stdp${var.project}${var.environment}${random_string.suffix.result}"
  resource_group_name             = azurerm_resource_group.main.name
  location                        = azurerm_resource_group.main.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  tags                            = local.tags
}

resource "azurerm_storage_container" "dp" {
  name                  = "dataprotection"
  storage_account_id    = azurerm_storage_account.dp.id
  container_access_type = "private"
}

# The app's managed identity may read/write the key blob.
resource "azurerm_role_assignment" "app_dp_blob" {
  scope                = azurerm_storage_account.dp.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.app.principal_id
}
