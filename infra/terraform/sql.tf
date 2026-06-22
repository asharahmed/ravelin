# Azure SQL — serverless, using the Azure SQL Database free offer (auto-pause to stay free).
# NOTE (remaining tech debt): the app still authenticates to SQL with the admin login. The
# connection string is now stored in Key Vault (see keyvault.tf) rather than inline, but the
# stronger step — the Container App's managed identity + a least-privilege contained DB user
# (no password at all) — is deferred: it needs a T-SQL user-provisioning step and risks
# locking the app out of the database if mis-sequenced.

resource "random_password" "sql" {
  length           = 24
  special          = true
  override_special = "!#%*-_=+"
  min_upper        = 2
  min_lower        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_mssql_server" "main" {
  name                          = "sql-${local.name_prefix}-${random_string.suffix.result}"
  resource_group_name           = azurerm_resource_group.main.name
  location                      = azurerm_resource_group.main.location
  version                       = "12.0"
  administrator_login           = var.sql_admin_login
  administrator_login_password  = random_password.sql.result
  minimum_tls_version           = "1.2"
  public_network_access_enabled = true
  tags                          = local.tags
}

resource "azurerm_mssql_database" "main" {
  name      = "sqldb-${var.project}-${var.environment}"
  server_id = azurerm_mssql_server.main.id

  # Serverless General Purpose, 1 vCore — auto-pauses when idle so cost is ~storage-only
  # while nobody is using the demo (cold start on first query, which is acceptable).
  # (The Azure SQL "free offer" isn't exposed by azurerm v4.78; this serverless config is
  #  the cost-equivalent fallback and stays cheap on the student credit.)
  sku_name                    = "GP_S_Gen5_1"
  min_capacity                = 0.5
  auto_pause_delay_in_minutes = 60
  max_size_gb                 = 32
  collation                   = "SQL_Latin1_General_CP1_CI_AS"
  storage_account_type        = "Local"
  zone_redundant              = false

  tags = local.tags
}

# Allow other Azure services (the Container App) to reach the server.
resource "azurerm_mssql_firewall_rule" "allow_azure" {
  name             = "AllowAzureServices"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = "0.0.0.0"
  end_ip_address   = "0.0.0.0"
}

# Optional: allow a specific client IP (for running migrations from a workstation).
resource "azurerm_mssql_firewall_rule" "client" {
  count            = var.client_ip_address == "" ? 0 : 1
  name             = "ClientMigrations"
  server_id        = azurerm_mssql_server.main.id
  start_ip_address = var.client_ip_address
  end_ip_address   = var.client_ip_address
}

locals {
  sql_connection_string = join("", [
    "Server=tcp:${azurerm_mssql_server.main.fully_qualified_domain_name},1433;",
    "Database=${azurerm_mssql_database.main.name};",
    "User ID=${var.sql_admin_login};",
    "Password=${random_password.sql.result};",
    "Encrypt=True;TrustServerCertificate=False;Connection Timeout=60;",
  ])
}
