output "resource_group_name" {
  description = "Resource group containing all Ravelin resources."
  value       = azurerm_resource_group.main.name
}

output "acr_login_server" {
  description = "ACR login server (e.g. acrravelindev123.azurecr.io) — push target for the pipeline."
  value       = azurerm_container_registry.main.login_server
}

output "acr_name" {
  description = "ACR name — used by `az acr` / pipeline tasks."
  value       = azurerm_container_registry.main.name
}

output "container_app_name" {
  description = "Container App name — `az containerapp update` target for deployments."
  value       = azurerm_container_app.main.name
}

output "app_url" {
  description = "Public HTTPS URL of the deployed app."
  value       = "https://${azurerm_container_app.main.ingress[0].fqdn}"
}

output "key_vault_name" {
  description = "Key Vault holding the app's secrets."
  value       = azurerm_key_vault.main.name
}

output "key_vault_uri" {
  description = "Key Vault data-plane URI."
  value       = azurerm_key_vault.main.vault_uri
}

output "sql_server_fqdn" {
  description = "Azure SQL server FQDN."
  value       = azurerm_mssql_server.main.fully_qualified_domain_name
}

output "sql_database_name" {
  description = "Azure SQL database name."
  value       = azurerm_mssql_database.main.name
}

output "sql_connection_string" {
  description = "ADO.NET connection string for the database (used to run migrations locally)."
  value       = local.sql_connection_string
  sensitive   = true
}

output "cicd_identity_name" {
  description = "CI/CD managed identity name — pick this when creating the ADO 'Managed identity' service connection."
  value       = azurerm_user_assigned_identity.cicd.name
}

output "cicd_identity_client_id" {
  description = "CI/CD managed identity client (application) ID — for reference / manual federated-credential fallback."
  value       = azurerm_user_assigned_identity.cicd.client_id
}

output "cicd_identity_principal_id" {
  description = "CI/CD managed identity principal (object) ID."
  value       = azurerm_user_assigned_identity.cicd.principal_id
}

output "admin_email" {
  description = "Seeded Admin login email."
  value       = var.seed_admin_email
}

output "admin_password" {
  description = "Seeded Admin login password."
  value       = random_password.admin.result
  sensitive   = true
}

output "demo_email" {
  description = "Seeded read-only demo (Viewer) login email."
  value       = var.seed_demo_email
}

output "demo_password" {
  description = "Seeded read-only demo (Viewer) login password."
  value       = random_password.demo.result
  sensitive   = true
}
