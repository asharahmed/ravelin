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
