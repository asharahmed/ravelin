# --- CI/CD deploy identity ----------------------------------------------------
# The Birmingham (university) tenant disables Microsoft Entra app registrations,
# so an Azure DevOps ARM service connection cannot use the default "app
# registration (automatic)" path. Instead the service connection uses
# "Managed identity" with workload identity federation: ADO creates a federated
# identity credential ON this managed identity (an ARM operation under the
# subscription we own — no directory/Graph privileges required).
#
# This identity is SEPARATE from the app's runtime pull identity
# (azurerm_user_assigned_identity.app, AcrPull-only). The CI identity needs
# push + deploy rights, which we deliberately keep off the running container.
resource "azurerm_user_assigned_identity" "cicd" {
  name                = "id-${local.name_prefix}-cicd"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  tags                = local.tags
}

# Push images to ACR (the pipeline's Image stage publishes here).
resource "azurerm_role_assignment" "cicd_acr_push" {
  scope                = azurerm_container_registry.main.id
  role_definition_name = "AcrPush"
  principal_id         = azurerm_user_assigned_identity.cicd.principal_id
}

# Update the Container App image (the pipeline's Deploy stage). Contributor on the
# resource group is the smallest built-in role that covers `az containerapp update`.
resource "azurerm_role_assignment" "cicd_rg_contributor" {
  scope                = azurerm_resource_group.main.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.cicd.principal_id
}
