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

# Update the Container App image (the pipeline's Deploy stage). A custom role scoped to the one
# Container App — least privilege — instead of Contributor on the whole resource group (which
# could also delete the SQL DB, read storage keys, or tear down the app/Key Vault).
resource "azurerm_role_definition" "cicd_containerapp_deploy" {
  name        = "Ravelin CI Container App Deploy (${local.name_prefix})"
  scope       = azurerm_container_app.main.id
  description = "Least-privilege: read/update the Ravelin Container App and its revisions only."

  permissions {
    actions = [
      "Microsoft.App/containerApps/read",
      "Microsoft.App/containerApps/write",
      "Microsoft.App/containerApps/revisions/read",
      "Microsoft.App/containerApps/revisions/*/action",
    ]
    not_actions = []
  }

  assignable_scopes = [azurerm_container_app.main.id]
}

resource "azurerm_role_assignment" "cicd_containerapp_deploy" {
  scope              = azurerm_container_app.main.id
  role_definition_id = azurerm_role_definition.cicd_containerapp_deploy.role_definition_resource_id
  principal_id       = azurerm_user_assigned_identity.cicd.principal_id
}
