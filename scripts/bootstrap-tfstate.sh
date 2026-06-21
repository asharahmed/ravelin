#!/usr/bin/env bash
# Bootstraps the Azure Storage backend that holds Terraform remote state.
# Run ONCE per environment, after `az login`. Idempotent: safe to re-run.
#
# Usage:
#   az login
#   az account set --subscription "<your-subscription-id>"   # if you have more than one
#   ./scripts/bootstrap-tfstate.sh
#
# Override defaults via env vars, e.g.:
#   LOCATION=eastus PROJECT=ravelin ENVIRONMENT=dev ./scripts/bootstrap-tfstate.sh
set -euo pipefail

PROJECT="${PROJECT:-ravelin}"
ENVIRONMENT="${ENVIRONMENT:-dev}"
LOCATION="${LOCATION:-canadacentral}"

RG="rg-${PROJECT}-tfstate"
CONTAINER="tfstate"
# Storage account names: 3-24 chars, lowercase alphanumeric, globally unique.
# Derive a stable name from the subscription id so re-runs reuse the same account.
SUB_ID="$(az account show --query id -o tsv)"
SUFFIX="$(echo -n "$SUB_ID" | shasum | cut -c1-8)"
SA="st${PROJECT}tf${SUFFIX}"

echo "Subscription : $SUB_ID"
echo "Resource grp : $RG"
echo "Storage acct : $SA"
echo "Container    : $CONTAINER"
echo "Location     : $LOCATION"
echo

az group create --name "$RG" --location "$LOCATION" --output none

az storage account create \
  --name "$SA" --resource-group "$RG" --location "$LOCATION" \
  --sku Standard_LRS --kind StorageV2 \
  --min-tls-version TLS1_2 \
  --allow-blob-public-access false \
  --output none

# Create the state container using the account key (retrieved via your az session).
# Terraform's azurerm backend likewise retrieves this key automatically from your
# az login, so no data-plane role assignment / propagation wait is needed.
KEY="$(az storage account keys list --account-name "$SA" --resource-group "$RG" --query "[0].value" -o tsv)"
az storage container create \
  --name "$CONTAINER" --account-name "$SA" \
  --account-key "$KEY" --output none

echo "Done. Use these values in infra/terraform/backend.hcl:"
echo
echo "  resource_group_name  = \"$RG\""
echo "  storage_account_name = \"$SA\""
echo "  container_name       = \"$CONTAINER\""
echo "  key                  = \"${ENVIRONMENT}.terraform.tfstate\""
echo
echo "Then: cd infra/terraform && terraform init -backend-config=backend.hcl"
