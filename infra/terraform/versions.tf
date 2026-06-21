terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # Remote state in Azure Storage. The backing storage account/container are created
  # once by scripts/bootstrap-tfstate.sh, then `terraform init -backend-config=backend.hcl`
  # supplies the values. Kept empty here so secrets/names stay out of version control.
  backend "azurerm" {}
}
