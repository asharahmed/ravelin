# Infrastructure

Terraform that provisions Ravelin's Azure resources, plus the remote-state bootstrap.

## What gets created (`infra/terraform`)
- Resource group
- Log Analytics workspace (Container Apps logs and metrics)
- Azure Container Registry (Basic, admin disabled — pulls use managed identity)
- User-assigned managed identity + AcrPull role assignment (credential-less image pull)
- Container Apps environment and a Container App (external HTTPS ingress on `8080`,
  `/health` probes, scale-to-zero)
- Azure SQL Database (serverless `GP_S_Gen5_1`, auto-pause after 60 min idle) and its server
- A separate CI/CD managed identity (AcrPush + Contributor) for the pipeline, kept distinct
  from the app's pull-only runtime identity

The Container App is created with a placeholder image; the CI/CD pipeline pushes the real
image to ACR and updates the running revision, so Terraform ignores image changes thereafter
(`lifecycle.ignore_changes`).

## One-time setup
```bash
az login
az account set --subscription "<subscription-id>"   # if multiple

# 1) Create the remote-state storage account
./scripts/bootstrap-tfstate.sh

# 2) Configure the backend + vars
cd infra/terraform
cp backend.hcl.example backend.hcl          # paste values printed by the bootstrap script
cp terraform.tfvars.example terraform.tfvars # adjust region/scale if desired

# 3) Init + apply
terraform init -backend-config=backend.hcl
terraform plan
terraform apply
```

`terraform output app_url` prints the live URL once deployed.

## Validate without Azure (no login needed)
```bash
cd infra/terraform
terraform fmt -check
terraform init -backend=false
terraform validate
```

## Notes
- `backend.hcl`, `terraform.tfvars`, and `*.tfstate` are gitignored.
- Region defaults to `canadacentral`; override via `terraform.tfvars` or the `location` var.
