#!/usr/bin/env bash
#
# Ravelin — manual, Docker-less deploy to Azure Container Apps.
#
# Mirrors azure-pipelines.yml exactly, for when the hosted pipeline is unavailable
# (e.g. the Microsoft-hosted parallelism grant is still pending). Builds an OCI image
# with the .NET SDK container tooling (Microsoft.NET.Build.Containers) — NO Docker
# daemon and NO `az acr build` (both are blocked on Azure for Students) — pushes it to
# ACR with a short-lived token, then points the Container App at the new tag.
#
# Usage:   scripts/deploy.sh <version-tag>        e.g.  scripts/deploy.sh 0.7.0
# Requires: az (logged in to the right subscription), .NET 10 SDK.

set -euo pipefail

TAG="${1:-}"
if [[ -z "$TAG" ]]; then
  echo "usage: scripts/deploy.sh <version-tag>   (e.g. 0.7.0)" >&2
  exit 1
fi

# --- Config (from `terraform output`; matches azure-pipelines.yml) --------------
ACR_NAME="acrravelindevs8066d"
ACR_LOGIN_SERVER="acrravelindevs8066d.azurecr.io"
RESOURCE_GROUP="rg-ravelin-dev"
CONTAINER_APP="ca-ravelin-dev"
IMAGE_REPO="ravelin"
BUILD_CONFIG="Release"
BASE_IMAGE="mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled-extra"
PROJECT="src/Ravelin/Ravelin.csproj"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Deploying ${IMAGE_REPO}:${TAG} to ${CONTAINER_APP} (rg ${RESOURCE_GROUP})"
az account show --query "{sub:name, state:state}" -o tsv >/dev/null

# --- 1. Build & test (fail fast before pushing anything) ------------------------
echo "==> Build & test"
dotnet build Ravelin.slnx -c "$BUILD_CONFIG" --nologo
dotnet test  Ravelin.slnx -c "$BUILD_CONFIG" --no-build --nologo

# --- 2. Build OCI image and push to ACR (no Docker daemon) ----------------------
echo "==> Acquiring short-lived ACR token"
TOKEN=$(az acr login --name "$ACR_NAME" --expose-token --query accessToken -o tsv)
export SDK_CONTAINER_REGISTRY_UNAME="00000000-0000-0000-0000-000000000000"
export SDK_CONTAINER_REGISTRY_PWORD="$TOKEN"

echo "==> Publishing container ${IMAGE_REPO}:${TAG} (+latest) to ${ACR_LOGIN_SERVER}"
dotnet publish "$PROJECT" -c "$BUILD_CONFIG" \
  -t:PublishContainer --os linux --arch x64 \
  -p:ContainerRegistry="$ACR_LOGIN_SERVER" \
  -p:ContainerRepository="$IMAGE_REPO" \
  -p:ContainerImageTags="\"${TAG};latest\"" \
  -p:ContainerBaseImage="$BASE_IMAGE"

# --- 3. Roll the Container App to the new image ---------------------------------
echo "==> Updating Container App image"
az config set extension.use_dynamic_install=yes_without_prompt >/dev/null 2>&1 || true
az containerapp update \
  --name "$CONTAINER_APP" \
  --resource-group "$RESOURCE_GROUP" \
  --image "${ACR_LOGIN_SERVER}/${IMAGE_REPO}:${TAG}" \
  --query "properties.latestRevisionName" -o tsv

FQDN=$(az containerapp show --name "$CONTAINER_APP" --resource-group "$RESOURCE_GROUP" \
  --query properties.configuration.ingress.fqdn -o tsv)
echo "==> Deployed ${IMAGE_REPO}:${TAG} -> https://${FQDN}"
echo "==> Probe: https://${FQDN}/health"
