# syntax=docker/dockerfile:1

# ---- Build stage -------------------------------------------------------------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy manifests first so `restore` is cached unless a .csproj/solution changes.
COPY global.json ./
COPY Ravelin.slnx ./
COPY src/Ravelin/Ravelin.csproj                 src/Ravelin/
COPY src/Ravelin.Client/Ravelin.Client.csproj   src/Ravelin.Client/
COPY src/Ravelin.Domain/Ravelin.Domain.csproj   src/Ravelin.Domain/
COPY src/Ravelin.Shared/Ravelin.Shared.csproj   src/Ravelin.Shared/
RUN dotnet restore src/Ravelin/Ravelin.csproj

# Copy the remaining source and publish the server (pulls in client/shared/domain).
COPY . .
RUN dotnet publish src/Ravelin/Ravelin.csproj -c Release -o /app/publish /p:UseAppHost=false

# ---- Runtime stage -----------------------------------------------------------
# Chiseled image: distroless-style (no shell/package manager), runs as a
# non-root user (UID 1654) by default — minimal attack surface for our security tool.
FROM mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled AS final
WORKDIR /app
COPY --from=build /app/publish .

# Container Apps will route to this port and probe /health.
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080

ENTRYPOINT ["dotnet", "Ravelin.dll"]
