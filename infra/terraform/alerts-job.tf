# --- Scheduled SLA re-evaluation (keeps the app scale-to-zero) ----------------------------
# A Container Apps cron Job fires hourly and POSTs to the app's internal re-eval endpoint
# (gated by a shared token). That wakes the scale-to-zero app, which raises any new
# breach / due-soon alerts and dispatches webhook/Slack notifications, then idles back down.
# The job container is tiny (curl) and runs for seconds — near-zero cost vs. an always-on
# replica, while still giving a guaranteed hourly check.

resource "random_password" "reeval" {
  length  = 48
  special = false
}

resource "azurerm_container_app_job" "reeval" {
  name                         = "caj-${local.name_prefix}-reeval"
  resource_group_name          = azurerm_resource_group.main.name
  location                     = azurerm_resource_group.main.location
  container_app_environment_id = azurerm_container_app_environment.main.id
  tags                         = local.tags

  replica_timeout_in_seconds = 120
  replica_retry_limit        = 1

  schedule_trigger_config {
    cron_expression          = "0 * * * *" # hourly, on the hour (UTC)
    parallelism              = 1
    replica_completion_count = 1
  }

  secret {
    name  = "reeval-token"
    value = random_password.reeval.result
  }

  template {
    container {
      name   = "reeval"
      image  = "docker.io/curlimages/curl:latest"
      cpu    = 0.25
      memory = "0.5Gi"

      command = ["/bin/sh", "-c"]
      args = [
        "curl -fsS --max-time 110 -X POST -H \"X-Reeval-Token: $REEVAL_TOKEN\" https://${azurerm_container_app.main.ingress[0].fqdn}/api/internal/reevaluate || { echo 'reeval call failed'; exit 1; }"
      ]

      env {
        name        = "REEVAL_TOKEN"
        secret_name = "reeval-token"
      }
    }
  }
}
