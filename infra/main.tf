locals {
  signals = {
    http_denials        = "Repeated application access denials"
    service_unavailable = "Application service-unavailable observations"
  }
  health = {
    health      = "Collector progress and heartbeat"
    destination = "Collector destination liveness"
  }
}

# Existing workspace, table and DCR are prerequisites, not adopted here.
resource "azurerm_sentinel_alert_rule_scheduled" "http" {
  for_each                   = local.signals
  name                       = uuidv5("url", "${lower(var.security_workspace_id)}/portfolio-http/${each.key}")
  log_analytics_workspace_id = var.security_workspace_id
  display_name               = each.value
  severity                   = "Low"
  enabled                    = var.enable_rules
  query                      = replace(file("${path.module}/../queries/${each.key}.kql"), "__SOURCE_RESOURCE_ID__", lower(var.source_component_id))
  query_frequency            = "PT5M"
  query_period               = "P1D"
  trigger_operator           = "GreaterThan"
  trigger_threshold          = 0
  suppression_enabled        = false
  suppression_duration       = "PT5M"
  custom_details = {
    DetectionKey        = "DetectionKey"
    WindowStart         = "WindowStart"
    WindowEnd           = "WindowEnd"
    ObservedInvocations = "ObservedInvocations"
    LatestArrival       = "LatestDistinctArrival"
  }
  event_grouping {
    aggregation_method = "AlertPerResult"
  }
  incident {
    create_incident_enabled = true
    grouping {
      enabled                 = true
      lookback_duration       = "P1D"
      reopen_closed_incidents = false
      entity_matching_method  = "Selected"
      by_custom_details       = ["DetectionKey"]
    }
  }
}

resource "azurerm_monitor_scheduled_query_rules_alert_v2" "collector" {
  for_each                = local.health
  name                    = "application-security-${each.key}"
  resource_group_name     = var.monitoring_resource_group
  location                = var.source_location
  display_name            = each.value
  enabled                 = var.enable_rules
  scopes                  = [var.operational_workspace_id]
  evaluation_frequency    = "PT5M"
  window_duration         = "PT45M"
  severity                = 2
  auto_mitigation_enabled = true
  criteria {
    query                   = replace(replace(file("${path.module}/../queries/${each.key}.kql"), "__SOURCE_RESOURCE_ID__", lower(var.source_component_id)), "__SECURITY_WORKSPACE_ID__", var.security_workspace_id)
    time_aggregation_method = "Count"
    operator                = "GreaterThan"
    threshold               = 0
    failing_periods {
      minimum_failing_periods_to_trigger_alert = 2
      number_of_evaluation_periods             = 2
    }
  }
  dynamic "action" {
    for_each = length(var.action_group_ids) == 0 ? [] : [1]
    content {
      action_groups = var.action_group_ids
    }
  }
}

# Optional: reuse equivalent existing grants instead of creating duplicates.
resource "azurerm_role_assignment" "source_reader" {
  count                = var.create_collector_grants ? 1 : 0
  scope                = var.source_component_id
  role_definition_name = "Monitoring Reader"
  principal_id         = var.collector_principal_id
}
resource "azurerm_role_assignment" "publisher" {
  count                = var.create_collector_grants ? 1 : 0
  scope                = var.dcr_resource_id
  role_definition_name = "Monitoring Metrics Publisher"
  principal_id         = var.collector_principal_id
}
