mock_provider "azurerm" {}
variables {
  security_workspace_id     = "/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/rg-security-hub-eastus2/providers/Microsoft.OperationalInsights/workspaces/law-security-hub-eastus2-001"
  operational_workspace_id  = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-application-production-centralus/providers/Microsoft.OperationalInsights/workspaces/law-application-production-centralus-001"
  source_component_id       = "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-application-production-centralus/providers/Microsoft.Insights/components/appi-application-production-centralus-001"
  dcr_resource_id           = "/subscriptions/33333333-3333-4333-8333-333333333333/resourceGroups/rg-security-hub-eastus2/providers/Microsoft.Insights/dataCollectionRules/dcr-careops-http-prod"
  collector_principal_id    = "55555555-5555-4555-8555-555555555555"
  monitoring_resource_group = "rg-monitoring-hub-eastus2"
  source_location           = "centralus"
}
run "disabled_definitions_without_grants" {
  command = plan
  assert {
    condition     = alltrue([for rule in azurerm_sentinel_alert_rule_scheduled.http : rule.enabled == false]) && alltrue([for rule in azurerm_monitor_scheduled_query_rules_alert_v2.collector : rule.enabled == false])
    error_message = "Definitions must stay disabled by default."
  }
  assert {
    condition     = length(azurerm_role_assignment.source_reader) == 0 && length(azurerm_role_assignment.publisher) == 0
    error_message = "Do not create redundant grants by default."
  }
  assert {
    condition     = alltrue([for rule in azurerm_sentinel_alert_rule_scheduled.http : !strcontains(rule.query, "__SOURCE_RESOURCE_ID__")])
    error_message = "Source placeholder must be bound to the selected component."
  }
}
run "explicit_grants_stay_resource_scoped" {
  command = plan
  variables { create_collector_grants = true }
  assert {
    condition     = azurerm_role_assignment.source_reader[0].scope == var.source_component_id && azurerm_role_assignment.publisher[0].scope == var.dcr_resource_id
    error_message = "Reader and publisher must not be subscription-wide."
  }
}
