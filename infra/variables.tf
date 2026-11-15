variable "security_workspace_id" { type = string }
variable "operational_workspace_id" { type = string }
variable "source_component_id" { type = string }
variable "dcr_resource_id" { type = string }
variable "collector_principal_id" { type = string }
variable "monitoring_resource_group" { type = string }
variable "source_location" { type = string }
variable "action_group_ids" {
  type    = list(string)
  default = []
}
variable "enable_rules" {
  type    = bool
  default = false
}
variable "create_collector_grants" {
  type    = bool
  default = false
}
