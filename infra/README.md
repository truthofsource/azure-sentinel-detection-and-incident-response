# Terraform integration and original ARM examples

This root describes two disabled Sentinel scheduled rules, two disabled Azure Monitor collector-health rules and optional resource-scoped reader/publisher grants. It targets existing resources through explicit inputs; it does not create a subscription, workspace, table, DCR, API, private network, app setting or action group.

The actual platform accepted the corresponding generated ARM definitions and controlled runtime activation. This Terraform root is a new public integration example, not a claim that it owns or deployed the live objects. Pick one management route, compare full plans and import existing resources deliberately; do not let two systems manage the same rule or assignment.

## Defaults and permissions

`enable_rules=false` and `create_collector_grants=false`. Existing equivalent source Reader/DCR publisher grants should be reused. This does not narrow an existing account-level storage grant or invent a container-only identity. Source logging, collector registration, host execution and fixed bootstrap binding are separate application settings.

Optional action-group IDs refer to an existing verified route. Without them, the public health definitions have no notification action. Cross-workspace query access, exact source-region placement and service query validation need separate cloud acceptance; mock tests cannot prove them.

```bash
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
terraform test
```

The tests use mock Azure responses and assert disabled defaults, no redundant grants, exact source substitution and resource-scoped optional assignments. `example.tfvars.example` contains only fictional targets. Do not submit it unchanged as a deployment.

The four `queries/*.kql` files come from the included original renderer. Terraform substitutes the exact source/workspace placeholders; the alert-trigger threshold is zero result rows because the KQL already applies the five-denial/three-503 threshold. The two collector-health alerts are operational Azure Monitor alerts, separate from Sentinel security-case creation.

Cloud resources/rules and query execution can incur charges. No Terraform apply or Azure login is part of this public validation. Private state, credentials and full plans remain outside Git.
