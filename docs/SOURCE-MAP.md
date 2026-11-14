# Source map and adaptation boundary

| Public path | Origin and role |
| --- | --- |
| `reference/securityHttpEvents*` | Selected observer and original privacy/selection tests from the application |
| `reference/securityHttpExport*` | Shared projection/validation plus retained legacy nonproduction exporter and tests |
| `reference/securityDurableDelivery*` | Actual persisted delivery engine and original failure/replay tests |
| `reference/securityDeliveryAzure*` | Actual Azure managed-identity/storage/HTTP adapter and original seam tests |
| `scripts/security_continuous_*` | Original default-disabled ARM and KQL renderers and read-only Kusto fixture builder |
| `scripts/test_security_continuous_delivery.py` | Original resource-ownership, query-shape and disabled-default contracts |
| `infra/security-log-onboarding/nonproduction-ingestion.json` | Example-bound upstream DCR/schema input used by the original production renderer |
| `infra/*.tf` | New public Terraform integration for the same detection/health pattern; not a claim that Terraform deployed the accepted cloud rules |
| `lab/`, `tests/`, `demo/` | New offline teaching model, model boundary tests and local evidence page |

Live resource/subscription/principal names and the environment-setting label are generalized. Role-definition IDs are public built-in Azure role identifiers. Test dates, schema/event behavior, limits and selected original test logic remain useful context. The public source has fresh Git history and does not include the private repository, operational settings, tokens or source records.

Three selected Function registration modules are included under `functions/`; unrelated HTTP handlers and the complete host are not. Original test filesystem paths are adapted to this repository, and `examples/nonproduction-isolation.json` contains only the five relevant disabled controls.

The extracted Azure adapter is not a complete Function host. Cloud execution additionally needs reviewed settings, exact identity permissions, private state access, a preexisting table/DCR and coordinated commissioning. Do not point the public examples at a live system merely to reproduce screenshots.
