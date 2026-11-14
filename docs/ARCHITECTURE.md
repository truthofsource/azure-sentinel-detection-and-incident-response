# Collection design and architecture

## Start with the purpose

The question is whether selected observed API access-denial or unavailability patterns deserve investigation. This is application-security onboarding into the central SIEM, not wholesale operational-log export or a complete business audit.

| Decision | Implemented boundary |
| --- | --- |
| Source | Exact environment Application Insights component, linked to its operational workspace |
| Selected evidence | Original UTC time, invocation/function, method, status, environment, stable ID and event kind |
| Excluded from this projection | Bodies, URLs, headers, tokens, claims, employee/client contents, IP addresses and invented caller identity |
| Collection | Five-minute timer with five-minute maturity and bounded overlap |
| State | Private Blob checkpoint/outbox, 60-second lease and conditional ETag writes |
| Destination | Custom ten-field table in the hub security Log Analytics workspace |
| DCR | Stream schema, transformation and destination instructions; not a queue or storage hop |
| Identity | API managed identity, source-component Monitoring Reader and DCR-scoped Monitoring Metrics Publisher |
| Existing storage access | Reused host-account Blob Data Contributor; not a newly container-only identity |
| Retention | The accepted security table was verified at 90 days; other tables have their own policies |
| Response | Human-owned incident; no automatic account containment |

## Storage is not one service

Application Insights is the application investigation experience; its linked Log Analytics workspace stores operational traces. The hub security workspace stores the selected security table. Blob Storage stores delivery state, and the business application's SQL audit remains a separate authority. A configured destination does not prove ingestion or restore coverage.

## Failure boundaries

The API host and timer share power, package and identity. Durable pending work survives a process restart, but it cannot recreate a trace that was never captured. Missing source ingestion time, invalid projections, dense one-second windows, permanent rejection and expired recovery bounds can stop progress visibly.

The existing Azure Activity/identity collection and role-assignment rule are separate sources from the new HTTP projection. A role-assignment incident is not an HTTP-rule incident. The notification route is an existing separately verified action group, not a new email service created by this public reference.

## Public example versus live bindings

Resource names, subscriptions, principal IDs and the environment-setting label are replaced with examples. The selected behavioral modules and original tests preserve the implementation pattern. This repository does not contain the application's token middleware, complete Function host, private network route, deployed secrets or production settings.
