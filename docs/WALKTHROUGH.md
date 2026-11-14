# Implementation walkthrough

1. `securityHttpEvent` checks opt-in, trigger type, function/invocation shape and a handled numeric 401, 403 or 503 response. It never reads private headers, bodies or claims; unsupported responses and pre-invocation platform failures are outside this hook.
2. `projectQueryResult` validates the selected schema and derives a stable identifier. The retained legacy exporter is nonproduction-only and is not the active production collector.
3. `deliverSecurityEvents` acquires the persisted state through an exclusive port. A pending batch is replayed before a new query; an empty interval advances the cursor without an ingestion send.
4. A nonempty interval is saved as pending before `send`. Only explicit 204 acceptance followed by saved state completes that batch; uncertain acceptance may replay the same IDs.
5. The Azure adapter uses managed identity and bounded source/ingestion requests. Lease renewal and ETag checks reject stale writers; a busy contender is not a working progress report.
6. Production KQL first deduplicates each stable ID by earliest destination arrival. It combines qualifying functions in the original five-minute source window, while completed arrival windows allow a late fifth distinct denial to cross the threshold.
7. Sentinel creates a Low signal for five distinct 401/403 or three 503 observations. A stable source/signal/window key supports one-day native grouping; late evidence may still produce more alerts and closed cases are not automatically reopened.
8. A responder reviews the source, window, expected activity and evidence limits. Notification acceptance, actual inbox receipt and saved human response remain separate checks.

The Python model is an explicit teaching implementation of rule semantics. The source KQL fixtures must be evaluated separately in an authorized Kusto environment before claiming a new live query acceptance.
