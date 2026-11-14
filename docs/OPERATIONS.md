# Operations and recovery

## Read the correct health signal

The collector emits a safe heartbeat with outcome, cursor age, pending count, attempts, retry time and code. A quiet HTTP source can still advance normally. Busy lease contenders must not hide a missing working collector.

Production health definitions check a missing non-busy heartbeat after fifteen minutes, cursor age over twenty minutes, or blocked/failed work. They evaluate every five minutes and need two failing evaluations; ingestion/evaluation delay means these are not exact alert-delivery deadlines.

The destination-liveness query checks acceptance reported 15–30 minutes ago with no matching-source arrival in thirty minutes. It detects coarse silence, not loss of every individual batch.

## Retry without destroying evidence

Retry delays nominally grow from five minutes toward one hour, with bounded provider advice and less than thirty seconds of jitter. The eighth unresolved failed processing attempt blocks; successful empty-interval or accepted-batch progress resets the counter. It is not a lifetime error allowance.

The next scheduled tick may arrive before RetryAt, report backoff and perform no new failed operation. Four backoff reports can therefore represent two failures and two waiting ticks. `DELIVERY_TRANSPORT` is also a fallback for unrecognized processing errors; it does not prove a network root cause or failed ingestion send.

Storage/lease failures can prevent retry state from being persisted. Inspect the exact safe stage and saved state rather than assuming every failure follows the same path. Do not force a lease break, overwrite a cursor, widen a role or discard a pending batch to clear an alert.

## Bounded work

Saved batches are limited to 500 events and 500,000 serialized bytes. Overflow shrinks source windows to a one-second minimum; a still-dense interval blocks. Each invocation has six processing steps and a 35-second soft work budget. Recovery is bounded to 24 hours; permanent rejection or an expired bound needs an explicit recovery decision.

## Pause and rollback

Coordinate collector, detection and health definitions. Preserve the checkpoint, pending work, table and original source/DCR/bootstrap binding; disable the new timer before restoring an older package. Do not activate the old nonproduction exporter as a production fallback. A long deliberate nonproduction pause can expire its recovery bound, so later acceptance needs a reviewed test-state decision.

## Operator ClickOps

Use the environment's Application Insights/Logs for source telemetry, hub security Logs for selected events, Sentinel Analytics/Incidents for detections and cases, and Azure Monitor Alerts/Action groups for collector health and notification history. Inspect configured permissions and actual saved state separately. Public commands in this repository do not authorize a live change.
