# Troubleshooting lessons from implementation

| Symptom | Investigation and correction | Lesson |
| --- | --- | --- |
| Event exists at the source but not in the hub | Compare exact source/DCR identity, saved cursor/pending state and destination IDs. | A green deploy or source row does not prove destination arrival. |
| Duplicate rows | Same stable ID arrived twice; analytical deduplication kept the count at one. | Stored rows, distinct events and billable bytes are different measures. |
| Four backoff reports | Two saved failures were followed by scheduled ticks before RetryAt; progress later resumed. | Waiting is not a new failed send; a generic safe code does not establish root cause. |
| Activity query appeared empty | `_ResourceId` was populated while legacy `ResourceId` was empty; use the populated-field fallback. | Check schema/field population before concluding the activity did not happen. |
| Incident alert reader returned 403 | GET failed; the documented read-only List Alerts POST succeeded with unchanged permissions. | Check the supported operation before broadening a role; do not generalize every 403. |
| Responder test assumed no deployment support | Read the actual built-in definition and effective permissions, then corrected the local assertion. | Least privilege must be demonstrated using real permissions, not a role-name assumption. |
| Notification API said Enabled but no email arrived | Portal showed pending receiver verification; after the owner verified it, one authorized diagnostic succeeded and was seen. | Acceptance, transport status, receipt and human response are separate evidence. |
| Sentinel rejected custom details | A label exceeded twenty characters; shorten the label while keeping the query-column mapping. | What-if is not a substitute for service validation and runtime readback. |
| Old release verifier blocked promotion | Add the required successful dependency-security publisher job to the exact-artifact validation. | Repair the source guard and prove the reviewed artifact; do not bypass the failed check. |

The root cause of the two generic processing failures was not established. The project records recovery, not an invented network repair or permanent-resolution claim.

## Private paths, timestamps and duplicate evidence

An installed package is not a working host: private Functions storage still required its intended Blob/Queue network path. Identical source/package publication succeeded after a bounded path repair, followed by endpoint and DNS cleanup. Exact readback also found a normalized UTC string that the strict parser rejected; a retained canonical value repaired the configuration without resetting an established checkpoint. [Operations collection](OPERATIONS-COLLECTION.md) separates the proved outcome from the original deployment's untraced internal cause and the stored duplicate's untraced cause.
