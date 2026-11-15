# Build your own from scratch: Azure Sentinel Detection And Incident Response

Your own custom application-security table, Logs Ingestion API call, Sentinel scheduled detection and a documented incident triage exercise.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

## Prerequisites

Azure subscription and permissions for Log Analytics, Sentinel, a data collection rule and its scoped ingestion identity; Python; a selected ingestion/retention budget. Use synthetic events and no employee records.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

## Create your project folder

Choose a new folder name. These first commands create a blank project; an optional `git init` gives it its own history. Create parent directories in your editor when a later step introduces a nested file.

```bash
mkdir my-azure-sentinel-detection-and-incident-response
cd my-azure-sentinel-detection-and-incident-response
git init
```

Create `.gitignore` before saving credentials or build outputs:

```gitignore
.venv/
node_modules/
.env
.env.*
local.settings.json
credentials.json
token.json
*.pem
*.key
*.tfstate*
*.tfplan
.terraform/
private*/
captures/
backups/
batch.json
reports/
out/
app-config.local.yaml
```

The source/file snippets are a starting implementation you type or paste into the named files. Replace `YOUR_*`, names, regions and addresses only with values from your own lab; do not place real client/employee records in a test project. Keep your terminal in this project root unless a step explicitly changes directory.

Before a first commit, set your own repository-local author with `git config user.name "YOUR_NAME"` and `git config user.email "YOUR_PUBLIC_COMMIT_EMAIL"`. Review `git status --short` and the staged diff before publishing; ignored local files are not a substitute for reviewing what you upload.

## Step 1 — Define the event and ownership contract

**Where:** Your new project folder.

Define TimeGenerated, EventId, Actor, Result and Source, with a stable event ID for duplicate handling. Name the collector owner, rule owner and incident responder separately, and decide which app actions must never be included as raw sensitive content.

**Check before continuing:** You have a versioned minimal event schema and a collection diagram.

## Step 2 — Create the workspace, table and collection rule

**Where:** Azure Portal → Log Analytics workspace → Tables; DCR setup.

Create a dedicated workspace, enable Sentinel and create MyAppSecurity_CL with the schema below using the DCR-based custom-table procedure. Create/select the required ingestion endpoint and DCR stream, map the fields to the table and record the immutable rule ID/ingestion URL privately.

Create **`schema.json`** with the following contents:

```json
{"TimeGenerated":"2026-01-01T00:00:00Z","EventId":"lab-example","Actor":"lab-actor","Result":"Denied","Source":"my-app-lab"}
```

**Check before continuing:** The table schema and data flow match; enabling Sentinel alone does not collect application events.

## Step 3 — Grant only collection access and install the client

**Where:** DCR IAM and your private workstation.

Assign the intended test collector Monitoring Metrics Publisher at the exact DCR scope and verify its network path. Install azure-identity and requests; keep the ingestion URL and token outside public source.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install azure-identity requests
.venv/bin/python -m pip freeze > requirements.lock.txt
```

**Check before continuing:** The selected identity can ingest to the intended rule without general workspace administration.

## Step 4 — Create and send a bounded synthetic batch

**Where:** Your editor and private terminal.

Create ingest.py below and set INGESTION_URL to your exact DCR/stream Logs Ingestion endpoint. The first run saves stable event IDs locally so an uncertain response does not require generating a new duplicate batch.

Create **`ingest.py`** with the following contents:

```python
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlsplit
import os, uuid, json, requests
from azure.identity import AzureCliCredential
url = os.environ['INGESTION_URL']
parsed = urlsplit(url)
if parsed.scheme != 'https' or not (parsed.hostname or '').endswith('.ingest.monitor.azure.com'):
    raise ValueError('Use the selected public-Azure ingestion endpoint')
batch = Path('batch.json')
if not batch.exists():
    now = datetime.now(timezone.utc).isoformat()
    events = [{'TimeGenerated': now, 'EventId': str(uuid.uuid4()),
               'Actor': 'lab-actor', 'Result': 'Denied', 'Source': 'my-app-lab'} for _ in range(3)]
    with batch.open('x') as output: json.dump(events, output)
events = json.loads(batch.read_text())
token = AzureCliCredential().get_token('https://monitor.azure.com/.default').token
response = requests.post(url, headers={'Authorization': 'Bearer '+token}, json=events, timeout=30)
response.raise_for_status()
print({'http_status': response.status_code, 'events_submitted': len(events)})
```

```bash
az login
.venv/bin/python ingest.py
```

Set `INGESTION_URL` privately to `https://YOUR_LOGS_INGESTION_HOST/dataCollectionRules/YOUR_DCR_IMMUTABLE_ID/streams/YOUR_STREAM_NAME?api-version=2023-01-01`, using the exact host, immutable ID and stream from your own rule. The DCE/DCR host alone is not the complete POST URL.

**Check before continuing:** Three synthetic denial events are submitted through your own collection rule.

## Step 5 — Verify table ingestion before adding an alert

**Where:** Workspace Logs / Microsoft Sentinel hunting.

Run the query below after allowing for ingestion delay. If empty, inspect the DCR stream/schema, target table, identity permission, endpoint and actual request outcome; do not repeatedly resubmit a batch to make a count appear. Compare batch.json TimeGenerated with the inspection query window before diagnosing missing ingestion. Preserve the original batch IDs/timestamps on a retry; widen a read-only inspection window when appropriate instead of regenerating events to manufacture an alert.

```kusto
MyAppSecurity_CL
| where TimeGenerated > ago(15m)
| where Source == "my-app-lab"
| summarize arg_max(TimeGenerated, *) by EventId
| where Result == "Denied"
| summarize Failures=count(), TimeGenerated=max(TimeGenerated) by Actor
| where Failures >= 3
```

**Check before continuing:** Your own EventIds arrive in the intended table and duplicate IDs do not inflate the detection.

## Step 6 — Create the scheduled rule and investigate its incident

**Where:** Sentinel → Analytics → Scheduled query rule.

Use the verified query, a deliberately chosen frequency/lookback, an account/entity mapping or Actor custom detail, and incident grouping appropriate to repeated evaluations. Enable incident creation, run the synthetic case and record evidence, assignee, benign/true/unknown classification and resolution reason; emails require a separately verified notification route.

**Check before continuing:** A real lab incident has a traceable source batch and a recorded human decision.

## Step 7 — Review noise, permissions, cost and cleanup

**Where:** Your rule/workspace and runbook.

Test duplicate ingestion and a below-threshold batch, inspect collector health and measure ingestion/retention cost. Give a separate test responder only the intended incident role if proving least privilege, then disable lab collection/rules and retain or delete the isolated workspace under your evidence policy.

**Check before continuing:** The project distinguishes collection, detection, incident creation, human response and notification delivery.

## Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. Existing portfolio images are references, not evidence that you performed these steps.

## Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

## Official implementation references

- [learn.microsoft.com — tutorial-logs-ingestion-portal](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)
- [learn.microsoft.com — logs-ingestion-api-overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [learn.microsoft.com — create-analytics-rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.
