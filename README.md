# Application Security Monitoring with Microsoft Sentinel

[![Central SIEM collection — illustrated overview](docs/diagrams/architecture.png)](docs/diagrams/architecture.svg)

[View SVG](docs/diagrams/architecture.svg) · [Download PNG](docs/diagrams/architecture.png) · [Edit in draw.io](docs/diagrams/architecture.drawio)

**Bring selected application logs into a central SIEM, detect useful patterns, and give a responder clear investigation work.**

[Purpose](#the-purpose) · [Business problem](#the-business-problem) · [What was built](#what-was-built) · [Proof](#proof-it-works) · [Step by step](#step-by-step) · [Run it](#run-it-locally)

## The Purpose

The purpose is to **ingest selected application security logs into Microsoft Sentinel**, turn qualifying patterns into alerts and incidents, and support an accountable human response. SIEM means Security Information and Event Management: a place to bring security evidence together and investigate it.

For this implementation, selected API responses—`401` (authentication needed or rejected), `403` (access denied) and `503` (service unavailable)—become a small, consistent security record. Ordinary operational logs stay in the application environment; the collector forwards the selected metadata to the central hub security workspace. It does not copy every application log, request body or employee record.

## The Business Problem

A healthcare workforce application can still load while staff receive repeated access errors, a role is misconfigured or a dependency becomes unavailable. Those symptoms can look alike in a dashboard even though an expired session, an intentional test, an application fault and unauthorized activity require different responses.

The operator needs to know what was actually observed, whether that evidence reached the security workspace, why a rule opened a case and who reviewed it. Missing logs, delayed collection and duplicate records can make that answer unreliable. A notification marked accepted also does not establish that the person received it or acted.

The business need was a traceable path from **application behavior to useful investigation work**, with controlled access, limited private data, visible collection failures and clear response ownership.

## The Solution

I implemented a small application-security log route using Application Insights, a durable managed-identity collector, a hub Log Analytics table, KQL detections and Microsoft Sentinel incidents. Azure Monitor separately watches whether the collector itself is working.

**Business outcome:** Operators can follow a selected application event through collection and detection, review its meaning, and verify saved response actions. Initial production collection and a bounded incident-response exercise were accepted; longer-term noise, cost and coverage reviews remain ongoing.

This project draws on an implemented Azure workforce platform. The public source uses fictional resource bindings and selected original tests; organization details, live targets, credentials and private records are excluded. The screenshots below show a **working fictional local model**, not an Azure portal capture or a new production incident. [Validation scope](docs/VALIDATION.md) separates those evidence types.

## Tools Used and What They Do

| Tool or service | Purpose in this project |
| --- | --- |
| Azure Functions, Node.js and TypeScript | Observe selected completed API responses and run the five-minute collector. |
| Application Insights and Log Analytics | Store application telemetry and the selected central security records in separate workspace contexts. |
| Managed identity and Azure RBAC | Authenticate the collector without an app password and limit source-reader/DCR-publisher grants. |
| Blob Storage leases and ETags | Coordinate one saved checkpoint and pending batch; reject stale writes. |
| DCR and Logs Ingestion API | Define the custom record shape/destination and accept authorized batches. A DCR is configuration, not a queue. |
| KQL and Microsoft Sentinel | Count distinct observations, handle delayed evidence and create reviewable security cases. |
| Azure Monitor and action groups | Watch collector health and use a separately verified notification route. |
| Terraform and ARM templates | Make definitions and permission scopes reviewable; public examples start disabled. |
| Python, Node test runner and Playwright | Exercise fictional scenarios, original implementation tests and local evidence-page behavior. |

## Step by Step

Your own custom application-security table, Logs Ingestion API call, Sentinel scheduled detection and a documented incident triage exercise.

[Open the standalone build guide](docs/BUILD-YOUR-OWN.md) or follow the same complete instructions below.

Start with a new folder, your own files and your own accounts. The numbered steps below describe the build; no portfolio repository checkout is required. The existing implementation/evidence elsewhere in this repository is a separate reference, not a claim that your new build has already passed.

### Prerequisites

Azure subscription and permissions for Log Analytics, Sentinel, a data collection rule and its scoped ingestion identity; Python; a selected ingestion/retention budget. Use synthetic events and no employee records.

Use Bash on Linux/macOS/WSL for Bash blocks and PowerShell for PowerShell blocks. Select the tool versions supported by the official sources below, record the versions you actually install and retain generated dependency locks. Cloud resources, scanner downloads, logs and external AI calls can create costs; review the stated scope before enabling them.

### Create your project folder

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

### Step 1 — Define the event and ownership contract

**Where:** Your new project folder.

Define TimeGenerated, EventId, Actor, Result and Source, with a stable event ID for duplicate handling. Name the collector owner, rule owner and incident responder separately, and decide which app actions must never be included as raw sensitive content.

**Check before continuing:** You have a versioned minimal event schema and a collection diagram.

### Step 2 — Create the workspace, table and collection rule

**Where:** Azure Portal → Log Analytics workspace → Tables; DCR setup.

Create a dedicated workspace, enable Sentinel and create MyAppSecurity_CL with the schema below using the DCR-based custom-table procedure. Create/select the required ingestion endpoint and DCR stream, map the fields to the table and record the immutable rule ID/ingestion URL privately.

Create **`schema.json`** with the following contents:

```json
{"TimeGenerated":"2026-01-01T00:00:00Z","EventId":"lab-example","Actor":"lab-actor","Result":"Denied","Source":"my-app-lab"}
```

**Check before continuing:** The table schema and data flow match; enabling Sentinel alone does not collect application events.

### Step 3 — Grant only collection access and install the client

**Where:** DCR IAM and your private workstation.

Assign the intended test collector Monitoring Metrics Publisher at the exact DCR scope and verify its network path. Install azure-identity and requests; keep the ingestion URL and token outside public source.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install azure-identity requests
.venv/bin/python -m pip freeze > requirements.lock.txt
```

**Check before continuing:** The selected identity can ingest to the intended rule without general workspace administration.

### Step 4 — Create and send a bounded synthetic batch

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

### Step 5 — Verify table ingestion before adding an alert

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

### Step 6 — Create the scheduled rule and investigate its incident

**Where:** Sentinel → Analytics → Scheduled query rule.

Use the verified query, a deliberately chosen frequency/lookback, an account/entity mapping or Actor custom detail, and incident grouping appropriate to repeated evaluations. Enable incident creation, run the synthetic case and record evidence, assignee, benign/true/unknown classification and resolution reason; emails require a separately verified notification route.

**Check before continuing:** A real lab incident has a traceable source batch and a recorded human decision.

### Step 7 — Review noise, permissions, cost and cleanup

**Where:** Your rule/workspace and runbook.

Test duplicate ingestion and a below-threshold batch, inspect collector health and measure ingestion/retention cost. Give a separate test responder only the intended incident role if proving least privilege, then disable lab collection/rules and retain or delete the isolated workspace under your evidence policy.

**Check before continuing:** The project distinguishes collection, detection, incident creation, human response and notification delivery.

### Verification and your own screenshots

| Evidence | What to record | Your result |
| --- | --- | --- |
| New build | Your own files/resource settings and tool versions | Not yet recorded |
| Working path | The actual successful request, configuration or recovery result | Not yet recorded |
| Failure boundary | A meaningful denied, malformed, stale or failed case | Not yet recorded |
| Recovery / cleanup | What you restored or removed and what remains billed | Not yet recorded |

Capture your own architecture/configuration, one working result and one failure/recovery result. Keep tokens, credentials, personal records and private identifiers out of public screenshots. The architecture diagram explains the design; record your own results rather than treating it as execution evidence.

### Troubleshooting order

1. Confirm the named file, working directory and selected tool/interpreter.
2. Check the exact input and resource/account selected for the failing step.
3. Separate identity permission, network/DNS reachability and application validation.
4. Keep the actual error and reconcile an unknown write outcome before repeating it; do not widen access or repeat paid operations blindly.

The numbered steps describe a build procedure. Local syntax checks, an accepted API request, a completed hosted operation and a human verification are different evidence levels; fill in the verification table with what you actually observed.

### Official implementation references

- [learn.microsoft.com — tutorial-logs-ingestion-portal](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/tutorial-logs-ingestion-portal)
- [learn.microsoft.com — logs-ingestion-api-overview](https://learn.microsoft.com/en-us/azure/azure-monitor/logs/logs-ingestion-api-overview)
- [learn.microsoft.com — create-analytics-rules](https://learn.microsoft.com/en-us/azure/sentinel/create-analytics-rules)

The walkthrough layout follows the prerequisites → creation/configuration → test → verification → troubleshooting → cleanup pattern of the [Splunk project reference](https://github.com/davidharris6/splunk-siem-log-analysis). Its Splunk-specific settings are not copied into unrelated projects.

<details>
<summary>Reference: how the existing platform implementation operates</summary>

1. **Choose useful application evidence.** Record selected denied or unavailable API responses with their original time and stable identifier. Exclude tokens, request bodies and employee contents from this projection.

2. **Deliver it to the security workspace.** Read mature source records using managed identity and save pending work before sending it. Keep the saved position and any unresolved batch when a request fails.

3. **Detect a meaningful pattern.** Count distinct observations in the original five-minute activity window, while using first arrival to handle late evidence. Replayed copies must not create extra distinct events.

4. **Open and review the case.** Check the source, count, time window and expected activity before choosing a disposition. Record the owner and explanation, then verify the saved result.

5. **Check notification and collector health separately.** Distinguish a generated incident, a provider-accepted message, actual receipt and human action. Use heartbeat, checkpoint age and pending state to detect problems in the collection path.

6. **Observe before tuning.** Review normal volume, duplicates, late data, analyst workload and posted costs over time. Change thresholds or scale only when evidence justifies the tradeoff.

</details>

## Architecture

[View the illustrated project overview](docs/diagrams/architecture.svg).

No new always-running VM or automatic account containment is required. The collector shares the API host, so API downtime also stops collection. [Collection and identity boundaries](docs/ARCHITECTURE.md)

## What Was Built

| Component | What it does | Code or guide |
| --- | --- | --- |
| Metadata-only API observer | Select handled numeric 401/403/503 responses without inspecting sensitive request contents. | [Observer](reference/securityHttpEvents.ts) |
| Stable event projection | Validate selected records and derive consistent identifiers. | [Projection](reference/securityHttpExport.ts) |
| Durable collector | Save a checkpoint/outbox, coordinate ownership, bound recovery and retry unresolved work. | [Collector](reference/securityDurableDelivery.ts) |
| Azure delivery adapter | Use managed identity, bounded requests, Blob lease renewal and conditional writes. | [Adapter](reference/securityDeliveryAzure.ts) |
| Detection and health queries | Handle delayed arrival, duplicates, quiet sources and missing collector progress. | [KQL](queries) · [original renderer](scripts/security_continuous_detections.py) |
| Infrastructure examples | Define disabled Sentinel/Monitor rules and optional resource-scoped reader/publisher grants. | [Terraform](infra/README.md) · [ARM renderer](scripts/security_continuous_delivery.py) |
| Analyst response procedure | Review evidence, assign responsibility, document a decision and verify saved state. | [Incident response](docs/INCIDENT-RESPONSE.md) |
| Fictional local workbench | Run twelve detection fixtures and display a clearly labelled response example. | [Model](lab/detection.py) · [demo](lab/demo.py) |

The legacy nonproduction exporter is retained only because the durable collector reuses its projection code. It is not the production delivery method. [Source map](docs/SOURCE-MAP.md)

## Operations and Recovery Collection

The actual platform now also sends selected recovery, terminal email-delivery and recovery-storage metadata through an independent collector. One expected healthy event matched all eleven fields in the hub; two stored copies count as one distinct event, and new operations-specific alerts remain unactivated.

[Sources, diagram, query, acceptance and limits](docs/OPERATIONS-COLLECTION.md) explains this later extension. Native Entra audit and interactive sign-in logs already arrive through a separate route; this does not imply workload-sign-in collection or complete identity-threat detections.

## Proof It Works

### 1. Selected original source tests run offline

```bash
npm ci --ignore-scripts
npm test
```

The tests exercise observation privacy, projection validation, saved-batch replay, bounded retry, dense windows, stale ownership and Azure-adapter seams. They do not sign in to Azure or send messages. Current results are in the [dated validation record](docs/validation-results.json).

### 2. Duplicate and delayed events have different outcomes

```bash
python -B -m unittest discover -s tests -v
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B -m lab.demo
```

The offline model checks the same twelve scenarios used by the included KQL fixture generator. It shows why four observations copied three times stay below five, while a late fifth distinct event can cross the original window's threshold. **The Python model is not a Kusto interpreter; public local results do not claim a fresh Azure KQL execution.**

### 3. Response ownership is part of acceptance

The actual platform exercise verified a scoped Responder identity, a saved owner, the human-authored rehearsal comment and expected-test closure. It used an existing labelled test case; it did not claim a new automatic incident or a new incident-email cycle. The public workbench displays a fictional explanation of that process. [Response evidence and limits](docs/INCIDENT-RESPONSE.md)

### 4. Production observation is recorded without overstating it

The November 14 eight-hour checkpoint recorded **97 timer reports: 93 progress and four backoff**. The four backoff reports represented two processing failures and their waiting ticks; both recovered. The latest report had pending=0 and checkpoint age=301 seconds.

One distinct commissioning event had two stored copies, totaling 800 billable bytes. That is initial evidence, not proof of complete audit coverage, a long-term service level or representative natural traffic. Posted workspace charges lagged the rollout; a tiny row sample is not a monthly forecast. [Detailed acceptance boundaries](docs/VALIDATION.md)

## Run It Locally

Requires Node.js 22+ and Python 3.12+. From the repository root:

```bash
npm ci --ignore-scripts
npm test
python -B -m unittest discover -s tests -v
python -B -m unittest discover -s scripts -p 'test_*.py' -v
python -B -m lab.demo
python -m http.server 8017 --bind 127.0.0.1 --directory out
```

Open [the local workbench](http://127.0.0.1:8017), review all three sections, then stop the server with Ctrl+C. On Windows, use `python.exe` or `py -3.12` if that is your installed launcher; the commands otherwise stay the same. No Azure login, real employee record or paid provider operation is needed. [Full commands](docs/COMMANDS.md)

## Strengths, Weaknesses and Tradeoffs

- **Strengths:** Small consistent evidence, keyless authentication, durable pending work, visible collection health, replay-aware counting and verified human action.
- **Weaknesses:** Source logging is sampled/best effort, the shared API host is a shared failure boundary, the projection lacks user/IP attribution, and bounded recovery can stop visibly.
- **Tradeoffs:** More context helps investigation but increases privacy exposure; lower thresholds increase analyst work; longer retention and replayed copies can cost more.

Measure normal volume, lag, duplicates, query limits and responder workload before adding a dedicated worker or more partitions. [Scaling and cost decisions](docs/SCALING.md)

## Troubleshooting Lessons

Expected role-assignment changes can open a case without proving compromise. A generic `DELIVERY_TRANSPORT` label does not establish a network root cause. An HTTP 403 can come from an incorrect reader operation, and provider acceptance can precede missing inbox receipt. Each required following the actual evidence path rather than widening permissions or replaying a business action. [Lessons and fixes](docs/LESSONS-LEARNED.md)

## Project Guides

| Guide | What it explains |
| --- | --- |
| [Architecture and collection design](docs/ARCHITECTURE.md) | Sources, storage, identity, privacy and failure boundaries |
| [Implementation walkthrough](docs/WALKTHROUGH.md) | How the code and queries work together |
| [Incident response](docs/INCIDENT-RESPONSE.md) | Triage, escalation, disposition and saved human evidence |
| [Operations and troubleshooting](docs/OPERATIONS.md) | Heartbeat, retry, delayed data, recovery and pause |
| [Commands](docs/COMMANDS.md) | Local tests, query generation and separate cloud prerequisites |
| [Validation](docs/VALIDATION.md) | Current local checks versus recorded hosted acceptance |
| [Terraform integration](infra/README.md) | Disabled definitions and optional scoped grants |
| [Source map](docs/SOURCE-MAP.md) | Extracted code versus new public examples |
| [Scaling and costs](docs/SCALING.md) | Measured bottlenecks, analyst capacity and billing boundaries |
| [References](docs/REFERENCES.md) | Official documentation used for the design |

## Repository Map

```text
reference/           Selected implementation modules and original tests
functions/           Selected observer/timer registration modules
examples/            Relevant disabled nonproduction settings only
scripts/             ARM/KQL renderers, original plan checks and publication review
queries/             Reviewed detection and collector-health KQL
infra/               Terraform integration, example inputs and mock plan tests
lab/                 Fictional offline detection model and demo generator
demo/                Local evidence-page template
tests/               Additional model boundary cases
docs/                Architecture, operations, response, evidence and screenshots
.github/workflows/   Manual-only local contracts; no cloud deployment permission
```

## Security and Cleanup

The local demo writes only `out/`; it does not enable services, send alerts or edit Sentinel. Infrastructure validation is separate from deployment, and applying cloud examples can incur charges. Do not apply the Terraform and ARM alternatives to the same objects without deciding ownership and imports. Keep real state files, credentials and incident contents out of this repository. [Security and publication boundary](SECURITY.md)
