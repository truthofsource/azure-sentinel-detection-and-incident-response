"""Prepare production rules and health queries for review; never enable or apply.

Use first destination arrival per stable event ID. Replayed copies cannot inflate
counts or masquerade as new arrivals. Newly arriving distinct events can update
an earlier event-time window; native incident grouping is bounded, not exactly once.
"""
import argparse
import datetime as dt
import json
from pathlib import Path
import uuid

from security_continuous_delivery import HUB, WORKSPACE, scope, template

SIGNALS = {"http_denials": (5, "tolong(Status) in (401,403)", "http_access_denied"),
           "service_unavailable": (3, "tolong(Status) == 503", "http_service_unavailable")}


def query(signal, *, fixture=False, reference=None):
    if signal not in SIGNALS or type(fixture) is not bool:
        raise ValueError("CONTINUOUS_SIGNAL")
    clock = "now()"
    if reference is not None:
        if not isinstance(reference, dt.datetime) or reference.utcoffset() != dt.timedelta(0):
            raise ValueError("CONTINUOUS_CLOCK")
        clock = "datetime(" + reference.isoformat(timespec="milliseconds").replace("+00:00", "Z") + ")"
    threshold, status, event = SIGNALS[signal]
    source = scope("production")["source"].lower()
    table = "Fixture" if fixture else "CareOpsSecurityHttp_CL"
    arrival = "Arrived" if fixture else "ingestion_time()"
    return f'''let ArrivalEnd=bin({clock},5m)-5m;
let ArrivalStart=ArrivalEnd-5m;
{table}
| where TimeGenerated >= {clock}-1d and TimeGenerated < {clock}+2m
| where Schema == "careops.security.http.v1" and Environment == "production"
| where SourceResourceId =~ "{source}"
| where EventId matches regex @"^[a-f0-9]{{64}}$"
| where FunctionName matches regex @"^[a-zA-Z][a-zA-Z0-9_]{{0,79}}$"
| extend Arrival={arrival}
| summarize arg_min(Arrival,*) by EventId
| where {status} and EventKind == "{event}"
| extend SourceResourceId=tolower(SourceResourceId), WindowStart=bin(TimeGenerated,5m)
| summarize TimeGenerated=max(TimeGenerated), LatestDistinctArrival=max(Arrival), ObservedInvocations=count(), Unauthorized=countif(tolong(Status)==401), Forbidden=countif(tolong(Status)==403), Unavailable=countif(tolong(Status)==503), FunctionsShown=make_set(FunctionName,10) by SourceResourceId, WindowStart
| where ObservedInvocations >= {threshold} and LatestDistinctArrival >= ArrivalStart and LatestDistinctArrival < ArrivalEnd
| extend WindowEnd=WindowStart+5m, FunctionsShown=tostring(FunctionsShown)
| extend DetectionKey=hash_sha256(strcat(SourceResourceId,"|{signal}|",tostring(WindowStart)))
| project TimeGenerated, SourceResourceId, DetectionKey, WindowStart, WindowEnd, LatestDistinctArrival, ObservedInvocations, Unauthorized, Forbidden, Unavailable, FunctionsShown'''


def rules():
    resources = []
    for signal in SIGNALS:
        resources.append({"type": "Microsoft.SecurityInsights/alertRules", "apiVersion": "2024-03-01", "scope": WORKSPACE,
                          "name": str(uuid.uuid5(uuid.NAMESPACE_URL, WORKSPACE.lower() + "/careops-security-production-v2/" + signal)),
                          "kind": "Scheduled", "properties": {
            "displayName": "CareOps production " + ("repeated HTTP access denials" if signal == "http_denials" else "service-unavailable observations"),
            "description": "Sampled HTTP observations, not an identity or compromise finding. Counts use event time; first destination arrival permits delayed recovery. Duplicate copies do not count. Review expected tests, roles, session expiry and maintenance. Native grouping is bounded; late distinct events may update a window. No automatic containment.",
            "enabled": False, "severity": "Low", "query": query(signal), "queryFrequency": "PT5M", "queryPeriod": "P1D",
            "triggerOperator": "GreaterThan", "triggerThreshold": 0, "suppressionEnabled": False, "suppressionDuration": "PT5M",
            "tactics": [], "techniques": [], "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
            "customDetails": {**{k: k for k in ("DetectionKey", "WindowStart", "WindowEnd", "ObservedInvocations", "Unauthorized", "Forbidden", "Unavailable", "FunctionsShown")},
                              "LatestArrival": "LatestDistinctArrival"},
            "entityMappings": [{"entityType": "AzureResource", "fieldMappings": [{"identifier": "ResourceId", "columnName": "SourceResourceId"}]}],
            "incidentConfiguration": {"createIncident": True, "groupingConfiguration": {
                "enabled": True, "reopenClosedIncident": False, "lookbackDuration": "P1D", "matchingMethod": "Selected",
                "groupByEntities": [], "groupByAlertDetails": [], "groupByCustomDetails": ["DetectionKey"]}},
        }})
    return template(resources)


def health_query(environment):
    data = scope(environment)
    # Seed ensures a missing heartbeat produces a row rather than an empty result.
    # Disabled until a real commissioning time and hosted checks are reviewed.
    return f'''let Latest=AppTraces
| where TimeGenerated > ago(45m) and _ResourceId =~ "{data["source"].lower()}"
| extend D=parse_json(Message)
| where tostring(D.schema)=="careops.security.delivery.v1"
| where tostring(D.outcome)!="busy"
| summarize arg_max(TimeGenerated,D)
| project LastHeartbeat=TimeGenerated, Outcome=tostring(D.outcome), CheckpointAgeSeconds=tolong(D.checkpointAgeSeconds), Pending=tolong(D.pending), SafeCode=tostring(D.code);
datatable(Expected:int)[1]
| extend JoinKey=1
| join kind=leftouter (Latest | extend JoinKey=1) on JoinKey
| extend MissingHeartbeat=isnull(LastHeartbeat) or LastHeartbeat < ago(15m), Stalled=CheckpointAgeSeconds > 1200, Blocked=Outcome in ("blocked","failed")
| where MissingHeartbeat or Stalled or Blocked
| project TimeGenerated=now(), MissingHeartbeat, Stalled, Blocked, LastHeartbeat, Outcome, CheckpointAgeSeconds, Pending, SafeCode'''


def health_rule(environment):
    data = scope(environment)
    return template([{"type": "Microsoft.Insights/scheduledQueryRules", "apiVersion": "2023-12-01",
                      "name": "alert-careops-security-delivery-" + environment, "location": data["location"],
                      "properties": {"displayName": "CareOps " + environment + " security collection health",
                                     "description": "Missing non-busy heartbeat, checkpoint older than twenty minutes, or blocked delivery. Quiet HTTP traffic alone is not failure. Query and notification delivery are separate prerequisites.",
                                     "enabled": False, "severity": 2, "evaluationFrequency": "PT5M", "windowSize": "PT45M", "autoMitigate": True,
                                     "scopes": [data["operations"]], "criteria": {"allOf": [{"query": health_query(environment), "timeAggregation": "Count",
                                         "operator": "GreaterThan", "threshold": 0, "failingPeriods": {"numberOfEvaluationPeriods": 2, "minFailingPeriodsToAlert": 2}}]},
                                     "actions": {"actionGroups": [HUB + "/resourceGroups/rg-monitoring-hub-eastus2/providers/Microsoft.Insights/actionGroups/ag-careops-security-monitoring"]}}}])


def arrival_query(environment):
    data = scope(environment)
    # Coarse liveness only: does not reconcile every batch/event or prove losslessness.
    return f'''let Accepted=AppTraces
| where TimeGenerated between (ago(30m)..ago(15m)) and _ResourceId =~ "{data["source"].lower()}"
| extend D=parse_json(Message)
| where tostring(D.schema)=="careops.security.delivery.v1" and tolong(D.accepted)>0
| summarize AcceptedReports=count();
let Arrived=workspace("{WORKSPACE}").CareOpsSecurityHttp_CL
| where TimeGenerated > ago(1d)
| where SourceResourceId =~ "{data["source"].lower()}" and Environment=="{environment}" and Schema=="careops.security.http.v1"
| where ingestion_time() > ago(30m)
| summarize ArrivalRows=count();
Accepted | extend JoinKey=1
| join kind=inner (Arrived | extend JoinKey=1) on JoinKey
| where AcceptedReports > 0 and ArrivalRows == 0
| project TimeGenerated=now(), AcceptedReports, ArrivalRows'''


def arrival_rule(environment):
    result = health_rule(environment)
    resource = result["resources"][0]
    resource["name"] = "alert-careops-security-arrival-" + environment
    p = resource["properties"]
    p["displayName"] = "CareOps " + environment + " accepted security data not observed"
    p["description"] = "Coarse destination-liveness gap: service acceptance reported 15-30 minutes ago, but no matching-source destination arrivals in 30 minutes. Does not reconcile every batch or establish losslessness. Check ingestion delay, DCR and target query access."
    p["criteria"]["allOf"][0]["query"] = arrival_query(environment)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(); args.output.mkdir(parents=True, exist_ok=True)
    (args.output / "production-disabled-rules.json").write_text(json.dumps(rules(), indent=2) + "\n", encoding="utf-8")
    for signal in SIGNALS:
        (args.output / (signal + ".kql")).write_text(query(signal) + "\n", encoding="utf-8")
    for environment in ("production", "nonproduction"):
        (args.output / (environment + "-collector-health.kql")).write_text(health_query(environment) + "\n", encoding="utf-8")
        (args.output / (environment + "-disabled-health.json")).write_text(json.dumps(health_rule(environment), indent=2) + "\n", encoding="utf-8")
        (args.output / (environment + "-destination-arrival.kql")).write_text(arrival_query(environment) + "\n", encoding="utf-8")
        (args.output / (environment + "-disabled-arrival.json")).write_text(json.dumps(arrival_rule(environment), indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"rules": 2, "enabled": False, "healthQueries": 2, "azureCalls": 0, "notifications": 0}))


if __name__ == "__main__":
    main()
