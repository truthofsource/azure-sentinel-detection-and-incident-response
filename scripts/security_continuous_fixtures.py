"""Read-only Kusto fixtures for delayed/replayed continuous detection. No ingestion."""
import datetime as dt
import hashlib
import json
import security_continuous_detections as detections
from security_continuous_delivery import scope

CLOCK = dt.datetime(2026, 11, 13, 18, tzinfo=dt.timezone.utc)


def rows(prefix, count, **changes):
    result = []
    for index in range(count):
        row = {"TimeGenerated": "2026-11-13T14:02:00.000Z", "Arrived": "2026-11-13T17:52:00.000Z",
               "EventId": hashlib.sha256(f"{prefix}-{index}".encode()).hexdigest(), "Schema": "careops.security.http.v1",
               "SourceResourceId": scope("production")["source"].lower(), "FunctionName": "roleCheck", "Environment": "production",
               "EventKind": "http_access_denied", "Status": 401}
        result.append(row | changes)
    return result


def cases():
    delayed = rows("delayed", 5)
    return [
        ("delayed_recovery", "http_denials", delayed, 1, 5),
        ("copies_not_distinct", "http_denials", rows("copies", 4) * 3, 0, 0),
        ("copies_at_threshold", "http_denials", delayed * 3, 1, 5),
        ("old_events_replayed", "http_denials", rows("replay", 5, Arrived="2026-11-13T17:32:00.000Z") + rows("replay", 5), 0, 0),
        ("late_threshold_crossing", "http_denials", rows("earlier", 4, Arrived="2026-11-13T17:32:00.000Z") + rows("fifth", 1), 1, 5),
        ("different_event_windows", "http_denials", rows("one", 3) + rows("two", 3, TimeGenerated="2026-11-13T14:07:00.000Z"), 0, 0),
        ("not_mature_arrival", "http_denials", rows("notyet", 5, Arrived="2026-11-13T17:55:00.000Z"), 0, 0),
        ("lower_arrival_inclusive", "http_denials", rows("left", 5, Arrived="2026-11-13T17:50:00.000Z"), 1, 5),
        ("wrong_environment", "http_denials", rows("env", 8, Environment="nonproduction"), 0, 0),
        ("wrong_source", "http_denials", rows("source", 8, SourceResourceId="/fictional/other"), 0, 0),
        ("outside_recovery_bound", "http_denials", rows("expired", 5, TimeGenerated="2026-11-12T17:59:00.000Z"), 0, 0),
        ("unavailable", "service_unavailable", rows("503", 3, Status=503, EventKind="http_service_unavailable"), 1, 3),
    ]


def build():
    fields = tuple(rows("declaration", 1)[0])
    declaration = ",".join(k + (":datetime" if k in ("TimeGenerated", "Arrived") else ":int" if k == "Status" else ":string") for k in fields)
    functions, evaluations = [], []
    for index, (name, signal, data, expected, observed) in enumerate(cases()):
        values = [",".join("datetime(" + row[k] + ")" if k in ("TimeGenerated", "Arrived") else json.dumps(row[k]) for k in fields) for row in data]
        functions.append(f"let Case{index}=(){{let Fixture=datatable({declaration})[" + ",\n".join(values) + "];\n" + detections.query(signal, fixture=True, reference=CLOCK) + "\n};")
        evaluations.append(f'(Case{index}() | summarize Results=count(), Observed=max(ObservedInvocations) | extend Case="{name}", Expected={expected} | extend Passed=Results==Expected and (Expected==0 or Observed=={observed}))')
    return "\n".join(functions) + "\nunion\n" + ",\n".join(evaluations) + "\n| project Case,Expected,Results,Observed,Passed\n"


if __name__ == "__main__":
    print(build())
