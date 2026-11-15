"""Offline model of the published KQL rules; not a Kusto interpreter or Azure client."""
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import re

def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.utcoffset() != timedelta(0):
        raise ValueError('UTC timestamps required')
    return result

def five_minutes(value):
    return value.replace(minute=value.minute // 5 * 5, second=0, microsecond=0)

def evaluate(rows, signal, clock, source):
    if signal not in ('http_denials', 'service_unavailable'):
        raise ValueError('Unknown signal')
    clock = timestamp(clock)
    arrival_end = five_minutes(clock) - timedelta(minutes=5)
    arrival_start = arrival_end - timedelta(minutes=5)
    first = {}
    for original in rows:
        row = dict(original)
        event = timestamp(row['TimeGenerated'])
        if not clock - timedelta(days=1) <= event < clock + timedelta(minutes=2):
            continue
        if (row['Schema'] != 'careops.security.http.v1' or row['Environment'] != 'production'
                or row['SourceResourceId'].lower() != source.lower()
                or not re.fullmatch('[a-f0-9]{64}', row['EventId'])
                or not re.fullmatch('[a-zA-Z][a-zA-Z0-9_]{0,79}', row['FunctionName'])):
            continue
        row['_event'] = event
        row['_arrival'] = timestamp(row['Arrived'])
        old = first.get(row['EventId'])
        if old is None or row['_arrival'] < old['_arrival']:
            first[row['EventId']] = row
    groups = defaultdict(list)
    for row in first.values():
        matches = (row['Status'] in (401, 403) and row['EventKind'] == 'http_access_denied') if signal == 'http_denials' else (row['Status'] == 503 and row['EventKind'] == 'http_service_unavailable')
        if matches:
            groups[five_minutes(row['_event'])].append(row)
    threshold = 5 if signal == 'http_denials' else 3
    return [{'window': window.isoformat(), 'observed': len(values), 'signal': signal}
            for window, values in sorted(groups.items())
            if len(values) >= threshold and arrival_start <= max(x['_arrival'] for x in values) < arrival_end]
