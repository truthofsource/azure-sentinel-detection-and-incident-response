"""Write review queries and plans locally; no cloud connection or deployment."""
from pathlib import Path
import json
import security_continuous_detections as detections
from security_continuous_delivery import scope, WORKSPACE

root = Path(__file__).resolve().parents[1]
folder = root / 'queries'
folder.mkdir(exist_ok=True)
source = scope('production')['source'].lower()
queries = {name: detections.query(name) for name in detections.SIGNALS}
queries.update(health=detections.health_query('production'), destination=detections.arrival_query('production'))
for name, query in queries.items():
    query = query.replace(source, '__SOURCE_RESOURCE_ID__').replace(WORKSPACE, '__SECURITY_WORKSPACE_ID__')
    (folder / (name + '.kql')).write_text(query + '\n', encoding='utf-8')
print(json.dumps({'queries': len(queries), 'azureCalls': 0, 'rulesEnabled': False}))
