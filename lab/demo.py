"""Build the fictional local workbench from fixture evaluations; no service calls."""
from pathlib import Path
import html
import json
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import security_continuous_fixtures as fixtures
from security_continuous_delivery import scope
from lab.detection import evaluate

root = Path(__file__).resolve().parents[1]
out = root / 'out'
out.mkdir(exist_ok=True)
cases = []
for name, signal, rows, expected, observed in fixtures.cases():
    result = evaluate(rows, signal, '2026-11-13T18:00:00Z', scope('production')['source'])
    passed = len(result) == expected and (not expected or result[0]['observed'] == observed)
    cases.append({'name': name, 'signal': signal, 'inputRows': len(rows), 'results': len(result), 'expected': expected, 'passed': passed})
data = {'scope': 'Fictional local model; no Azure query, notification or incident write',
        'cases': cases, 'passed': sum(x['passed'] for x in cases),
        'caseReview': {'case': 'DEMO-001', 'owner': 'Fictional Responder', 'status': 'Closed',
                       'classification': 'Benign positive / Suspicious but expected',
                       'reason': 'Authorized test; five distinct denied invocations crossed the example threshold.'}}
(out / 'results.json').write_text(json.dumps(data, indent=2), encoding='utf-8')
template = (root / 'demo/template.html').read_text(encoding='utf-8')
rows = ''.join('<tr><td>' + html.escape(x['name'].replace('_', ' ')) + '</td><td>' + str(x['inputRows']) + '</td><td>' + str(x['results']) + '</td><td><span class="good">' + ('Passed' if x['passed'] else 'Failed') + '</span></td></tr>' for x in cases)
template = template.replace('{{PASSED}}', str(data['passed'])).replace('{{ROWS}}', rows)
(out / 'index.html').write_text(template, encoding='utf-8')
print(json.dumps({'passed': data['passed'], 'scenarios': len(cases), 'page': 'out/index.html', 'azureCalls': 0}))
if not all(x['passed'] for x in cases):
    raise SystemExit(1)
