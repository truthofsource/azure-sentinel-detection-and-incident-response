"""Check public source and documentation locally; no secret verification or cloud calls."""
import json
from pathlib import Path
import re
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
IGNORED = {'node_modules', '.git', '.terraform', 'dist', 'out', '__pycache__'}
SUBSCRIPTIONS = {
    '11111111-1111-4111-8111-111111111111',
    '22222222-2222-4222-8222-222222222222',
    '33333333-3333-4333-8333-333333333333',
}
files = [p for p in ROOT.rglob('*') if p.is_file() and not IGNORED.intersection(p.relative_to(ROOT).parts)]
links = 0
for path in files:
    relative = path.relative_to(ROOT)
    assert not path.is_symlink(), relative
    assert path.suffix.lower() not in ('.pem', '.key', '.pfx', '.tfstate', '.tfplan', '.eml', '.docx'), relative
    if path.suffix.lower() in ('.png', '.jpg', '.jpeg'):
        assert relative.parts[:2] == ('docs', 'images'), relative
        continue
    text = path.read_text(encoding='utf-8-sig')
    for subscription in re.findall(r'/subscriptions/([a-f0-9-]{36})', text, re.I):
        assert subscription.lower() in SUBSCRIPTIONS, ('Unexpected live subscription binding', relative)
    # Match values rather than field names in fixtures/source. This is a guard,
    # not a replacement for review or a full secret scanner.
    assert not re.search(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', text), relative
    assert not re.search(r'AccountKey=[A-Za-z0-9+/]{30,}={0,2}', text), relative
    assert not re.search(r'eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}', text), relative
    if path.suffix == '.md':
        for target in re.findall(r'\]\(([^)]+)\)', text):
            if '://' in target or target.startswith(('mailto:', '#')):
                continue
            resolved = (path.parent / unquote(target.split('#', 1)[0])).resolve()
            assert resolved.is_relative_to(ROOT) and resolved.exists(), (relative, target)
            links += 1
assert (ROOT / 'docs/validation-results.json').is_file()
assert (ROOT / 'docs/images/01-overview.png').is_file()
assert len(list((ROOT / 'queries').glob('*.kql'))) == 4
print(json.dumps({'filesReviewed': len(files), 'relativeLinks': links,
                  'exampleSubscriptionsOnly': True, 'privateKeyJwtAndAccountKeyGuards': True,
                  'cloudOperations': False}))
