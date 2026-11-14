# Commands and expected results

Run from the repository root unless a command uses `-chdir`.

```bash
# Install only this project's locked dependencies; no lifecycle install scripts.
npm ci --ignore-scripts

# Compile selected implementation source and run its original offline tests.
npm test

# Exercise the Python model, including the twelve original fixture scenarios.
python -B -m unittest discover -s tests -v

# Check original disabled plan/resource/query contracts without Azure calls.
python -B -m unittest discover -s scripts -p 'test_*.py' -v

# Regenerate four review queries locally from the source renderer.
python -B scripts/export_queries.py

# Build the fictional workbench and open the static output.
python -B -m lab.demo
python -m http.server 8017 --bind 127.0.0.1 --directory out

# Check public files/links/source bindings; no cloud access.
python -B scripts/review_publication.py
```

On Windows, `py -3.12` can replace `python` if that launcher is installed. Stop the loopback server with Ctrl+C. The server reads only the generated `out` folder and is not an incident editor.

## Terraform review

```bash
terraform -chdir=infra init -backend=false
terraform -chdir=infra fmt -check -recursive
terraform -chdir=infra validate
terraform -chdir=infra test
```

Provider download may require network access; mock tests need no Azure credentials. `plan`/`apply` against real resources are intentionally absent from automatic checks. Existing Sentinel workspace/table, source/workspace bindings, DCR, managed identity and notification route are separate prerequisites. Review imports and ownership before any real deployment.

## Separate read-only KQL fixture evaluation

```bash
python -B scripts/security_continuous_fixtures.py
```

This prints a self-contained `datatable` query; it does not send it anywhere. An authorized operator can evaluate it in a separately selected Kusto context. The local Python model passing does not mean that live query ran.

## ARM alternatives

```bash
python -B scripts/security_continuous_delivery.py --output out/review-arm
python -B scripts/security_continuous_detections.py --output out/review-detections
```

These render fictional, default-disabled review files only. They do not create grants, containers, tables or rules. Their fixed example bindings must be replaced consistently and reviewed before any separate cloud operation.

## Optional local screenshots

```bash
npx playwright install chromium
node scripts/capture_demo.mjs
```

Run the demo generator first. These commands install/use a local Chromium browser and capture only the fictional page; external requests are blocked. They do not sign in to Azure.

## Selected operations investigation

The read-only KQL and ClickOps path are in [Operations collection](OPERATIONS-COLLECTION.md). Use an existing authorized security-workspace session; do not run a deployment, reset a checkpoint, force a backup or send an email to reproduce that observation. The local demo does not simulate this later hosted collector.
