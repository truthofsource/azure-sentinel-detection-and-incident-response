"""Render default-disabled, closed-scope security delivery plans. No cloud calls.

Production reuses the existing 90-day table, never adopts the full hub root.
Nonproduction reuses its accepted DCR and source grant. No app settings or power
state are written; a reviewed activation receipt is a separate runtime step.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
HUB = "/subscriptions/33333333-3333-4333-8333-333333333333"
WORKSPACE = HUB + "/resourceGroups/rg-security-hub-eastus2/providers/Microsoft.OperationalInsights/workspaces/law-security-hub-eastus2-001"
ENVIRONMENTS = {
    "production": {"subscription": "11111111-1111-4111-8111-111111111111", "platform": "rg-application-production-centralus",
                   "application": "rg-api-production-centralus", "component": "appi-application-production-centralus-001",
                   "storage": "platformfunctionprod01", "principal": "55555555-5555-4555-8555-555555555555",
                   "workspace": "law-application-production-centralus-001", "location": "centralus"},
    "nonproduction": {"subscription": "22222222-2222-4222-8222-222222222222", "platform": "rg-application-nonproduction-eastus2",
                      "application": "rg-api-nonproduction-eastus2", "component": "appi-application-nonproduction-eastus2-001",
                      "storage": "stplatformfuncnp001", "principal": "66666666-6666-4666-8666-666666666666",
                      "workspace": "law-application-nonproduction-eastus2-001", "location": "eastus2"},
}


def scope(environment):
    if environment not in ENVIRONMENTS:
        raise ValueError("DELIVERY_PLAN_ENVIRONMENT")
    data = ENVIRONMENTS[environment]
    root = f'/subscriptions/{data["subscription"]}/resourceGroups/'
    return data | {"source": root + data["platform"] + "/providers/Microsoft.Insights/components/" + data["component"],
                   "operations": root + data["platform"] + "/providers/Microsoft.OperationalInsights/workspaces/" + data["workspace"]}


def template(resources):
    return {"$schema": SCHEMA, "contentVersion": "1.0.0.0", "resources": resources}


def checkpoint_plan(environment):
    data = scope(environment)
    container = data["storage"] + "/default/security-http-delivery"
    # Both verified API host identities already have account-scoped Blob Data
    # Contributor. Reuse that required host grant; do not add a redundant role.
    return template([
        {"type": "Microsoft.Storage/storageAccounts/blobServices/containers", "apiVersion": "2023-05-01", "name": container,
         "properties": {"publicAccess": "None"}},
    ])


def production_ingestion_plan():
    data = scope("production")
    prior = json.loads((ROOT / "infra/security-log-onboarding/nonproduction-ingestion.json").read_text(encoding="utf-8"))
    rule = copy.deepcopy(next(r for r in prior["resources"] if r["type"] == "Microsoft.Insights/dataCollectionRules"))
    rule.update(name="dcr-careops-http-prod", location="eastus2")
    rule.pop("dependsOn")
    rule["properties"]["destinations"]["logAnalytics"][0]["workspaceResourceId"] = WORKSPACE
    rule["properties"]["dataFlows"][0]["transformKql"] = (
        'source | where Schema == "careops.security.http.v1" and Environment == "production" and SourceResourceId =~ "' + data["source"] +
        '" | where (tolong(Status) in (401, 403) and EventKind == "http_access_denied") or (tolong(Status) == 503 and EventKind == "http_service_unavailable")'
        ' | project TimeGenerated, EventId, Schema, SourceResourceId, InvocationId, FunctionName, Method, Environment, EventKind, Status')
    publisher = copy.deepcopy(next(r for r in prior["resources"] if r["type"] == "Microsoft.Authorization/roleAssignments"))
    publisher["name"] = "[guid(resourceId('Microsoft.Insights/dataCollectionRules','dcr-careops-http-prod'),'" + data["principal"] + "','publisher')]"
    publisher["scope"] = "[resourceId('Microsoft.Insights/dataCollectionRules','dcr-careops-http-prod')]"
    publisher["dependsOn"] = [publisher["scope"]]
    publisher["properties"]["principalId"] = data["principal"]
    # Source reader is emitted separately to its existing component resource group.
    return template([rule, publisher])


def production_reader_plan():
    data = scope("production")
    return template([{"type": "Microsoft.Authorization/roleAssignments", "apiVersion": "2022-04-01",
                      "name": "[guid('" + data["source"] + "','" + data["principal"] + "','security-http-reader')]",
                      "scope": data["source"], "properties": {"principalId": data["principal"], "principalType": "ServicePrincipal",
                      "roleDefinitionId": "[subscriptionResourceId('Microsoft.Authorization/roleDefinitions','43d0d8ad-25c7-4714-9337-8ba259a9fe05')]"}}])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    plans = {"production-ingestion": production_ingestion_plan(), "production-source-reader": production_reader_plan(),
             **{env + "-checkpoint": checkpoint_plan(env) for env in ENVIRONMENTS}}
    hashes = {}
    for name, plan in plans.items():
        payload = (json.dumps(plan, indent=2) + "\n").encode()
        (args.output / (name + ".json")).write_bytes(payload)
        hashes[name] = hashlib.sha256(payload).hexdigest()
    print(json.dumps({"plans": hashes, "azureCalls": 0, "activation": False}))


if __name__ == "__main__":
    main()
