"""Closed resource ownership, recovery-aware detection and default-Off guards."""
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import security_continuous_delivery as plans
import security_continuous_detections as detections
import security_continuous_fixtures as fixtures


class ContinuousDeliveryTests(unittest.TestCase):
    def test_checkpoint_owns_only_private_container_without_redundant_host_grant(self):
        for environment in plans.ENVIRONMENTS:
            resources = plans.checkpoint_plan(environment)["resources"]
            self.assertEqual(len(resources), 1)
            container = resources[0]
            self.assertEqual(container["type"], "Microsoft.Storage/storageAccounts/blobServices/containers")
            self.assertEqual(container["properties"], {"publicAccess": "None"})
            self.assertIn("/default/security-http-delivery", container["name"])
            self.assertNotIn("roleAssignments", json.dumps(resources))
            self.assertNotIn("listKeys", json.dumps(resources))
        with self.assertRaises(ValueError):
            plans.checkpoint_plan("other")

    def test_production_dcr_cannot_adopt_table_change_retention_or_expand_source(self):
        resources = plans.production_ingestion_plan()["resources"]
        self.assertEqual([r["type"] for r in resources], ["Microsoft.Insights/dataCollectionRules", "Microsoft.Authorization/roleAssignments"])
        rule, publisher = resources
        self.assertEqual(rule["name"], "dcr-careops-http-prod")
        self.assertEqual(rule["properties"]["destinations"]["logAnalytics"][0]["workspaceResourceId"], plans.WORKSPACE)
        transform = rule["properties"]["dataFlows"][0]["transformKql"]
        self.assertIn('Environment == "production"', transform)
        self.assertIn(plans.scope("production")["source"], transform)
        self.assertIn("tolong(Status)", transform)
        self.assertEqual(len(rule["properties"]["streamDeclarations"]["Custom-CareOpsSecurityHttp"]["columns"]), 10)
        self.assertIn("dcr-careops-http-prod", publisher["scope"])
        reader = plans.production_reader_plan()["resources"][0]
        self.assertEqual(reader["scope"], plans.scope("production")["source"])

    def test_new_rules_stay_disabled_and_do_not_modify_pilot_or_shared_notification(self):
        resources = detections.rules()["resources"]
        self.assertEqual(len(resources), 2)
        self.assertEqual(len({r["name"] for r in resources}), 2)
        for resource in resources:
            self.assertFalse(resource["properties"]["enabled"])
            self.assertEqual(resource["scope"], plans.WORKSPACE)
            self.assertEqual(resource["properties"]["queryPeriod"], "P1D")
            self.assertEqual(resource["properties"]["eventGroupingSettings"]["aggregationKind"], "AlertPerResult")
            self.assertTrue(all(len(key) <= 20 for key in resource["properties"]["customDetails"]))
            self.assertEqual(resource["properties"]["customDetails"]["LatestArrival"], "LatestDistinctArrival")
            self.assertFalse(resource["properties"]["incidentConfiguration"]["groupingConfiguration"]["reopenClosedIncident"])
        self.assertNotIn("actionGroup", json.dumps(resources))

    def test_delayed_detection_uses_first_arrival_before_threshold_and_no_replay_count(self):
        query = detections.query("http_denials")
        self.assertLess(query.index("arg_min(Arrival"), query.index("ObservedInvocations=count()"))
        self.assertIn("LatestDistinctArrival >= ArrivalStart", query)
        self.assertIn("WindowStart=bin(TimeGenerated,5m)", query)
        self.assertNotIn("Fixture", query)
        self.assertIn("ingestion_time()", query)
        self.assertEqual(len(fixtures.cases()), 12)
        self.assertIn("old_events_replayed", fixtures.build())

    def test_health_checks_missing_heartbeat_without_treating_quiet_traffic_as_failure(self):
        for environment in plans.ENVIRONMENTS:
            query = detections.health_query(environment)
            self.assertIn("datatable(Expected:int)[1]", query)
            self.assertIn("join kind=leftouter", query)
            self.assertIn("CheckpointAgeSeconds > 1200", query)
            self.assertIn(plans.scope(environment)["source"].lower(), query)
            self.assertNotIn("CareOpsSecurityHttp_CL | count", query)
            self.assertEqual(detections.health_rule(environment)["resources"][0]["location"], plans.scope(environment)["location"])

    def test_destination_gap_requires_prior_acceptance_and_cannot_enable_delivery(self):
        for environment in plans.ENVIRONMENTS:
            q = detections.arrival_query(environment)
            self.assertIn("AcceptedReports > 0 and ArrivalRows == 0", q)
            self.assertIn("ago(30m)..ago(15m)", q)
            self.assertIn(plans.WORKSPACE, q)
            r = detections.arrival_rule(environment)["resources"][0]
            self.assertFalse(r["properties"]["enabled"])
            self.assertEqual(r["properties"]["criteria"]["allOf"][0]["query"], q)


if __name__ == "__main__":
    unittest.main()
