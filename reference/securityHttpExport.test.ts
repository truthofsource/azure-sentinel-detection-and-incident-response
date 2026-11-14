import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { EXPORT_SETTING, exportConfig, exportQuery, projectQueryResult, exportSecurityHttpEvents, safeExportError } from "./securityHttpExport";

const env = { [EXPORT_SETTING]: "true", PLATFORM_ENVIRONMENT: "nonproduction",
  CAREOPS_SECURITY_SOURCE_RESOURCE_ID: "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/fictional/providers/Microsoft.Insights/components/fictional-nonproduction",
  CAREOPS_SECURITY_INGESTION_ENDPOINT: "https://fictional.eastus-1.ingest.monitor.azure.com",
  CAREOPS_SECURITY_DCR_IMMUTABLE_ID: `dcr-${"a".repeat(32)}` };
const config = exportConfig(env)!;
const now = Date.parse("2026-11-12T18:00:00.000Z");
const row = ["2026-11-12T17:59:00.000Z", "11111111-1111-4111-8111-111111111111", "employees", "GET", "nonproduction", "http_access_denied", 403];
const names = ["occurred_at", "invocation_id", "function_name", "method", "environment", "event", "status"];
const result = (rows: unknown[][] = [row]) => ({ tables: [{ name: "PrimaryResult", columns: names.map(name => ({ name })), rows }] });

test("export is default Off and production cannot be commissioned by this implementation", () => {
  assert.equal(exportConfig({}), null);
  assert.throws(() => exportConfig({ ...env, PLATFORM_ENVIRONMENT: "production" }), /EXPORT_ENVIRONMENT/);
});
test("configuration rejects URL credential forwarding and query injection", () => {
  const credentialUrl = new URL(env.CAREOPS_SECURITY_INGESTION_ENDPOINT);
  credentialUrl.username = "fixture";
  credentialUrl.password = "not-a-real-credential";
  for (const url of ["http://fictional.eastus-1.ingest.monitor.azure.com", "https://attacker.test", `${env.CAREOPS_SECURITY_INGESTION_ENDPOINT}/extra`, credentialUrl.href]) {
    assert.throws(() => exportConfig({ ...env, CAREOPS_SECURITY_INGESTION_ENDPOINT: url }), /EXPORT_ENDPOINT/);
  }
  assert.throws(() => exportConfig({ ...env, CAREOPS_SECURITY_SOURCE_RESOURCE_ID: `${env.CAREOPS_SECURITY_SOURCE_RESOURCE_ID}\n| union SecretTable` }), /EXPORT_SOURCE/);
  assert.throws(() => exportConfig({ ...env, CAREOPS_SECURITY_DCR_IMMUTABLE_ID: "../other" }), /EXPORT_RULE/);
});

test("Azure Direct DCR endpoints are accepted without widening URL boundaries", () => {
  const direct = "https://fictional-eastus2.logs.z1.ingest.monitor.azure.com";
  assert.equal(exportConfig({ ...env, CAREOPS_SECURITY_INGESTION_ENDPOINT: `${direct}/` })?.endpoint, direct);
  for (const endpoint of [
    `${direct}.attacker.test`, `${direct}:8443`, `${direct}/extra`, `${direct}?query=1`,
    `${direct}#fragment`, direct.replace("https:", "http:"),
    direct.replace(".z1.", ".evil."), direct.replace(".logs.", ".other."),
  ]) assert.throws(() => exportConfig({ ...env, CAREOPS_SECURITY_INGESTION_ENDPOINT: endpoint }), /EXPORT_ENDPOINT/);
});
test("source query projects approved fields with independent resource and environment filters", () => {
  const query = exportQuery(config);
  assert.ok(query.startsWith(`app("${config.source}").traces\n| where timestamp > ago(15m)`));
  assert.ok(query.includes("parse_json(message)"));
  // Kusto parses ISO strings as dynamic datetimes and tostring expands them to
  // seven fractional digits. Normalize the query output to the strict JS contract.
  assert.ok(query.includes('occurred_at=strcat(format_datetime(todatetime(E.occurred_at), "yyyy-MM-dd"), "T", format_datetime(todatetime(E.occurred_at), "HH:mm:ss.fff"), "Z")'));
  assert.ok(!query.includes("AppTraces"));
  assert.ok(query.includes('tostring(E.environment) == "nonproduction"'));
  assert.ok(query.endsWith("| take 501"));
  assert.ok(!query.includes("project Message"));
});
test("projection has stable IDs and removes exact duplicates", () => {
  const rows = projectQueryResult(result([row, [...row]]), config, now);
  assert.equal(rows.length, 1); assert.match(rows[0].EventId, /^[a-f0-9]{64}$/);
  assert.equal(rows[0].EventId, projectQueryResult(result(), config, now)[0].EventId);
  assert.deepEqual(Object.keys(rows[0]).sort(), ["TimeGenerated", "EventId", "Schema", "SourceResourceId", "InvocationId", "FunctionName", "Method", "Environment", "EventKind", "Status"].sort());
  const changed = [...row]; changed[2] = "clients";
  assert.notEqual(rows[0].EventId, projectQueryResult(result([changed]), config, now)[0].EventId);
});
test("malformed, partial and oversized query results never become an ingestion payload", () => {
  for (const data of [null, { ...result(), error: { message: "private" } }, { tables: [] }, { tables: [...result().tables, ...result().tables] }]) {
    assert.throws(() => projectQueryResult(data, config, now), /EXPORT_QUERY_SHAPE/);
  }
  const data = result(); data.tables[0].columns.push({ name: "private_content" });
  assert.throws(() => projectQueryResult(data, config, now), /EXPORT_QUERY_COLUMNS/);
  assert.throws(() => projectQueryResult(result(Array.from({ length: 501 }, () => row)), config, now), /EXPORT_OVERFLOW/);
});
test("wrong event/status, private field values, invalid dates and wrong environment reject the whole batch", () => {
  for (const [index, value] of [[0, "2026-02-30T17:59:00.000Z"], [0, "2025-01-01T00:00:00.000Z"], [1, "private-user"], [2, "employees/private-name"], [3, "GET\nprivate"], [4, "production"], [5, "http_service_unavailable"], [6, "403"], [6, 200]] as [number, unknown][]) {
    const bad = [...row] as unknown[]; bad[index] = value;
    assert.throws(() => projectQueryResult(result([row, bad]), config, now), /EXPORT_ROW_INVALID/);
  }
  assert.throws(() => projectQueryResult(result([[...row, "private"]]), config, now), /EXPORT_ROW_SHAPE/);
});
test("conflicting copies of one event are rejected rather than silently choosing a winner", () => {
  const changed = [...row]; changed[3] = "POST";
  assert.throws(() => projectQueryResult(result([row, changed]), config, now), /EXPORT_EVENT_CONFLICT/);
});
test("disabled export and an empty query avoid all unnecessary token and send work", async () => {
  const forbidden = async () => { throw new Error("unexpected network"); };
  assert.deepEqual(await exportSecurityHttpEvents({}, { token: forbidden, fetch: forbidden }), { accepted: 0 });
  let tokens = 0, requests = 0;
  const output = await exportSecurityHttpEvents(env, {
    token: async () => { tokens++; return "fictional"; },
    fetch: async () => { requests++; return new Response(JSON.stringify(result([])), { status: 200 }); },
  }, now);
  assert.deepEqual(output, { accepted: 0 }); assert.equal(tokens, 1); assert.equal(requests, 1);
});
test("keyless transport scopes tokens and refuses redirects with only the projection sent", async () => {
  const scopes: string[] = []; const bodies: string[] = [];
  const output = await exportSecurityHttpEvents(env, {
    token: async scope => { scopes.push(scope); return "fictional-token"; },
    fetch: async (url, options) => {
      assert.equal(options?.redirect, "error"); assert.ok(options?.signal);
      bodies.push(options?.body as string);
      if (bodies.length === 1) {
        assert.ok(String(url).startsWith("https://api.loganalytics.azure.com/v1/subscriptions/"));
        return new Response(JSON.stringify(result()), { status: 200 });
      }
      assert.ok(String(url).includes(`/streams/Custom-CareOpsSecurityHttp?api-version=2023-01-01`));
      return new Response(null, { status: 204 });
    },
  }, now);
  assert.deepEqual(scopes, ["https://api.loganalytics.io/.default", "https://monitor.azure.com/.default"]);
  assert.deepEqual(output, { accepted: 1 });
  assert.deepEqual(JSON.parse(bodies[1]), projectQueryResult(result(), config, now));
});
test("provider failures make one attempt and never expose provider bodies as diagnostics", async () => {
  let attempts = 0;
  await assert.rejects(exportSecurityHttpEvents(env, { token: async () => "fictional", fetch: async () => {
    attempts++; return new Response("private provider details", { status: 403 });
  } }, now), /EXPORT_QUERY_HTTP/);
  assert.equal(attempts, 1);
  assert.equal(safeExportError(new Error("private provider details")), "EXPORT_FAILED");
  assert.equal(safeExportError(new Error("EXPORT_QUERY_HTTP")), "EXPORT_QUERY_HTTP");
});

test("ingestion failures are not accepted or retried and invalid JSON is not forwarded", async () => {
  let requests = 0;
  await assert.rejects(exportSecurityHttpEvents(env, { token: async () => "fictional", fetch: async () => {
    requests++;
    return requests === 1 ? new Response(JSON.stringify(result()), { status: 200 }) : new Response("private details", { status: 429 });
  } }, now), /EXPORT_INGEST_HTTP/);
  assert.equal(requests, 2);
  requests = 0;
  await assert.rejects(exportSecurityHttpEvents(env, { token: async () => "fictional", fetch: async () => {
    requests++; return new Response("not-json", { status: 200 });
  } }, now), /EXPORT_QUERY_JSON/);
  assert.equal(requests, 1);
});

test("compiled exporter timer is Off by default and cannot register in production", () => {
  const isolation = JSON.parse(readFileSync(resolve(process.cwd(), "examples/nonproduction-isolation.json"), "utf8")).api;
  assert.equal(isolation.CAREOPS_SECURITY_EXPORT_ENABLED, "false");
  assert.equal(isolation.CAREOPS_SECURITY_EVENT_LOGGING_ENABLED, "false");
  assert.equal(isolation["AzureWebJobs.securityHttpExport.Disabled"], "true");
  const script = `
    const { app } = require('@azure/functions');
    let count = 0;
    app.timer = (name, options) => {
      if (name !== 'securityHttpExport' || options.schedule !== '0 */5 * * * *'
        || options.runOnStartup !== false || options.useMonitor !== true) throw new Error('timer policy');
      count++;
    };
    app.http = () => { throw new Error('unexpected HTTP registration'); };
    require(process.argv[1]);
    process.stdout.write(String(count));
  `;
  for (const [setting, environment, count] of [[undefined, "nonproduction", "0"], ["true", "production", "0"], ["TRUE", "nonproduction", "0"], ["true", "nonproduction", "1"]]) {
    const childEnv: NodeJS.ProcessEnv = { ...process.env, PLATFORM_ENVIRONMENT: environment };
    if (setting === undefined) delete childEnv[EXPORT_SETTING]; else childEnv[EXPORT_SETTING] = setting;
    const child = spawnSync(process.execPath, ["-e", script, require.resolve("../functions/securityhttpexport")], { env: childEnv, encoding: "utf8", timeout: 15_000 });
    assert.equal(child.status, 0, "isolated timer registration must complete");
    assert.equal(child.stdout, count);
  }
});
