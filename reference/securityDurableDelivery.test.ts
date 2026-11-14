import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { deliveryConfig, initialState, validateState, deliveryQuery, deliverSecurityEvents, safeDeliveryError, SOURCES, DeliveryTransientError,
  type DeliveryPorts, type DeliveryState, type DeliveryConfig } from "./securityDurableDelivery";

const now = Date.parse("2026-11-13T18:00:00.000Z");
const env = { CAREOPS_SECURITY_DURABLE_ENABLED: "true", PLATFORM_ENVIRONMENT: "production", CAREOPS_SECURITY_SOURCE_RESOURCE_ID: SOURCES.production,
  CAREOPS_SECURITY_INGESTION_ENDPOINT: "https://fictional.logs.z1.ingest.monitor.azure.com", CAREOPS_SECURITY_DCR_IMMUTABLE_ID: `dcr-${"a".repeat(32)}`,
  CAREOPS_SECURITY_DELIVERY_START_UTC: "2026-11-13T17:50:00.000Z" };
const config = deliveryConfig(env)!;
const names = ["occurred_at", "invocation_id", "function_name", "method", "environment", "event", "status"];
const row = ["2026-11-13T17:51:00.000Z", "11111111-1111-4111-8111-111111111111", "roleCheck", "GET", "production", "http_access_denied", 401];
const result = (rows: unknown[][] = [row]) => ({ tables: [{ columns: names.map(name => ({ name })), rows }] });
function fixture(c: DeliveryConfig = config) {
  let stored: unknown = null, clock = now, queries = 0, sends = 0;
  const saves: DeliveryState[] = [], ids: string[][] = [];
  const ports: DeliveryPorts = {
    clock: () => clock,
    exclusive: async run => run({ state: structuredClone(stored), save: async value => { stored = structuredClone(value); saves.push(structuredClone(value)); } }),
    query: async () => { queries++; return result(); },
    send: async rows => { sends++; ids.push(rows.map(r => r.EventId)); return 204; },
  };
  return { c, ports, saves, ids, get state() { return stored as DeliveryState; }, set state(v: DeliveryState) { stored = structuredClone(v); },
    get queries() { return queries; }, get sends() { return sends; }, set time(v: number) { clock = v; } };
}
test("durable collection is default Off, exact-source bound and cannot run alongside the pilot", () => {
  assert.equal(deliveryConfig({}), null);
  assert.throws(() => deliveryConfig({ ...env, CAREOPS_SECURITY_EXPORT_ENABLED: "true" }), /DUAL_COLLECTORS/);
  assert.throws(() => deliveryConfig({ ...env, CAREOPS_SECURITY_SOURCE_RESOURCE_ID: SOURCES.nonproduction }), /SOURCE/);
  assert.throws(() => deliveryConfig({ ...env, CAREOPS_SECURITY_INGESTION_ENDPOINT: "https://attacker.test" }), /ENDPOINT/);
  assert.throws(() => deliveryConfig({ ...env, CAREOPS_SECURITY_DELIVERY_START_UTC: "yesterday" }), /START/);
  assert.throws(() => initialState(config, now + 2 * 86_400_000), /BOOTSTRAP_RANGE/);
});
test("the query separates ingestion selection from original event time and projects only approved fields", () => {
  const q = deliveryQuery(config, Date.parse(config.start), now - 300_000);
  assert.ok(q.includes("ingestion_time()")); assert.ok(q.includes('tostring(E.environment) == "production"'));
  assert.ok(q.includes(config.source)); assert.ok(q.endsWith("take 501")); assert.ok(!q.includes("project message"));
  assert.ok(q.includes('function_name=iff(isnull(Ingested), ""'));
  assert.throws(() => deliveryQuery(config, 0, now), /QUERY_RANGE/);
});
test("outbox is durable before send and checkpoint advances only after explicit 204", async () => {
  const f = fixture();
  f.ports.send = async rows => {
    assert.ok(f.state.pending); assert.deepEqual(f.state.pending.rows, rows); assert.equal(f.state.cursor, config.start); return 204;
  };
  const out = await deliverSecurityEvents(config, f.ports);
  assert.equal(out.accepted, 1); assert.equal(f.state.cursor, "2026-11-13T17:55:00.000Z"); assert.equal(f.state.pending, null);
  assert.equal(f.state.lastAccepted, new Date(now).toISOString());
});
test("uncertain acceptance survives restart and replays the same IDs before any new query", async () => {
  const f = fixture(); let sends = 0; const batches: string[][] = [];
  f.ports.send = async rows => { batches.push(rows.map(r => r.EventId)); if (++sends === 1) throw new Error("socket lost after possible acceptance"); return 204; };
  const first = await deliverSecurityEvents(config, f.ports); assert.equal(first.outcome, "backoff");
  assert.equal(f.state.cursor, config.start); assert.ok(f.state.pending); assert.equal(f.queries, 1);
  const due = Date.parse(f.state.nextAttempt!);
  f.time = due - 1; assert.equal((await deliverSecurityEvents(config, f.ports)).outcome, "backoff"); assert.equal(sends, 1);
  // At the retry instant, use a one-step clock budget after send to avoid catch-up queries.
  let timeCalls = 0; f.ports.clock = () => due + (++timeCalls > 4 ? 40_000 : 0);
  f.ports.query = async () => { throw new Error("pending replay must precede query"); };
  await deliverSecurityEvents(config, f.ports);
  assert.equal(sends, 2); assert.deepEqual(batches[0], batches[1]); assert.equal(f.state.pending, null);
});
test("permanent rejection retains the original batch and blocks instead of silently skipping it", async () => {
  const f = fixture(); f.ports.send = async () => { throw new Error("DELIVERY_INGEST_REJECTED"); };
  const out = await deliverSecurityEvents(config, f.ports); assert.equal(out.outcome, "blocked"); assert.ok(f.state.pending);
  assert.equal(f.state.cursor, config.start); f.ports.send = async () => { throw new Error("unexpected retry"); };
  assert.equal((await deliverSecurityEvents(config, f.ports)).outcome, "blocked");
});
test("transient query failure cannot advance the cursor and stops after the bounded retry count", async () => {
  const f = fixture(); f.ports.query = async () => { throw new Error("DELIVERY_QUERY_TRANSIENT"); };
  for (let n = 1; n <= 8; n++) {
    const out = await deliverSecurityEvents(config, f.ports); assert.equal(f.state.attempts, n); assert.equal(f.state.cursor, config.start);
    assert.equal(out.outcome, n === 8 ? "blocked" : "backoff"); if (f.state.nextAttempt) f.time = Date.parse(f.state.nextAttempt);
  }
});
test("overflow reduces windows without advancing or sending; dense windows stop visibly", async () => {
  const f = fixture(); f.ports.query = async () => result(Array.from({ length: 501 }, () => row));
  await deliverSecurityEvents(config, f.ports); assert.equal(f.state.cursor, config.start); assert.equal(f.sends, 0);
  const out = await deliverSecurityEvents(config, f.ports); assert.equal(out.outcome, "blocked"); assert.equal(out.code, "DELIVERY_DENSE_WINDOW");
  assert.equal(f.state.cursor, config.start);
});
test("wrong-environment data blocks the whole batch without storing or sending it", async () => {
  const f = fixture(); const bad = [...row]; bad[4] = "nonproduction"; f.ports.query = async () => result([row, bad]);
  const out = await deliverSecurityEvents(config, f.ports); assert.equal(out.outcome, "blocked"); assert.equal(f.state.pending, null); assert.equal(f.sends, 0);
});
test("foreign/corrupt state, changed target, and extra private fields are refused", () => {
  const s = initialState(config, now);
  for (const bad of [{ ...s, binding: "other" }, { ...s, private_note: "private" }, { ...s, cursor: "not-date" }, { ...s, attempts: -1 }]) {
    assert.throws(() => validateState(bad, config, now), /STATE/);
  }
  assert.equal(safeDeliveryError(new Error("private provider message")), "DELIVERY_TRANSPORT");
});
test("expired recovery bound halts without querying or silently resetting", async () => {
  const f = fixture(); f.state = initialState(config, now); f.time = now + 86_400_000;
  const out = await deliverSecurityEvents(config, f.ports); assert.equal(out.code, "DELIVERY_RECOVERY_RANGE"); assert.equal(f.queries, 0);
});
test("busy lease holder is respected without source query or send", async () => {
  const f = fixture(); f.ports.exclusive = async () => null;
  assert.equal((await deliverSecurityEvents(config, f.ports)).outcome, "busy"); assert.equal(f.queries, 0); assert.equal(f.sends, 0);
});
test("state persistence failure never claims successful ingestion", async () => {
  const f = fixture(); f.ports.exclusive = async run => run({ state: null, save: async () => { throw new Error("lost lease"); } });
  await assert.rejects(deliverSecurityEvents(config, f.ports), /lost lease/); assert.equal(f.sends, 0);
});

test("a crash after acceptance but before checkpoint replays the persisted batch without loss", async () => {
  const f = fixture(); let crash = true; const sendIds: string[][] = [];
  f.ports.exclusive = async run => run({ state: structuredClone(f.state ?? null), save: async s => {
    if (crash && s.lastAccepted) throw Error("checkpoint connection lost");
    if (crash && s.attempts) throw Error("process terminated");
    f.state = s;
  } });
  f.ports.send = async rows => { sendIds.push(rows.map(r => r.EventId)); return 204; };
  await assert.rejects(deliverSecurityEvents(config, f.ports), /terminated/);
  assert.equal(f.state.cursor, config.start); assert.ok(f.state.pending); crash = false;
  await deliverSecurityEvents(config, f.ports);
  assert.deepEqual(sendIds[0], sendIds[1]); assert.equal(f.state.pending, null);
});

test("a pending outbox is not sent if its persistence failed, and retry advice is respected", async () => {
  const f = fixture(); f.ports.exclusive = async run => run({ state: null, save: async s => { if (s.pending) throw Error("unavailable store"); f.state = s; } });
  await assert.rejects(deliverSecurityEvents(config, f.ports)); assert.equal(f.sends, 0);
  const g = fixture(); g.ports.query = async () => { throw new DeliveryTransientError("DELIVERY_QUERY_TRANSIENT", 1_800_000); };
  await deliverSecurityEvents(config, g.ports); assert.ok(Date.parse(g.state.nextAttempt!) >= now + 1_800_000);
});
test("timer defaults Off, has no HTTP route and registers without network when opted in", () => {
  const script = `const {app}=require('@azure/functions');let n=0;app.timer=(name,o)=>{if(name!=='securityHttpDelivery'||o.schedule!=='0 */5 * * * *'||o.runOnStartup!==false||o.useMonitor!==true)throw Error('policy');n++;};app.http=()=>{throw Error('HTTP');};require(process.argv[1]);process.stdout.write(String(n));`;
  for (const [flag,count] of [["false","0"],["true","1"]]) {
    const r = spawnSync(process.execPath, ["-e", script, resolve("dist/functions/securityhttpdelivery.js")],
      { env: { ...process.env, CAREOPS_SECURITY_DURABLE_ENABLED: flag }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr); assert.equal(r.stdout, count);
  }
});
