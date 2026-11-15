import test from "node:test";
import assert from "node:assert/strict";
import type { ManagedIdentityCredential } from "@azure/identity";
import { blobStateStore, azureDeliveryPorts, retryDelay } from "./securityDeliveryAzure";
import { deliveryConfig, initialState, DeliveryTransientError, SOURCES } from "./securityDurableDelivery";

const config = deliveryConfig({ CAREOPS_SECURITY_DURABLE_ENABLED: "true", PLATFORM_ENVIRONMENT: "production",
  CAREOPS_SECURITY_SOURCE_RESOURCE_ID: SOURCES.production, CAREOPS_SECURITY_INGESTION_ENDPOINT: "https://fictional.logs.z1.ingest.monitor.azure.com",
  CAREOPS_SECURITY_DCR_IMMUTABLE_ID: `dcr-${"a".repeat(32)}`, CAREOPS_SECURITY_DELIVERY_START_UTC: "2026-11-13T17:50:00.000Z" })!;
const state = initialState(config, Date.parse("2026-11-13T18:00:00Z"));
function fakeBlob() {
  let data = Buffer.from("null"), etag = "v1", held = false, owned = false, release = 0, renew = 0;
  const writes: string[] = [];
  const lease = { leaseId: "owned-lease", acquireLease: async (duration: number) => {
    assert.equal(duration, 60); if (held) throw { code: "LeaseAlreadyPresent" }; held = true; owned = true;
  }, renewLease: async () => { renew++; if (!owned) throw { code: "LeaseIdMismatchWithLeaseOperation" }; },
    releaseLease: async () => { release++; held = false; } };
  const blob = {
    getBlobLeaseClient: () => lease,
    uploadData: async (bytes: Buffer, options: { conditions: { ifNoneMatch?: string; ifMatch?: string; leaseId?: string } }) => {
      if (options.conditions.ifNoneMatch) throw { code: "ConditionNotMet" };
      assert.equal(options.conditions.leaseId, lease.leaseId);
      if (options.conditions.ifMatch !== etag) throw { code: "ConditionNotMet" };
      if (!owned) throw { code: "LeaseIdMismatchWithBlobOperation" };
      writes.push(etag); data = Buffer.from(bytes); etag += "n"; return { etag };
    },
    getProperties: async (options: { conditions: { leaseId: string } }) => {
      assert.equal(options.conditions.leaseId, lease.leaseId); return { etag, contentLength: data.length };
    },
    downloadToBuffer: async (_offset: number, _length: number, options: { conditions: { ifMatch: string; leaseId: string } }) => {
      assert.equal(options.conditions.ifMatch, etag); assert.equal(options.conditions.leaseId, lease.leaseId); return data;
    },
  };
  return { blob: blob as unknown as Parameters<typeof blobStateStore>[0], writes,
    get renew() { return renew; }, get release() { return release; }, get data() { return JSON.parse(data.toString()); },
    loseLease() { owned = false; }, changeETag() { etag = "another-owner-version"; },
    set held(value: boolean) { held = value; }, corrupt() { data = Buffer.from("private invalid json"); } };
}

test("the blob adapter leases, renews and uses the latest ETag on every write", async () => {
  const f = fakeBlob(); const store = blobStateStore(f.blob);
  await store(async s => { assert.equal(s.state, null); await s.save(state); await s.save({ ...state, windowMs: 1000 }); });
  assert.deepEqual(f.writes, ["v1", "v1n"]); assert.equal(f.renew, 2); assert.equal(f.release, 1); assert.equal(f.data.windowMs, 1000);
});
test("another owner is skipped; lost ownership refuses writes; both failure paths preserve data", async () => {
  const f = fakeBlob(), store = blobStateStore(f.blob); f.held = true;
  assert.equal(await store(async () => { throw Error("must not run"); }), null);
  f.held = false;
  await assert.rejects(store(async s => { f.loseLease(); await s.save(state); }));
  assert.equal(f.data, null); assert.equal(f.writes.length, 0); assert.equal(f.release, 1);
});
test("malformed saved JSON fails closed and still releases ownership", async () => {
  const f = fakeBlob(); f.corrupt();
  await assert.rejects(blobStateStore(f.blob)(async () => undefined), /STATE_JSON/); assert.equal(f.release, 1);
});
test("a changed ETag refuses a stale checkpoint even if the caller retains an old lease handle", async () => {
  const f = fakeBlob();
  await assert.rejects(blobStateStore(f.blob)(async s => { f.changeETag(); await s.save(state); }), e => (e as { code?: string }).code === "ConditionNotMet");
  assert.equal(f.writes.length, 0); assert.equal(f.data, null); assert.equal(f.release, 1);
});
test("HTTP adapters pin destinations/scopes and never follow redirects or include private fields", async () => {
  const scopes: string[] = [], requests: { url: string; options: RequestInit }[] = [];
  const credential = { getToken: async (scope: string) => { scopes.push(scope); return { token: "fictional-token", expiresOnTimestamp: Date.now() + 60000 }; } } as unknown as ManagedIdentityCredential;
  const request = (async (url: string, options: RequestInit) => { requests.push({ url, options }); return url.includes("/query") ? new Response('{"tables":[]}', { status: 200 }) : new Response(null, { status: 204 }); }) as typeof fetch;
  const ports = azureDeliveryPorts(config, "platformfunctionprod01", credential, request);
  assert.deepEqual(await ports.query("allowlisted query"), { tables: [] }); assert.equal(await ports.send([]), 204);
  assert.deepEqual(scopes, ["https://api.loganalytics.io/.default", "https://monitor.azure.com/.default"]);
  assert.equal(requests[0].url, `https://api.loganalytics.azure.com/v1${config.source}/query`);
  assert.ok(requests[1].url.startsWith(config.endpoint + "/dataCollectionRules/"));
  for (const r of requests) { assert.equal(r.options.redirect, "error"); assert.ok(r.options.signal); }
  assert.throws(() => azureDeliveryPorts(config, "stplatformfuncnp001", credential, request), /STORAGE_SCOPE/);
});
test("throttling carries bounded retry advice; permanent response bodies are never read", async () => {
  const credential = { getToken: async () => ({ token: "fictional", expiresOnTimestamp: Date.now() + 60000 }) } as unknown as ManagedIdentityCredential;
  const response = (status: number) => (async () => new Response("private provider body", { status, headers: { "Retry-After": "1800" } })) as typeof fetch;
  await assert.rejects(azureDeliveryPorts(config, "platformfunctionprod01", credential, response(429)).query("q"), e => e instanceof DeliveryTransientError && e.retryAfterMs === 1_800_000);
  await assert.rejects(azureDeliveryPorts(config, "platformfunctionprod01", credential, response(403)).send([]), { message: "DELIVERY_INGEST_REJECTED" });
  assert.equal(retryDelay("9999999"), 3_600_000); assert.equal(retryDelay("invalid"), 0);
  assert.equal(retryDelay("Fri, 13 Nov 2026 18:01:00 GMT", Date.parse("2026-11-13T18:00:00Z")), 60000);
});
test("oversized query responses cannot be interpreted as successful batches", async () => {
  const credential = { getToken: async () => ({ token: "fictional", expiresOnTimestamp: Date.now() + 60000 }) } as unknown as ManagedIdentityCredential;
  const request = (async () => new Response("a".repeat(1_000_001))) as typeof fetch;
  await assert.rejects(azureDeliveryPorts(config, "platformfunctionprod01", credential, request).query("q"), /QUERY_SIZE/);
});
