import { ManagedIdentityCredential } from "@azure/identity";
import { BlobServiceClient, type BlockBlobClient } from "@azure/storage-blob";
import { DeliveryTransientError } from "./securityDurableDelivery";
import type { DeliveryConfig, DeliveryPorts, DeliveryState } from "./securityDurableDelivery";

const ACCOUNTS = { production: "platformfunctionprod01", nonproduction: "stplatformfuncnp001" } as const;
export const DELIVERY_CONTAINER = "security-http-delivery";
const code = (e: unknown) => typeof e === "object" && e !== null ? (e as { code?: unknown }).code : null;
const deadline = () => AbortSignal.timeout(5000);

/** One private blob atomically owns cursor and outbox. No keys or SAS fallback. */
export function azureStateStore(config: DeliveryConfig, account: string, credential: ManagedIdentityCredential): DeliveryPorts["exclusive"] {
  if (account !== ACCOUNTS[config.environment]) throw new Error("DELIVERY_STORAGE_SCOPE");
  const service = new BlobServiceClient(`https://${account}.blob.core.windows.net`, credential,
    { retryOptions: { maxTries: 1, tryTimeoutInMs: 5000 } });
  const blob = service.getContainerClient(DELIVERY_CONTAINER).getBlockBlobClient(`${config.environment}/state-v1.json`);
  return blobStateStore(blob);
}
/** SDK seam for concurrency/failure tests; runtime construction pins account/container. */
export function blobStateStore(blob: Pick<BlockBlobClient, "uploadData" | "getBlobLeaseClient" | "getProperties" | "downloadToBuffer">): DeliveryPorts["exclusive"] {
  return async run => {
    try { await blob.uploadData(Buffer.from("null"), { conditions: { ifNoneMatch: "*" }, abortSignal: deadline() }); }
    catch (error) { if (!["BlobAlreadyExists", "ConditionNotMet", "LeaseIdMissing"].includes(String(code(error)))) throw error; }
    const lease = blob.getBlobLeaseClient();
    try { await lease.acquireLease(60, { abortSignal: deadline() }); }
    catch (error) { if (code(error) === "LeaseAlreadyPresent") return null; throw error; }
    let completed = false;
    try {
      const properties = await blob.getProperties({ conditions: { leaseId: lease.leaseId }, abortSignal: deadline() });
      if (!properties.etag || properties.contentLength === undefined || properties.contentLength > 1_000_000) throw new Error("DELIVERY_STATE_SIZE");
      let etag = properties.etag;
      const data = await blob.downloadToBuffer(0, properties.contentLength,
        { conditions: { leaseId: lease.leaseId, ifMatch: etag }, abortSignal: deadline() });
      let state: unknown;
      try { state = JSON.parse(data.toString("utf8")); } catch { throw new Error("DELIVERY_STATE_JSON"); }
      const result = await run({ state, save: async (value: DeliveryState) => {
        const bytes = Buffer.from(JSON.stringify(value));
        if (bytes.length > 1_000_000) throw new Error("DELIVERY_STATE_SIZE");
        // Renew before every conditional write. A new owner's lease can never be adopted.
        await lease.renewLease({ abortSignal: deadline() });
        const response = await blob.uploadData(bytes, { conditions: { leaseId: lease.leaseId, ifMatch: etag },
          blobHTTPHeaders: { blobContentType: "application/json" }, abortSignal: deadline() });
        if (!response.etag) throw new Error("DELIVERY_STATE_ETAG");
        etag = response.etag;
      } });
      completed = true; return result;
    } finally {
      // Expiry/lost lease cannot authorize an old writer's conditional save.
      try { await lease.releaseLease({ abortSignal: deadline() }); }
      catch { if (completed) throw new Error("DELIVERY_LEASE_RELEASE"); }
    }
  };
}
async function jsonWithinLimit(response: Response): Promise<unknown> {
  if (!response.body) throw new Error("DELIVERY_QUERY_JSON");
  const reader = response.body.getReader(), chunks: Uint8Array[] = []; let size = 0;
  try {
    for (;;) {
      const next = await reader.read(); if (next.done) break;
      size += next.value.byteLength;
      if (size > 1_000_000) throw new Error("DELIVERY_QUERY_SIZE");
      chunks.push(next.value);
    }
  } finally { await reader.cancel().catch(() => undefined); reader.releaseLock(); }
  try { return JSON.parse(Buffer.concat(chunks).toString("utf8")); }
  catch { throw new Error("DELIVERY_QUERY_JSON"); }
}
export function retryDelay(header: string | null, now = Date.now()): number {
  if (header === null) return 0;
  const value = /^\d+$/.test(header) ? Number(header) * 1000 : Date.parse(header) - now;
  return Number.isFinite(value) ? Math.max(0, Math.min(3_600_000, value)) : 0;
}
export function azureDeliveryPorts(config: DeliveryConfig, account: string, credential: ManagedIdentityCredential, request: typeof fetch = fetch): DeliveryPorts {
  async function auth(scope: string, signal: AbortSignal): Promise<string> {
    const result = await credential.getToken(scope, { abortSignal: signal });
    if (!result?.token) throw new Error("DELIVERY_TOKEN");
    return result.token;
  }
  function status(response: Response, kind: "QUERY" | "INGEST"): never {
    if (response.status === 408 || response.status === 429 || response.status >= 500)
      throw new DeliveryTransientError(`DELIVERY_${kind}_TRANSIENT`, retryDelay(response.headers.get("Retry-After")));
    throw new Error(`DELIVERY_${kind}_REJECTED`);
  }
  return {
    exclusive: azureStateStore(config, account, credential), clock: Date.now,
    query: async query => {
      const signal = AbortSignal.timeout(10_000), token = await auth("https://api.loganalytics.io/.default", signal);
      const response = await request(`https://api.loganalytics.azure.com/v1${config.source}/query`, {
        method: "POST", redirect: "error", signal, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
        body: JSON.stringify({ query, timespan: "P2D" }),
      });
      if (response.status !== 200) status(response, "QUERY");
      return jsonWithinLimit(response);
    },
    send: async rows => {
      const signal = AbortSignal.timeout(10_000), token = await auth("https://monitor.azure.com/.default", signal);
      const response = await request(`${config.endpoint}/dataCollectionRules/${config.rule}/streams/Custom-CareOpsSecurityHttp?api-version=2023-01-01`, {
        method: "POST", redirect: "error", signal, headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: JSON.stringify(rows),
      });
      if (response.status !== 204) status(response, "INGEST");
      return 204;
    },
  };
}
