import { createHash } from "node:crypto";
import { projectQueryResult, type SecurityProjection } from "./securityHttpExport";

export const DELIVERY_SETTING = "CAREOPS_SECURITY_DURABLE_ENABLED";
export const SOURCES = {
  nonproduction: "/subscriptions/22222222-2222-4222-8222-222222222222/resourceGroups/rg-application-nonproduction-eastus2/providers/Microsoft.Insights/components/appi-application-nonproduction-eastus2-001",
  production: "/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/rg-application-production-centralus/providers/Microsoft.Insights/components/appi-application-production-centralus-001",
} as const;
export type DeliveryConfig = { source: string; environment: keyof typeof SOURCES; endpoint: string; rule: string; start: string; binding: string };
export type DeliveryState = {
  version: 1; binding: string; cursor: string; windowMs: number;
  pending: null | { end: string; rows: SecurityProjection[] };
  attempts: number; nextAttempt: string | null; blocked: boolean; error: string | null; lastAccepted: string | null;
};
export type StateSession = { state: unknown; save: (state: DeliveryState) => Promise<void> };
export type DeliveryPorts = {
  exclusive: <T>(run: (session: StateSession) => Promise<T>) => Promise<T | null>;
  query: (kql: string) => Promise<unknown>;
  send: (rows: readonly SecurityProjection[]) => Promise<number>;
  clock: () => number;
};
const DAY = 86_400_000;
/** Provider throttling advice is bounded; no provider text enters persisted state. */
export class DeliveryTransientError extends Error {
  constructor(code: "DELIVERY_QUERY_TRANSIENT" | "DELIVERY_INGEST_TRANSIENT", readonly retryAfterMs = 0) { super(code); }
}
const columns = ["occurred_at", "invocation_id", "function_name", "method", "environment", "event", "status"];
const fail = (code: string): never => { throw new Error("DELIVERY_" + code); };
function iso(value: unknown): value is string {
  return typeof value === "string" && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value)
    && Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
export function deliveryConfig(env: NodeJS.ProcessEnv): DeliveryConfig | null {
  if (env[DELIVERY_SETTING] !== "true") return null;
  if (env.CAREOPS_SECURITY_EXPORT_ENABLED === "true") fail("DUAL_COLLECTORS");
  const environment = env.PLATFORM_ENVIRONMENT;
  if (environment !== "production" && environment !== "nonproduction") return fail("ENVIRONMENT");
  const source = SOURCES[environment].toLowerCase();
  if (env.CAREOPS_SECURITY_SOURCE_RESOURCE_ID?.toLowerCase() !== source) fail("SOURCE");
  const endpoint = env.CAREOPS_SECURITY_INGESTION_ENDPOINT ?? "";
  if (!/^https:\/\/(?:[a-z0-9-]+\.[a-z0-9-]+|[a-z0-9-]+\.logs\.z[0-9]+)\.ingest\.monitor\.azure\.com\/?$/.test(endpoint)) fail("ENDPOINT");
  const rule = env.CAREOPS_SECURITY_DCR_IMMUTABLE_ID ?? "";
  if (!/^dcr-[a-f0-9]{32}$/.test(rule)) fail("RULE");
  const start = env.CAREOPS_SECURITY_DELIVERY_START_UTC;
  if (!iso(start)) return fail("START");
  const normalized = endpoint.replace(/\/$/, "");
  const binding = createHash("sha256").update(JSON.stringify([source, environment, normalized, rule, start])).digest("hex");
  return { source, environment, endpoint: normalized, rule, start, binding };
}
export function initialState(config: DeliveryConfig, now: number): DeliveryState {
  if (Date.parse(config.start) > now || Date.parse(config.start) < now - DAY) fail("BOOTSTRAP_RANGE");
  return { version: 1, binding: config.binding, cursor: config.start, windowMs: 300_000,
    pending: null, attempts: 0, nextAttempt: null, blocked: false, error: null, lastAccepted: null };
}
function exactKeys(value: object, keys: string[]): boolean {
  return Object.keys(value).sort().join("|") === [...keys].sort().join("|");
}
export function validateState(value: unknown, config: DeliveryConfig, now: number): DeliveryState {
  if (!value || typeof value !== "object" || !exactKeys(value, ["version", "binding", "cursor", "windowMs", "pending", "attempts", "nextAttempt", "blocked", "error", "lastAccepted"])) return fail("STATE");
  const s = value as DeliveryState;
  if (s.version !== 1 || s.binding !== config.binding || !iso(s.cursor) || s.cursor < config.start
    || Date.parse(s.cursor) > now || !Number.isSafeInteger(s.windowMs) || s.windowMs < 1000 || s.windowMs > 300_000
    || !Number.isSafeInteger(s.attempts) || s.attempts < 0 || s.attempts > 8 || typeof s.blocked !== "boolean"
    || s.nextAttempt !== null && !iso(s.nextAttempt) || s.lastAccepted !== null && (!iso(s.lastAccepted) || Date.parse(s.lastAccepted) > now)
    || s.error !== null && !/^DELIVERY_[A-Z_]{1,40}$/.test(s.error)) fail("STATE");
  if (s.attempts === 0 && (s.nextAttempt !== null || s.error !== null || s.blocked)
    || s.attempts > 0 && (s.error === null || !s.blocked && s.nextAttempt === null)
    || s.blocked && s.nextAttempt !== null || s.attempts === 8 && !s.blocked) fail("STATE");
  if (s.pending !== null) {
    const p = s.pending;
    if (!p || typeof p !== "object" || !exactKeys(p, ["end", "rows"]) || !iso(p.end)
      || p.end <= s.cursor || Date.parse(p.end) - Date.parse(s.cursor) > s.windowMs
      || Date.parse(p.end) > now || !Array.isArray(p.rows) || p.rows.length < 1 || p.rows.length > 500) fail("PENDING");
    const names = ["TimeGenerated", "EventId", "Schema", "SourceResourceId", "InvocationId", "FunctionName", "Method", "Environment", "EventKind", "Status"];
    for (const row of p.rows) if (!row || typeof row !== "object" || !exactKeys(row, names)) fail("PENDING");
    const checked = projectQueryResult({ tables: [{ columns: columns.map(name => ({ name })), rows: p.rows.map(r => [r.TimeGenerated, r.InvocationId, r.FunctionName, r.Method, r.Environment, r.EventKind, r.Status]) }] }, config, now, config.environment);
    if (checked.length !== p.rows.length || Buffer.byteLength(JSON.stringify(p.rows)) > 500_000) fail("PENDING");
    for (let i = 0; i < checked.length; i++) for (const k of names) {
      if ((checked[i] as unknown as Record<string, unknown>)[k] !== (p.rows[i] as unknown as Record<string, unknown>)[k]) fail("PENDING");
    }
  }
  return s;
}
export function deliveryQuery(config: DeliveryConfig, start: number, end: number): string {
  if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || start < Date.parse(config.start) || end - start > 360_000) fail("QUERY_RANGE");
  const from = new Date(start).toISOString(), through = new Date(end).toISOString();
  return `app("${config.source}").traces
| where timestamp >= datetime(${from}) - 1d and timestamp < datetime(${through}) + 2m
| extend Ingested=ingestion_time()
| where (Ingested >= datetime(${from}) and Ingested < datetime(${through})) or isnull(Ingested)
| where message contains "careops.security.http.v1"
| extend E=parse_json(message)
| where tostring(E.schema) == "careops.security.http.v1" and tostring(E.environment) == "${config.environment}"
| project occurred_at=strcat(format_datetime(todatetime(E.occurred_at), "yyyy-MM-dd"), "T", format_datetime(todatetime(E.occurred_at), "HH:mm:ss.fff"), "Z"), invocation_id=tostring(E.invocation_id), function_name=iff(isnull(Ingested), "", tostring(E.function_name)), method=tostring(E.method), environment=tostring(E.environment), event=tostring(E.event), status=toint(E.status)
| take 501`;
}
export function safeDeliveryError(error: unknown): string {
  const code = error instanceof Error ? error.message : "";
  if (/^DELIVERY_[A-Z_]{1,40}$/.test(code)) return code;
  if (/^EXPORT_(?:QUERY|ROW|EVENT|OVERFLOW)/.test(code)) return "DELIVERY_SOURCE_INVALID";
  return "DELIVERY_TRANSPORT";
}
function retryable(code: string): boolean {
  return ["DELIVERY_TRANSPORT", "DELIVERY_QUERY_TRANSIENT", "DELIVERY_INGEST_TRANSIENT"].includes(code);
}
export type DeliveryOutcome = { outcome: "idle" | "progress" | "backoff" | "blocked" | "busy"; accepted: number; cursor?: string; attempts?: number; pending?: number; code?: string; lastAccepted?: string | null; retryAt?: string | null; checkpointAgeSeconds?: number };

/** Independent timer; leased persistent outbox. At least once, not an audit ledger. */
export async function deliverSecurityEvents(config: DeliveryConfig, ports: DeliveryPorts): Promise<DeliveryOutcome> {
  const began = ports.clock();
  const output = await ports.exclusive(async session => {
    let state = session.state === null ? initialState(config, ports.clock()) : validateState(session.state, config, ports.clock());
    if (session.state === null) await session.save(state);
    let accepted = 0;
    const report = (outcome: DeliveryOutcome["outcome"]): DeliveryOutcome => ({ outcome, accepted, cursor: state.cursor,
      attempts: state.attempts, pending: state.pending?.rows.length ?? 0, lastAccepted: state.lastAccepted, retryAt: state.nextAttempt,
      checkpointAgeSeconds: Math.max(0, Math.floor((ports.clock() - Date.parse(state.cursor)) / 1000)), ...(state.error ? { code: state.error } : {}) });
    if (state.blocked) return report("blocked");
    if (state.nextAttempt && Date.parse(state.nextAttempt) > ports.clock()) return report("backoff");
    for (let step = 0; step < 6 && ports.clock() - began < 35_000; step++) {
      try {
        const now = ports.clock();
        if (Date.parse(state.cursor) < now - DAY) fail("RECOVERY_RANGE");
        if (!state.pending) {
          const end = Math.min(Date.parse(state.cursor) + state.windowMs, now - 300_000);
          if (end <= Date.parse(state.cursor)) return report(accepted ? "progress" : "idle");
          const start = Math.max(Date.parse(config.start), Date.parse(state.cursor) - Math.min(60_000, Math.floor(state.windowMs / 2)));
          const data = await ports.query(deliveryQuery(config, start, end));
          let rows: SecurityProjection[];
          try { rows = projectQueryResult(data, config, ports.clock(), config.environment); }
          catch (error) {
            if (error instanceof Error && error.message === "EXPORT_OVERFLOW") {
              if (state.windowMs === 1000) fail("DENSE_WINDOW");
              state = { ...state, windowMs: Math.max(1000, Math.floor(state.windowMs / 2)) };
              await session.save(state); continue;
            }
            throw error;
          }
          if (!rows.length) {
            state = { ...state, cursor: new Date(end).toISOString(), attempts: 0, nextAttempt: null, error: null, windowMs: 300_000 };
            await session.save(state); continue;
          }
          if (Buffer.byteLength(JSON.stringify(rows)) > 500_000) fail("PAYLOAD_SIZE");
          state = { ...state, pending: { end: new Date(end).toISOString(), rows } };
          await session.save(state);
        }
        const pending = state.pending;
        if (!pending) return fail("PENDING");
        if (await ports.send(pending.rows) !== 204) fail("INGEST_REJECTED");
        accepted += pending.rows.length;
        const next: DeliveryState = { ...state, cursor: pending.end, pending: null, attempts: 0, nextAttempt: null,
          error: null, lastAccepted: new Date(ports.clock()).toISOString(), windowMs: 300_000 };
        await session.save(next); state = next;
      } catch (error) {
        const code = safeDeliveryError(error), attempts = Math.min(8, state.attempts + 1);
        const blocked = !retryable(code) || attempts >= 8;
        const jitter = parseInt(config.binding.slice(0, 4), 16) % 30_000;
        const advice = error instanceof DeliveryTransientError && Number.isFinite(error.retryAfterMs)
          ? Math.max(0, Math.min(3_600_000, error.retryAfterMs)) : 0;
        state = { ...state, attempts, blocked, error: code,
          nextAttempt: blocked ? null : new Date(ports.clock() + Math.max(advice, Math.min(3_600_000, 300_000 * 2 ** (attempts - 1))) + jitter).toISOString() };
        await session.save(state);
        return report(blocked ? "blocked" : "backoff");
      }
    }
    return report("progress");
  });
  return output ?? { outcome: "busy", accepted: 0 };
}
