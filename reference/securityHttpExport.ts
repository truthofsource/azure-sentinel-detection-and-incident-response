import { createHash } from "node:crypto";
import { SECURITY_HTTP_SCHEMA } from "./securityHttpEvents";

export const EXPORT_SETTING = "CAREOPS_SECURITY_EXPORT_ENABLED";
export const EXPORT_STREAM = "Custom-CareOpsSecurityHttp";
const columns = ["occurred_at", "invocation_id", "function_name", "method", "environment", "event", "status"];
const uuid = /^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i;
const sourcePattern = /^\/subscriptions\/[a-f0-9-]{36}\/resourceGroups\/[a-zA-Z0-9_.()-]{1,90}\/providers\/Microsoft\.Insights\/components\/[a-zA-Z0-9_.()-]{1,260}$/i;

export type ExportConfig = { source: string; endpoint: string; rule: string };
export type SecurityProjection = {
  TimeGenerated: string; EventId: string; Schema: string; SourceResourceId: string;
  InvocationId: string; FunctionName: string; Method: string; Environment: "nonproduction" | "production";
  EventKind: string; Status: number;
};
export function exportConfig(env: NodeJS.ProcessEnv): ExportConfig | null {
  if (env[EXPORT_SETTING] !== "true") return null;
  // This commissioning implementation cannot export production events.
  if (env.PLATFORM_ENVIRONMENT !== "nonproduction") throw new Error("EXPORT_ENVIRONMENT");
  const source = env.CAREOPS_SECURITY_SOURCE_RESOURCE_ID ?? "";
  const endpoint = env.CAREOPS_SECURITY_INGESTION_ENDPOINT ?? "";
  const rule = env.CAREOPS_SECURITY_DCR_IMMUTABLE_ID ?? "";
  if (!sourcePattern.test(source)) throw new Error("EXPORT_SOURCE");
  // Direct DCR endpoints use <identifier>.logs.zN; DCE endpoints use
  // <identifier>.<region>. Both remain HTTPS-only in the Azure Monitor domain.
  if (!/^https:\/\/(?:[a-z0-9-]+\.[a-z0-9-]+|[a-z0-9-]+\.logs\.z[0-9]+)\.ingest\.monitor\.azure\.com\/?$/.test(endpoint)) throw new Error("EXPORT_ENDPOINT");
  if (!/^dcr-[a-f0-9]{32}$/i.test(rule)) throw new Error("EXPORT_RULE");
  return { source: source.toLowerCase(), endpoint: endpoint.replace(/\/$/, ""), rule };
}

export function exportQuery(config: ExportConfig): string {
  // The component query endpoint exposes the Application Insights namespace,
  // not workspace AppTraces. Scope both the request URL and app() explicitly.
  return `app("${config.source}").traces
| where timestamp > ago(15m)
| where message contains "${SECURITY_HTTP_SCHEMA}"
| extend E=parse_json(message)
| where tostring(E.schema) == "${SECURITY_HTTP_SCHEMA}" and tostring(E.environment) == "nonproduction"
| project occurred_at=strcat(format_datetime(todatetime(E.occurred_at), "yyyy-MM-dd"), "T", format_datetime(todatetime(E.occurred_at), "HH:mm:ss.fff"), "Z"), invocation_id=tostring(E.invocation_id), function_name=tostring(E.function_name), method=tostring(E.method), environment=tostring(E.environment), event=tostring(E.event), status=toint(E.status)
| take 501`;
}

export function projectQueryResult(result: unknown, config: ExportConfig, now = Date.now(), expectedEnvironment: "nonproduction" | "production" = "nonproduction"): SecurityProjection[] {
  const data = result as { error?: unknown; tables?: { name: string; columns: { name: string }[]; rows: unknown[][] }[] };
  if (!data || data.error || !Array.isArray(data.tables) || data.tables.length !== 1) throw new Error("EXPORT_QUERY_SHAPE");
  const table = data.tables[0];
  if (!Array.isArray(table.columns) || table.columns.map(c => c.name).join("|") !== columns.join("|") || !Array.isArray(table.rows)) throw new Error("EXPORT_QUERY_COLUMNS");
  if (table.rows.length > 500) throw new Error("EXPORT_OVERFLOW");
  const projected = new Map<string, SecurityProjection>();
  for (const row of table.rows) {
    if (!Array.isArray(row) || row.length !== columns.length) throw new Error("EXPORT_ROW_SHAPE");
    const [at, invocation, fn, method, environment, event, status] = row;
    if (typeof at !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(at)
      || !Number.isFinite(Date.parse(at)) || new Date(at).toISOString() !== at
      || Date.parse(at) < now - 86_400_000 || Date.parse(at) > now + 120_000
      || typeof invocation !== "string" || !uuid.test(invocation)
      || typeof fn !== "string" || !/^[a-zA-Z][a-zA-Z0-9_]{0,79}$/.test(fn)
      || typeof method !== "string" || !/^(GET|POST|PATCH|PUT|DELETE|HEAD|OPTIONS|OTHER)$/.test(method)
      || environment !== expectedEnvironment
      || !((status === 401 || status === 403) && event === "http_access_denied" || status === 503 && event === "http_service_unavailable")) throw new Error("EXPORT_ROW_INVALID");
    const key = `${config.source}|${invocation.toLowerCase()}|${fn}|${status}`;
    const EventId = createHash("sha256").update(key).digest("hex");
    const entry: SecurityProjection = { TimeGenerated: at, EventId, Schema: SECURITY_HTTP_SCHEMA,
      SourceResourceId: config.source, InvocationId: invocation.toLowerCase(), FunctionName: fn,
      Method: method, Environment: expectedEnvironment, EventKind: event as string, Status: status as number };
    const previous = projected.get(EventId);
    if (previous && JSON.stringify(previous) !== JSON.stringify(entry)) throw new Error("EXPORT_EVENT_CONFLICT");
    projected.set(EventId, entry);
  }
  return [...projected.values()];
}

type Dependencies = {
  token: (scope: string, signal: AbortSignal) => Promise<string>;
  fetch: typeof fetch;
};
export async function exportSecurityHttpEvents(env: NodeJS.ProcessEnv, dependencies: Dependencies, now = Date.now()): Promise<{ accepted: number }> {
  const config = exportConfig(env);
  if (!config) return { accepted: 0 };
  const querySignal = AbortSignal.timeout(10_000);
  const queryToken = await dependencies.token("https://api.loganalytics.io/.default", querySignal);
  const query = await dependencies.fetch(`https://api.loganalytics.azure.com/v1${config.source}/query`, {
    method: "POST", redirect: "error", signal: querySignal,
    headers: { Authorization: `Bearer ${queryToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query: exportQuery(config), timespan: "PT15M" }),
  });
  if (query.status !== 200) throw new Error("EXPORT_QUERY_HTTP");
  const text = await query.text();
  if (Buffer.byteLength(text) > 1_000_000) throw new Error("EXPORT_QUERY_SIZE");
  let data: unknown;
  try { data = JSON.parse(text); } catch { throw new Error("EXPORT_QUERY_JSON"); }
  const rows = projectQueryResult(data, config, now);
  if (!rows.length) return { accepted: 0 };
  const payload = JSON.stringify(rows);
  if (Buffer.byteLength(payload) > 500_000) throw new Error("EXPORT_PAYLOAD_SIZE");
  const sendSignal = AbortSignal.timeout(10_000);
  const token = await dependencies.token("https://monitor.azure.com/.default", sendSignal);
  const response = await dependencies.fetch(`${config.endpoint}/dataCollectionRules/${config.rule}/streams/${EXPORT_STREAM}?api-version=2023-01-01`, {
    method: "POST", redirect: "error", signal: sendSignal,
    headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }, body: payload,
  });
  // Accepted != queryable or acknowledged. Never log provider response bodies.
  if (response.status !== 204) throw new Error("EXPORT_INGEST_HTTP");
  return { accepted: rows.length };
}

export function safeExportError(error: unknown): string {
  const code = error instanceof Error ? error.message : "";
  return /^EXPORT_[A-Z_]{1,40}$/.test(code) ? code : "EXPORT_FAILED";
}
