import type { PostInvocationContext } from "@azure/functions";

export const SECURITY_HTTP_SCHEMA = "careops.security.http.v1";
export const SECURITY_HTTP_SETTING = "CAREOPS_SECURITY_EVENT_LOGGING_ENABLED";

export type SecurityHttpEvent = {
  schema: typeof SECURITY_HTTP_SCHEMA;
  occurred_at: string;
  invocation_id: string;
  function_name: string;
  method: string;
  environment: "production" | "nonproduction" | "local" | "unknown";
  event: "http_access_denied" | "http_service_unavailable";
  status: 401 | 403 | 503;
};

const methods = new Set(["GET", "POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS"]);

/** Metadata only: never inspect URL, headers, claims, bodies, errors or response content. */
export function securityHttpEvent(
  context: PostInvocationContext,
  environment: NodeJS.ProcessEnv = process.env,
  now = new Date()
): SecurityHttpEvent | null {
  if (environment[SECURITY_HTTP_SETTING] !== "true") return null;
  const invocation = context.invocationContext;
  if (invocation.options.trigger.type !== "httpTrigger") return null;
  if (!/^[a-zA-Z][a-zA-Z0-9_]{0,79}$/.test(invocation.functionName)
    || !/^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$/i.test(invocation.invocationId)) return null;
  const result = context.result;
  if (!result || typeof result !== "object") return null;
  const status: unknown = (result as { status?: unknown }).status;
  if (status !== 401 && status !== 403 && status !== 503) return null;
  const input = context.inputs[0];
  const method = input && typeof input === "object" ? (input as { method?: unknown }).method : undefined;
  const selectedEnvironment = environment.PLATFORM_ENVIRONMENT;
  return {
    schema: SECURITY_HTTP_SCHEMA,
    occurred_at: now.toISOString(),
    invocation_id: invocation.invocationId.toLowerCase(),
    function_name: invocation.functionName,
    method: typeof method === "string" && methods.has(method) ? method : "OTHER",
    environment: selectedEnvironment === "production" || selectedEnvironment === "nonproduction" || selectedEnvironment === "local"
      ? selectedEnvironment : "unknown",
    event: status === 503 ? "http_service_unavailable" : "http_access_denied",
    status,
  };
}

/** A supplemental observation must not alter the handler result or its audit enforcement. */
export function observeSecurityHttpResult(context: PostInvocationContext): void {
  try {
    const event = securityHttpEvent(context);
    if (event) context.invocationContext.log(JSON.stringify(event));
  } catch {
    // No raw error fallback: it can expose content or turn logging into an outage.
    // Delivery/sampling/collector health require independent acceptance.
  }
}
