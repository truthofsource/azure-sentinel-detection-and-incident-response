import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { InvocationContext, PostInvocationContext } from "@azure/functions";
import { observeSecurityHttpResult, securityHttpEvent, SECURITY_HTTP_SETTING } from "./securityHttpEvents";

const id = "11111111-1111-4111-8111-111111111111";
const enabled = { [SECURITY_HTTP_SETTING]: "true", PLATFORM_ENVIRONMENT: "nonproduction" };
const date = new Date("2026-11-12T18:00:00Z");
function sample(status: unknown = 403) {
  return new PostInvocationContext({
    invocationContext: new InvocationContext({ invocationId: id, functionName: "employees",
      options: { trigger: { type: "httpTrigger", name: "request" } } }),
    inputs: [{ method: "GET" }], result: { status },
  });
}

test("logging is absent by default and requires the exact opt-in", () => {
  for (const value of [undefined, "false", "TRUE", "1", " true "]) {
    assert.equal(securityHttpEvent(sample(), { [SECURITY_HTTP_SETTING]: value }, date), null);
  }
});
test("401 and 403 are observed HTTP denials, not inferred password or MFA failures", () => {
  for (const status of [401, 403]) {
    const event = securityHttpEvent(sample(status), enabled, date)!;
    assert.equal(event.event, "http_access_denied"); assert.equal(event.status, status);
    assert.equal(event.occurred_at, date.toISOString()); assert.equal(event.invocation_id, id);
    assert.deepEqual(Object.keys(event).sort(), ["schema", "occurred_at", "invocation_id", "function_name", "method", "environment", "event", "status"].sort());
  }
});
test("503 is availability evidence without an invented root cause", () => {
  assert.equal(securityHttpEvent(sample(503), enabled, date)?.event, "http_service_unavailable");
});
test("success, other errors and malformed statuses are not security events", () => {
  for (const status of [200, 201, 400, 404, 429, 500, "403", null, undefined, NaN]) {
    const context = sample(); context.result = { status };
    assert.equal(securityHttpEvent(context, enabled, date), null);
  }
});
test("timer/queue invocations do not enter the HTTP schema", () => {
  const context = sample(); context.invocationContext.options.trigger.type = "timerTrigger";
  assert.equal(securityHttpEvent(context, enabled, date), null);
});
test("credentials, paths, bodies and error payloads are never read or copied", () => {
  const context = sample(); const forbidden = () => { throw new Error("private-content-must-not-be-read"); };
  const input = { method: "POST" };
  for (const name of ["url", "headers", "body", "query", "params"]) Object.defineProperty(input, name, { get: forbidden });
  context.inputs = [input];
  const result = { status: 403 };
  for (const name of ["body", "jsonBody", "headers"]) Object.defineProperty(result, name, { get: forbidden });
  context.result = result;
  Object.defineProperty(context, "error", { get: forbidden });
  const event = securityHttpEvent(context, enabled, date)!;
  assert.equal(event.method, "POST"); assert.ok(!JSON.stringify(event).includes("private"));
});
test("unrecognized methods and environment values cannot inject log data", () => {
  const context = sample(); context.inputs = [{ method: "GET\nsecret" }];
  const event = securityHttpEvent(context, { ...enabled, PLATFORM_ENVIRONMENT: "private-tenant-label" }, date)!;
  assert.equal(event.method, "OTHER"); assert.equal(event.environment, "unknown");
});
test("invalid invocation identifiers and function labels are rejected", () => {
  const context = sample(); context.invocationContext.invocationId = "private-value";
  assert.equal(securityHttpEvent(context, enabled, date), null);
  context.invocationContext.invocationId = id; context.invocationContext.functionName = "employee/private-name";
  assert.equal(securityHttpEvent(context, enabled, date), null);
});
test("independent invocations keep their own status and function without shared actor state", async () => {
  const outputs = await Promise.all([401, 403, 503].map(async status => {
    const context = sample(status); context.invocationContext.functionName = `route${status}`;
    return securityHttpEvent(context, enabled, date)!;
  }));
  assert.deepEqual(outputs.map(e => [e.function_name, e.status]), [["route401",401],["route403",403],["route503",503]]);
});
test("observer uses invocation logging and preserves handler result even if logging fails", () => {
  const previous = process.env[SECURITY_HTTP_SETTING]; process.env[SECURITY_HTTP_SETTING] = "true";
  try {
    const context = sample(); const result = context.result; const lines: string[] = [];
    context.invocationContext.log = line => { lines.push(line); };
    observeSecurityHttpResult(context); assert.equal(JSON.parse(lines[0]).status, 403);
    context.invocationContext.log = () => { throw new Error("private transport failure"); };
    assert.doesNotThrow(() => observeSecurityHttpResult(context)); assert.equal(context.result, result);
  } finally {
    if (previous === undefined) delete process.env[SECURITY_HTTP_SETTING]; else process.env[SECURITY_HTTP_SETTING] = previous;
  }
});

test("compiled startup registers exactly one observation only for true, without adding an HTTP function", () => {
  // Isolate module caches/environment between cases. Intercept registration, not
  // Azure host behavior: this proves package wiring, not hosted log delivery.
  const script = `
    const { app } = require('@azure/functions');
    const { observeSecurityHttpResult } = require(process.argv[2]);
    let count = 0;
    app.hook.postInvocation = handler => {
      if (handler !== observeSecurityHttpResult) throw new Error('unexpected handler');
      count++;
      return { dispose() {} };
    };
    app.http = () => { throw new Error('unexpected HTTP registration'); };
    require(process.argv[1]);
    require(process.argv[1]);
    process.stdout.write(String(count));
  `;
  for (const setting of [undefined, "false", "TRUE", "1", "true"]) {
    const environment = { ...process.env };
    if (setting === undefined) delete environment[SECURITY_HTTP_SETTING];
    else environment[SECURITY_HTTP_SETTING] = setting;
    const child = spawnSync(process.execPath,
      ["-e", script, require.resolve("../functions/securitytelemetry"), require.resolve("./securityHttpEvents")],
      { env: environment, encoding: "utf8", timeout: 10_000 });
    assert.equal(child.status, 0, "isolated startup must complete");
    assert.equal(child.stdout, setting === "true" ? "1" : "0");
  }
});
