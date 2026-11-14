import { app } from "@azure/functions";
import { observeSecurityHttpResult, SECURITY_HTTP_SETTING } from "../reference/securityHttpEvents";

// Existing application logs/SQL audit remain authoritative for their own scope.
// This opt-in observation adds no HTTP route, collector, identity or response action.
if (process.env[SECURITY_HTTP_SETTING] === "true") {
  app.hook.postInvocation(observeSecurityHttpResult);
}
