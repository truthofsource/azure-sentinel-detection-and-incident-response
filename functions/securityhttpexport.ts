import { app } from "@azure/functions";
import { ManagedIdentityCredential } from "@azure/identity";
import { EXPORT_SETTING, exportSecurityHttpEvents, safeExportError } from "../reference/securityHttpExport";

if (process.env[EXPORT_SETTING] === "true" && process.env.PLATFORM_ENVIRONMENT === "nonproduction") {
  const credential = new ManagedIdentityCredential();
  app.timer("securityHttpExport", {
    schedule: "0 */5 * * * *", useMonitor: true, runOnStartup: false,
    handler: async (_timer, context) => {
      try {
        const result = await exportSecurityHttpEvents(process.env, {
          token: async (scope, signal) => {
            const token = await credential.getToken(scope, { abortSignal: signal });
            if (!token?.token) throw new Error("EXPORT_TOKEN");
            return token.token;
          }, fetch,
        });
        context.log(JSON.stringify({ schema: "careops.security.export.v1", outcome: "accepted", accepted: result.accepted }));
      } catch (error) {
        context.error(JSON.stringify({ schema: "careops.security.export.v1", outcome: "failed", code: safeExportError(error) }));
      }
    },
  });
}
