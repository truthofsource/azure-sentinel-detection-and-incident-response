import { app } from "@azure/functions";
import { ManagedIdentityCredential } from "@azure/identity";
import { DELIVERY_SETTING, deliveryConfig, deliverSecurityEvents, safeDeliveryError } from "../reference/securityDurableDelivery";
import { azureDeliveryPorts } from "../reference/securityDeliveryAzure";

if (process.env[DELIVERY_SETTING] === "true") {
  // Config failure is logged by this timer, never made a staff HTTP dependency.
  app.timer("securityHttpDelivery", { schedule: "0 */5 * * * *", useMonitor: true, runOnStartup: false,
    handler: async (_timer, context) => {
      try {
        const config = deliveryConfig(process.env);
        if (!config) return;
        const credential = new ManagedIdentityCredential();
        const result = await deliverSecurityEvents(config,
          azureDeliveryPorts(config, process.env.CAREOPS_SECURITY_DELIVERY_ACCOUNT_NAME ?? "", credential));
        context.log(JSON.stringify({ schema: "careops.security.delivery.v1", environment: config.environment, ...result }));
      } catch (error) {
        context.error(JSON.stringify({ schema: "careops.security.delivery.v1", outcome: "failed", code: safeDeliveryError(error) }));
      }
    },
  });
}
