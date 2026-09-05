import express from "express";
import { readFileSync } from "node:fs";

import {
  DeclarativeMappingAdapter,
  MemoryReplayStore,
  TailscaleTransportVerifier,
  TrustedAccessSDK,
  TrustedIdentityVerifier,
  LocalhostTransportVerifier,
  type AgentctlPrincipal,
  type MappedApplicationPrincipal,
  type Registry,
  type TrustedAccessConfig,
} from "@agentctl/verifier";
import { createExpressTrustedAccessMiddleware } from "@agentctl/verifier/integrations/express.js";

declare global {
  namespace Express {
    interface Request {
      agentctlPrincipal?: AgentctlPrincipal;
      applicationPrincipal?: MappedApplicationPrincipal;
    }
  }
}

const config: TrustedAccessConfig = {
  enabled: true,
  environment: "dev",
  transports: ["localhost", "tailscale"],
  application: { identity: "trusted-access-express", audience: "trusted-access-express-dev" },
  adapter: {
    type: "declarative_mapping",
    mappings: {
      "dev-user": "express-dev-user",
      "dev-admin": "express-dev-admin",
      "dev-agent": "express-dev-agent",
    },
  },
  principals: {
    user: { name: "user", subject: "dev-user", principal_type: "human", scopes: ["app:read"] },
    admin: { name: "admin", subject: "dev-admin", principal_type: "human", scopes: ["app:read", "app:admin"] },
    agent: { name: "agent", subject: "dev-agent", principal_type: "agent", scopes: ["app:read", "app:test"] },
  },
};

const registry = JSON.parse(readFileSync(new URL("../.agentctl/registry.json", import.meta.url), "utf8")) as Registry;
// Example-only resolver injection. Production Node integrations must resolve
// the server-observed socket peer through Tailscale LocalAPI before the SDK.
const peerMap = JSON.parse(process.env.AGENTCTL_TAILSCALE_PEERS_JSON ?? "{}") as Record<string, string>;
const verifiers = {
  localhost: new LocalhostTransportVerifier(),
  tailscale: new TailscaleTransportVerifier((peerAddress) => peerMap[peerAddress]),
};
const verifier = new TrustedIdentityVerifier(registry, config, new MemoryReplayStore(), "trusted-access-express-dev", verifiers);
const sdk = new TrustedAccessSDK(verifier, new DeclarativeMappingAdapter(config.adapter?.mappings ?? {}));
const trustedMiddleware = createExpressTrustedAccessMiddleware(sdk, {
  transport: process.env.AGENTCTL_TRANSPORT ?? "localhost",
});

const app = express();

function requireApplicationScope(principal: AgentctlPrincipal | undefined, scope: string): void {
  if (!principal?.hasScope(scope)) {
    const error = new Error(`missing application scope ${scope}`) as Error & { statusCode?: number };
    error.statusCode = 403;
    throw error;
  }
}

app.get("/health", (_request, response) => response.json({ status: "ok" }));
app.get("/me", trustedMiddleware as express.RequestHandler, (request, response) => {
  requireApplicationScope(request.agentctlPrincipal, "app:read");
  response.json({
    applicationIdentity: (request.applicationPrincipal as { applicationIdentity: string }).applicationIdentity,
    subject: request.agentctlPrincipal?.subject,
    principalType: request.agentctlPrincipal?.principalType,
    scopes: request.agentctlPrincipal?.scopes,
    authMethod: request.agentctlPrincipal?.authMethod,
  });
});
app.get("/admin", trustedMiddleware as express.RequestHandler, (request, response) => {
  requireApplicationScope(request.agentctlPrincipal, "app:admin");
  response.json({ status: "admin-authorized" });
});
app.use((error: Error & { statusCode?: number }, _request: express.Request, response: express.Response, _next: express.NextFunction) => {
  response.status(error.statusCode ?? 500).json({ error: error.message });
});

app.listen(Number(process.env.PORT ?? 3000), "127.0.0.1", () => {
  console.log("agentctl Trusted Access Express example listening on http://127.0.0.1:3000");
});
