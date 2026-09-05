import { ApplicationAuthorizationError, extractTrustedAssertion, type TrustedAccessSDK } from "../application.js";
import type { AgentctlPrincipal } from "../application.js";
import type { TransportObservation } from "../trusted.js";

export interface ExpressTrustedRequest {
  method: string;
  headers: Record<string, string | string[] | undefined>;
  socket: { remoteAddress?: string };
  agentctlPrincipal?: AgentctlPrincipal;
  applicationPrincipal?: unknown;
}

export interface ExpressTrustedResponse {
  status(code: number): ExpressTrustedResponse;
  json(body: unknown): void;
}

export type ExpressNext = (error?: unknown) => void;

export function createExpressTrustedAccessMiddleware<TApplicationPrincipal>(
  sdk: TrustedAccessSDK<TApplicationPrincipal>,
  options: { transport?: string; now?: () => number; authorizationHeaderName?: string; authorizationScheme?: string } = {},
) {
  const transport = options.transport ?? "localhost";
  const now = options.now ?? (() => Math.floor(Date.now() / 1000));
  const headerName = (options.authorizationHeaderName ?? "authorization").toLowerCase();
  const scheme = options.authorizationScheme ?? "Agentctl-Trusted";
  return (req: ExpressTrustedRequest, res: ExpressTrustedResponse, next: ExpressNext): void => {
    try {
      const rawHeader = req.headers[headerName];
      const authorization = Array.isArray(rawHeader) ? rawHeader[0] : rawHeader;
      const assertion = extractTrustedAssertion(authorization, scheme);
      const forwardedHeadersPresent = ["forwarded", "x-forwarded-for", "x-real-ip"].some((name) => req.headers[name] !== undefined);
      const observation: TransportObservation = { transport, peerAddress: req.socket.remoteAddress, forwardedHeadersPresent };
      const context = sdk.authenticateWithContext(assertion, { observation, now: now() });
      req.agentctlPrincipal = context.agentctlPrincipal;
      req.applicationPrincipal = context.applicationPrincipal;
      next();
    } catch (error) {
      const code = error instanceof ApplicationAuthorizationError ? error.code : (error as { code?: string }).code ?? "TRUSTED_ACCESS_DENIED";
      const status = error instanceof ApplicationAuthorizationError ? 403 : 401;
      res.status(status).json({ error: "trusted_access_denied", code });
    }
  };
}
