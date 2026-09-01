import { verifyAgentRequest, type Registry } from "@agentctl/verifier";

export function verifyRequest(input: {
  authorizationHeader: string;
  requestIdHeader?: string;
  method: string;
  target: string;
  body: Uint8Array;
  contentType?: string;
  registry: Registry;
  replayStore: { consume(jti: string, expiresAt: number, now: number): boolean };
  environment: string;
  audience: string;
  now: number;
}) {
  const [scheme, assertion] = input.authorizationHeader.split(" ", 2);
  if (scheme !== "Agentctl" || !assertion) throw new Error("missing Agentctl assertion");
  return verifyAgentRequest({
    assertion,
    request: {
      method: input.method,
      target: input.target,
      body: input.body,
      contentType: input.contentType,
      requestId: input.requestIdHeader,
    },
    registry: input.registry,
    replayStore: input.replayStore,
    expectedAudience: input.audience,
    expectedEnvironment: input.environment,
    now: input.now,
  });
}
