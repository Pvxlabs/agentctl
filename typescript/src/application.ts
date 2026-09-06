import type { TrustedIdentityVerifier, TransportObservation } from "./trusted.js";

export interface AgentctlPrincipal {
  issuer: string;
  subject: string;
  principalType: "human" | "agent" | "observer";
  scopes: string[];
  audience: string;
  environment: string;
  authMethod: "trusted_dev";
  transport: string;
  assertionId: string;
  hasScope(scope: string): boolean;
  requireScope(scope: string): void;
}

function withScopeMethods(value: Omit<AgentctlPrincipal, "hasScope" | "requireScope">): AgentctlPrincipal {
  return {
    ...value,
    hasScope: (scope) => value.scopes.includes(scope),
    requireScope: (scope) => {
      if (!value.scopes.includes(scope)) throw new ApplicationAuthorizationError("SCOPE_DENIED", "application scope is not granted to the trusted principal");
    },
  };
}

export class ApplicationAuthorizationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "ApplicationAuthorizationError";
    this.code = code;
  }
}

export interface ApplicationAdapter<TApplicationPrincipal> {
  establish(principal: AgentctlPrincipal): TApplicationPrincipal;
}

export type CustomApplicationAdapter<TApplicationPrincipal> = ApplicationAdapter<TApplicationPrincipal>;

export interface MappedApplicationPrincipal {
  applicationIdentity: string;
  trustedPrincipal: AgentctlPrincipal;
  subject: string;
  scopes: string[];
  hasScope(scope: string): boolean;
  requireScope(scope: string): void;
}

export class DeclarativeMappingAdapter implements ApplicationAdapter<MappedApplicationPrincipal> {
  private readonly mappings: Record<string, string>;

  constructor(mappings: Record<string, string>) {
    if (mappings === null || typeof mappings !== "object" || Array.isArray(mappings)) {
      throw new ApplicationAuthorizationError("APPLICATION_ADAPTER_INVALID", "application adapter mappings must be an object");
    }
    this.mappings = {};
    for (const [subject, applicationIdentity] of Object.entries(mappings)) {
      if (subject.trim() !== subject || subject.length === 0 || typeof applicationIdentity !== "string" || applicationIdentity.trim() !== applicationIdentity || applicationIdentity.length === 0) {
        throw new ApplicationAuthorizationError("APPLICATION_ADAPTER_INVALID", "application adapter mappings must use trimmed non-empty strings");
      }
      this.mappings[subject] = applicationIdentity;
    }
  }

  establish(principal: AgentctlPrincipal): MappedApplicationPrincipal {
    const applicationIdentity = this.mappings[principal.subject];
    if (typeof applicationIdentity !== "string" || applicationIdentity.trim().length === 0) {
      throw new ApplicationAuthorizationError("APPLICATION_IDENTITY_MAPPING_MISSING", `no application identity mapping exists for trusted subject ${principal.subject}`);
    }
    return {
      applicationIdentity: applicationIdentity.trim(),
      trustedPrincipal: principal,
      subject: principal.subject,
      scopes: [...principal.scopes],
      hasScope: (scope) => principal.hasScope(scope),
      requireScope: (scope) => principal.requireScope(scope),
    };
  }
}

export interface ApplicationAuthentication<TApplicationPrincipal> {
  agentctlPrincipal: AgentctlPrincipal;
  applicationPrincipal: TApplicationPrincipal;
}

export class TrustedAccessSDK<TApplicationPrincipal> {
  constructor(private readonly verifier: TrustedIdentityVerifier, private readonly adapter: ApplicationAdapter<TApplicationPrincipal>) {}

  verify(assertion: string, input: { observation: TransportObservation; now: number }): AgentctlPrincipal {
    const principal = this.verifier.verifyPrincipal(assertion, input);
    return withScopeMethods(principal as Omit<AgentctlPrincipal, "hasScope" | "requireScope">);
  }

  establish(principal: AgentctlPrincipal): TApplicationPrincipal {
    return this.adapter.establish(principal);
  }

  authenticate(assertion: string, input: { observation: TransportObservation; now: number }): TApplicationPrincipal {
    return this.authenticateWithContext(assertion, input).applicationPrincipal;
  }

  authenticateWithContext(assertion: string, input: { observation: TransportObservation; now: number }): ApplicationAuthentication<TApplicationPrincipal> {
    const agentctlPrincipal = this.verify(assertion, input);
    return { agentctlPrincipal, applicationPrincipal: this.establish(agentctlPrincipal) };
  }

  authenticateHandoffWithContext(assertion: string, now: number): ApplicationAuthentication<TApplicationPrincipal> {
    const agentctlPrincipal = this.verifier.verifyHandoffPrincipal(assertion, now);
    return { agentctlPrincipal, applicationPrincipal: this.establish(agentctlPrincipal) };
  }

  authenticateHandoff(assertion: string, now: number): TApplicationPrincipal {
    return this.authenticateHandoffWithContext(assertion, now).applicationPrincipal;
  }

  static requireScope(principal: AgentctlPrincipal, scope: string): void {
    principal.requireScope(scope);
  }
}

export function extractTrustedAssertion(authorizationHeader: string | undefined, scheme = "Agentctl-Trusted"): string {
  if (typeof authorizationHeader !== "string") throw new Error("missing trusted identity assertion");
  const separator = authorizationHeader.indexOf(" ");
  const token = separator >= 0 ? authorizationHeader.slice(separator + 1) : "";
  if (separator < 0 || authorizationHeader.slice(0, separator) !== scheme || !token || /\s/u.test(token)) {
    throw new Error(`expected ${scheme} assertion`);
  }
  return token;
}
