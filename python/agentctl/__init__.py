"""agentctl protocol and verifier package."""

__version__ = "0.1.1"
__protocol_version__ = "agent-action-assertion/v1"

from .protocol import (  # noqa: F401
    ASSERTION_PREFIX,
    PROTOCOL_VERSION,
    AssertionErrorCode,
    ParsedAssertion,
    build_assertion,
    canonical_json_bytes,
    canonical_request_target,
    parse_assertion,
    serialize_assertion,
    sha256_hex,
)
from .trusted import (  # noqa: F401
    ATIP_PROTOCOL_NAME,
    ATIP_VERSION,
    ATIP_WIRE_VERSION,
    AgentctlPrincipal,
    LocalhostTransportVerifier,
    TAILSCALE_LOCALAPI_RESOLVER,
    TAILSCALE_LOCALAPI_SOCKET,
    TAILSCALE_SOCKET_PEER_INVARIANT,
    TailscaleLocalAPIClient,
    TailscaleLocalAPITransportVerifier,
    TailscalePeerIdentity,
    TailscalePeerPolicy,
    TailscaleTransportEvidence,
    TailscaleTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
    TrustedHandoffConfig,
    TrustedIngressConfig,
    TrustedIngressSurface,
    TrustedAdapterConfig,
    TrustedApplicationConfig,
    TrustedAccessError,
    TrustedIdentityEvidence,
    TrustedIdentityVerifier,
    TrustedPrincipalPolicy,
    TrustedTransportVerifier,
    establish_application_principal,
    is_dev_environment,
    parse_trusted_identity_assertion,
)
from .application import (  # noqa: F401
    ApplicationAdapter,
    ApplicationAdapterError,
    ApplicationAuthentication,
    ApplicationAuthorizationError,
    CustomApplicationAdapter,
    DevIdentityBootstrapAdapter,
    DeclarativeMappingAdapter,
    MappedApplicationPrincipal,
    TrustedAccessSDK,
    extract_trusted_assertion,
)
from .runtime import (  # noqa: F401
    DEFAULT_AUTHORITY_ID,
    DEFAULT_AUTHORITY_KEY_ID,
    RUNTIME_LAYOUT_VERSION,
    TrustedAccessRuntime,
    TrustedAccessRuntimePaths,
    default_runtime_dir,
)
from .onboarding import (  # noqa: F401
    DEFAULT_DEV_PROFILE,
    DevIdentityProfile,
    OnboardingError,
    build_onboarding_plan,
    format_onboarding,
    onboard,
)
