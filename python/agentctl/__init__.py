"""agentctl protocol and verifier package."""

__version__ = "0.1.0"
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
    TailscaleTransportVerifier,
    TransportObservation,
    TrustedAccessAuthority,
    TrustedAccessConfig,
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
    DeclarativeMappingAdapter,
    MappedApplicationPrincipal,
    TrustedAccessSDK,
    extract_trusted_assertion,
)
