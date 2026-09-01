# Verifier SDK Contract

Target middleware should pass the following values without reserialization:

```text
assertion
HTTP method
request target
exact transmitted body bytes
content type
X-Agentctl-Request-ID
optional resource identifier
```

The verifier returns the machine principal, the one authorized scope, and
request-bound evidence. The target application remains responsible for
domain authentication, business authorization, validation, transaction
handling, and canonical readback.
