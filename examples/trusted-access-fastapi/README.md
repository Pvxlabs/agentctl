# FastAPI Trusted Development Access Example

This is a runnable, DEV-only reference integration. It maps application-neutral
subjects to example FastAPI identities and then keeps application scope checks
active. The `fastapi-dev-*` values are example application identities, not
agentctl core concepts.

## Run

From the repository root:

```bash
python3 -m venv /tmp/agentctl-fastapi-venv
/tmp/agentctl-fastapi-venv/bin/pip install -r examples/trusted-access-fastapi/requirements.txt
/tmp/agentctl-fastapi-venv/bin/pip install -e .
cd examples/trusted-access-fastapi
agentctl trusted-access validate --manifest .agent-control.yaml
agentctl identity create --principal-id dev-authority --display-name "DEV Authority" --environment dev --key-id dev-authority-key --out .agentctl/dev-authority.json
agentctl principals add --identity-file .agentctl/dev-authority.json --registry-file .agentctl/registry.json
/tmp/agentctl-fastapi-venv/bin/python app.py
```

The example already includes its manifest, so the commands above create only
the local DEV authority state and do not overwrite that manifest. For a new
project, `agentctl trusted-access init --path <project>` creates the manifest,
authority state, and integration guide; it refuses to replace an existing
manifest unless `--force` is explicitly supplied.

The app exposes `/health` without Trusted Access and protects `/me` and
`/admin` with `Agentctl-Trusted <assertion>`. A real app should obtain the
assertion from a controlled DEV authority endpoint or local agentctl identity;
do not publish an unrestricted endpoint that accepts `principal=admin`.

## Tailscale

Set `AGENTCTL_TRANSPORT=tailscale` only when the server is actually reached via
Tailscale. The demo resolver reads a server-owned JSON map from
`AGENTCTL_TAILSCALE_PEERS_JSON`, for example:

```bash
AGENTCTL_TAILSCALE_PEERS_JSON='{"100.90.1.2":"node:dev-laptop"}' \
AGENTCTL_TRANSPORT=tailscale \
/tmp/agentctl-fastapi-venv/bin/python examples/trusted-access-fastapi/app.py
```

This map is only a runnable stand-in. Production deployments must replace it
with a server-side Tailscale LocalAPI or equivalent authenticated peer resolver.
Forwarded headers and a bare `100.x.x.x` address are rejected.
