# Express Trusted Development Access Example

This is a runnable, DEV-only TypeScript reference integration. It verifies the
dedicated `Agentctl-Trusted` assertion, maps application-neutral subjects to
example Express identities, and keeps normal application scope checks active.

## Run

Install the agentctl CLI and build the SDK package before installing the
example dependencies:

```bash
python3 -m pip install -e .
pnpm --dir typescript install
pnpm --dir typescript build
cd examples/trusted-access-express
pnpm install
agentctl trusted-access validate --manifest .agent-control.yaml
agentctl identity create --principal-id dev-authority --display-name "DEV Authority" --environment dev --key-id dev-authority-key --out .agentctl/dev-authority.json
agentctl principals add --identity-file .agentctl/dev-authority.json --registry-file .agentctl/registry.json
pnpm build
pnpm start
```

The example already includes its manifest, so the commands above create only
the local DEV authority state and do not overwrite the manifest. For a new
project, `agentctl trusted-access init --path <project>` creates the manifest,
authority state, and integration guide; it refuses to replace an existing
manifest unless `--force` is explicitly supplied. The example uses an in-memory
replay store for clarity; production integrations must provide a durable atomic
`ReplayStore`.

The `/health` route is unprotected. `/me` requires `app:read` and `/admin`
requires `app:admin`. A real app should obtain assertions from a controlled DEV
authority path; do not expose an unrestricted `principal=admin` endpoint.

## Tailscale

Set `AGENTCTL_TRANSPORT=tailscale` only for a server reached over Tailscale.
This example injects a deterministic server-side resolver map so it can run
without a Node LocalAPI dependency:

```bash
AGENTCTL_TAILSCALE_PEERS_JSON='{"100.90.1.2":"node:dev-laptop"}' \
AGENTCTL_TRANSPORT=tailscale \
pnpm start
```

The resolver callback is a test/example seam, not proof supplied by the
client. A production Node deployment must perform the Tailscale LocalAPI (or
equivalent authenticated server-side lookup) before passing the observed peer
identity to the SDK. Forwarding headers and a bare `100.x.x.x` address are not
accepted as proof.
