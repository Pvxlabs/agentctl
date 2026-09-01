# agentctl Agent Skill

This skill is workflow guidance for Codex, Claude Code, Cursor Agent, and
other coding or deployment agents. It is not the security boundary. The
security boundary is the target middleware verifier, machine identity, and
the target project's domain authority.

## Required workflow

1. Discover `.agent-control.yaml` from the current directory or an explicit
   path.
2. Run `agentctl capabilities --manifest .agent-control.yaml` and select one
   named action whose method, route, audience, and scope match the intended
   operation.
3. Use `agentctl call --action <name>` for the exact action. Supply the exact
   request body and path parameters; do not construct a different route by
   hand.
4. Treat `AUTHORIZED` as authorization evidence and `EXECUTED` as transport
   response receipt only. Do not claim that a business operation succeeded
   unless the target project's response and canonical readback prove it.
5. After a mutation, perform the target project's canonical readback through
   its normal API and record the domain result separately.

## Prohibited shortcuts

- Do not read browser cookies or reuse a human browser session.
- Do not simulate CSRF or request an administrator password.
- Do not obtain or store database credentials.
- Do not mutate a target database directly.
- Do not map a machine principal to a fake human user.
- Do not bypass the target project's authentication, business authorization,
  validation, transaction, or readback authority.
- Do not put private keys or secrets in `.agent-control.yaml`.

If the manifest has no exact action for the intended request, stop and report
the missing contract. Do not broaden a scope or invent a wildcard.
