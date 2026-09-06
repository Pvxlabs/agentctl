---
name: agentctl
description: Integrate agentctl Trusted Access into a project for DEV identity establishment and passwordless AI-agent testing.
metadata:
  short-description: Onboard a project to agentctl Trusted Access
  agentctl_min_version: "0.1.1"
  skill_version: "1.1.0"
  trusted_access_onboarding_version: "1.1"
---

# agentctl Trusted Access

Use this skill when the user asks to integrate agentctl Trusted Access, DEV
passwordless access, or AI-agent testing into a project.

## Workflow

1. Identify the target project and check `agentctl --version`.
2. If agentctl is missing or below `0.1.1`, install the canonical pinned release
   from `https://github.com/Pvxlabs/agentctl` using the documented user-local
   installer path. Do not install from an unpinned branch.
3. Run `agentctl trusted-access onboard --plan`.
4. Read only the reported application-specific blockers. If identity bootstrap
   is required, the application owns the public seam
   `agentctl_trusted_access_adapter.py:adapter` and maps neutral subjects to
   its normal DEV identities.
5. Run `agentctl trusted-access onboard` and stop only when the output
   contains `TRUSTED_ACCESS_READY=YES`.

The application must keep its normal sessions, roles, CSRF checks, and
authorization. agentctl establishes a trusted DEV principal; it does not turn
off authentication or create application accounts.

## Boundaries

- Do not redesign authentication, authorization, crypto, transport, or runtime.
- Do not read or request DEV passwords, browser cookies, or database credentials.
- Do not manually create accounts when the application adapter owns that work.
- Do not modify production, tailnet ACLs, or deployment infrastructure.
- Do not redo host qualification or add a reverse proxy.
- Do not read agentctl internals to guess a consumer integration; use the
  public onboarding CLI and adapter contract.
