# Distribution and Discovery

The canonical public source is `https://github.com/Pvxlabs/agentctl`, branch
`main`. Consumer installations use a versioned tag, currently `v0.1.1`; the
tag, Python package version, and `agentctl --version` output are one contract.

## User-local installation

```bash
python3 -m pip install --user "git+https://github.com/Pvxlabs/agentctl.git@v0.1.1"
agentctl --version
agentctl skill install --update
```

This is non-interactive, does not require root, and does not require cloning
the repository. The package is not currently published to PyPI.

`agentctl skill install --update` downloads the Skill from the same pinned tag
and atomically installs it under `$CODEX_HOME/skills/agentctl`, defaulting to
`~/.codex/skills/agentctl`. It writes a metadata file containing:

```text
agentctl_min_version
skill_version
trusted_access_onboarding_version
sha256
```

`agentctl skill status` reports whether the installed Skill is intact and
compatible. Existing compatible installations are not reinstalled by an
ordinary install, and the updater is idempotent when the downloaded content is
unchanged.

## Agent workflow

The canonical Skill directs an agent to check `agentctl --version`, install or
update the pinned release when needed, run `trusted-access onboard --plan`, fix
only application-owned blockers, and finish with
`TRUSTED_ACCESS_READY=YES`. It does not ask the agent to redesign security,
read passwords, or modify production infrastructure.
