# DeepSeek Harness Docker Services

Open-source-ready guarded Docker operations for DeepSeek Harness (DSH). The
repository separates the DSH client plugin from a privileged controller. It is
for teams that want useful inventory, health, resources, logs, lifecycle,
parameter, secret, and deploy controls without exposing raw Docker, shell, or
remote-host access to the UI or model.

## What it provides

- Inventory displays controlled and unmanaged containers, status/health,
  resource fields, image/digest, deployment repo/branch/SHA/time/test state,
  and an optional internal or Tailscale URL.
- Per-service action allowlists cover logs, start/stop/restart, schema-driven
  non-secret parameters, and write-only secret status/set/rotate/test.
- Deploy calls are exact-revision guarded (repo, branch, SHA, optional digest),
  locked per service, recorded with test state, and passed only to a configured
  hook. No request accepts a shell command, host path, or remote address.
- Local Docker, constrained SSH helper, and mTLS JSON adapter reference
  implementations; all use typed operations only.
- RBAC capabilities, bounded plugin error containment, redacted hash-chained
  audit records, atomic secret writes, package checks, and CI.

## Quick start

```sh
npm install --package-lock=false
npm run ci
cp examples/controller.json /etc/dsh-docker-services/controller.json
```

Then replace the example values, create the dedicated controller account and
hooks, and follow [deployment instructions](docs/DEPLOYMENT.md). Read the
[threat model](docs/THREAT-MODEL.md) before granting Docker/socket access.

## Project layout

- `packages/plugin`: DSH plugin; no Docker or secret filesystem access.
- `packages/controller`: privileged allowlist enforcement and adapters.
- `packages/shared`: versioned protocol and configuration validation.
- `examples`: host unit, container deployment, and generic configuration.

This project intentionally does not ship a universal deploy script: deployment
semantics are workload-specific and must be reviewed as administrator-owned,
fixed hooks. See [releasing](docs/RELEASING.md) for artifact separation.
