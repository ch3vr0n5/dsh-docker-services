# Threat model

## Boundary

The DSH plugin is unprivileged. It sends typed requests over a local Unix socket
to the controller. Only the controller may access Docker or configured deploy
and secret-test executables. The controller never accepts a command string, a
Docker socket URL, a filesystem path, an SSH target, or a deployment hook from
the plugin/UI.

The deployment operator owns the controller configuration, Unix socket ACL,
Docker access, deployment hooks, secret root, and authentication proxy. Anyone
who can edit that configuration or control Docker is already privileged on the
host and is outside the protection boundary.

## Controls

- Services, containers, actions, repositories, branches, secret IDs, parameter
  keys, hook paths, and remote targets are configuration allowlists.
- RBAC maps an authenticated role to fixed capabilities. The plugin passes an
  actor and role, never a capability set. In production, inject those headers
  only after authentication at a trusted local proxy, or replace
  `identityFromRequest` with Unix peer credential/mTLS identity lookup.
- Local Docker uses `execFile` with a fixed binary and fixed argument shape.
  SSH uses a fixed host, user, known-hosts file, and provisioned helper path;
  mTLS uses one configured HTTPS endpoint. Neither accepts caller-controlled
  command or destination data.
- Deployment requires an allowlisted repo/branch, SHA-shaped exact revision,
  optional required image digest, a per-service lock, then calls only the
  configured absolute hook with fixed named arguments. Hooks must independently
  verify checkout/ref/image provenance before changing a workload.
- Secret set/rotate validates length/newline rules and atomically writes a
  regular file below `secretRoot`. Status exposes only configured/updated time.
  There is deliberately no secret get endpoint, inventory field, audit field,
  or test-hook argument containing secret material.
- Audit records are append-only through the controller API, redacted, and hash
  chained. Send the JSONL file to write-once/off-host storage for resistance to
  a privileged host compromise; local filesystem permissions alone cannot make
  root-proof immutability.

## Residual risks

Docker socket access is effectively host-root access on common deployments.
Treat the controller account and any container mounting that socket as highly
privileged. A malicious allowed deploy hook, compromised DSH process with an
operator role, or a malicious allowed image can operate the configured service.
Run hooks as a dedicated account, pin images by digest, restrict egress, retain
audit records remotely, and review configuration changes like production code.
