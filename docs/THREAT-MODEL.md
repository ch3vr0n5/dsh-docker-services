# Threat model

## Boundary

The DSH plugin is unprivileged. It sends typed requests to an authenticating
local proxy or mTLS terminator. That boundary forwards to the private controller
socket with a short-lived HMAC assertion. Only the controller may access Docker
or configured deploy/secret-test executables. No API accepts a command string,
Docker endpoint, filesystem path, SSH target, or hook path.

The deployment operator owns controller configuration, socket ACLs, Docker
access, hooks, secret roots, keys, and the authentication proxy. Anyone who can
modify those or control Docker is already privileged and outside this boundary.

## Controls

- Services, containers, actions, repositories, branches, secret IDs, parameter
  keys, hook paths, and remote targets are administrator allowlists.
- RBAC uses the signed proxy assertion's actor and role. The controller rejects
  caller `x-dsh-actor`/`x-dsh-role` headers, verifies issuer, audience, time,
  signature and nonce, and rejects replay using a durable, cross-process locked
  nonce store. Only the trusted proxy may access the private socket and HMAC key.
- Local Docker uses a root-owned absolute binary, explicit validated Unix
  socket, minimal environment, bounded output/time, and fixed argument forms.
  SSH and mTLS use fixed destinations and bounded, cancellable JSON operations.
- Deploy requires an allowed repo/branch, full SHA, idempotency key, and
  renewable service lease. A root-owned hook must prove remote reachability and
  branch ancestry, deploy by digest, run tests, and return authoritative JSON.
  The controller independently requires that every configured container has the
  exact digest and configured running/health state. Client digest/test metadata
  and incomplete or mismatched hook results fail.
- Secret writes validate schema, reject symlink components, use no-follow file
  opens and durable atomic replacement under an owned 0700 root. Status exposes
  only configured/time; there is no secret-read route.
- Audit appends are serialized across processes by a no-follow OS lock, fsynced,
  redacted, hash chained, and followed by a keyed fsynced checkpoint. Put the
  checkpoint file on independently retained or off-host storage. Startup/health
  detect truncation, rollback, or corruption.
- Public errors are bounded and opaque. Detailed errors go only to a protected,
  bounded, redacted log and are correlated by request ID. Failed child-process
  stdout/stderr content is never copied into errors or logs, even after
  redaction; diagnostics contain only operation/classification, exit/signal,
  bounded byte counts, and a random execution correlation ID.

## Residual risks

Docker access is effectively host-root on common deployments. A malicious
allowed hook/image, compromised trusted proxy, operator identity, or host root
can still operate configured services. Local files cannot resist a root attacker
who also obtains the checkpoint key and off-host store. Pin images, isolate the
proxy/controller, restrict egress, retain checkpoints independently, and review
configuration/hook changes as production code.
