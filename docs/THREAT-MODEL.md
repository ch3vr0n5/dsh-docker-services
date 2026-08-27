# Threat model

## Boundary

The DSH plugin is unprivileged. It sends typed requests to an authenticating
local proxy or mTLS terminator. At startup the reference proxy verifies secure
Unix-socket ancestry, opens a bounded connection pool, authenticates the
controller with a fresh domain-separated HMAC challenge, and pins those exact
connections for its lifetime. It never follows the controller pathname again
or reconnects. That boundary forwards to the private controller over the pinned
connections with short-lived HMAC assertions and per-request/response,
purpose-separated MACs. Only the controller may access Docker
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
  signature and nonce, then validates a non-JSON byte-framed request MAC before
  parsing or acting. That record covers the fixed identity, method, normalized
  target, allowlisted headers, and exact body. A durable, cross-process locked
  store rejects replays of its complete canonical digest. The response MAC is
  bound to that request plus status, allowlisted headers, body, and terminal
  outcome; the proxy buffers and verifies it before releasing output. Only the
  trusted proxy may access the private socket and HMAC key.
- The controller socket's protected parent is the filesystem authorization
  boundary. Inode metadata is not treated as endpoint identity. Every pinned
  lane proves key possession before the public proxy socket is bound; pathname
  replacement after startup receives no traffic. Loss of a lane fails closed,
  and recovery requires a proxy restart. Both controller and proxy output
  sockets are created at their final mode under a narrow synchronous umask—there
  is no bind-then-chmod window.
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
configuration/hook changes as production code. Processes running as the trusted
socket/key owner are also inside this boundary; do not co-locate untrusted code
under either service UID.
