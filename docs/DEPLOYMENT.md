# Deployment

Copy `examples/controller.json`, replace all examples, and provision every
binary and hook as root-owned and not group/world writable. Writable roots must
be owned by the controller UID, mode 0700, and have no symlink component. Keep
auth/checkpoint keys out of configuration and put the keyed checkpoint file on
a separate off-host or independently retained mount.

DSH connects to an authenticating proxy socket, never the private controller
socket. The proxy strips identity headers and signs an assertion containing
`iss`, `aud`, `sub`, `role`, `iat`, `exp`, and a unique nonce using
`auth.keyFile`; assertions should expire within five minutes. The controller
maps the signed role to configured capabilities. An mTLS terminator may provide
the same trusted boundary after validating client certificates.

Before accepting Harness traffic, the proxy establishes `controllerConnections`
(default 4, range 1–16) Unix connections and authenticates the controller on
each with a fresh HMAC challenge. Those connections are pinned and never
reconnected. A controller restart intentionally makes the proxy unavailable;
restart the proxy to create a newly authenticated pool. Keep controller and
proxy socket parents owned by their service UID and non-group/world-writable.

The proxy sets only its own protocol headers on forwarded operations; it never
forwards client identity or authentication headers. The assertion value is
`base64url(UTF-8 JSON) + "." + base64url(HMAC-SHA256(derived assertion key,
encoded JSON))`.
`iat`/`exp` are finite integer Unix seconds with at most a five-minute assertion
lifetime, actor/role/nonce are bounded identifiers, and every request record's
ID/nonce pair is single-use. Replay state is durably stored below `stateDir/auth-replay`, survives controller
restart, and is serialized across controller processes. The exported
`signProxyAssertion` helper is the reference implementation. The proxy must
remove any assertion or identity header received from its client before adding
its own.

Ordinary traffic uses protocol version 1 and a deterministic binary canonical
record: request ID and nonce, fixed actor/role, `GET`/`POST`, normalized
origin-form path/query, an explicit `content-type`/`content-length` allowlist,
and exact SHA-256 body digest/length. The controller verifies that record before
parsing JSON or calling an operation, and durably rejects a replay of its full
canonical digest. Its complete response carries a separately derived response
MAC bound to the original request ID/nonce/digest, status, explicitly
allowlisted response headers, response digest/length, and `ok`/`error` terminal
outcome. The proxy buffers within its response bound and rejects missing,
replayed, truncated, extra-framed, or mismatched responses with an opaque 502;
it never forward-streams privileged controller output.

The `@dsh-docker-services/proxy` package and `examples/proxy.json` are the
reference implementation. Run one proxy per Harness trust domain with a fixed
actor and role. Give it only the shared controller-socket volume, its private
output-socket volume, and the domain signing key; never mount Docker, service
secrets, repositories, deployment hooks, or controller state. Mount only the
proxy output socket into Harness. The example Compose file demonstrates these
boundaries.

Programmatic embedding must use exported `startProxy(config)`. It returns only
after controller authentication and race-free private-socket binding complete,
and supplies a bounded `close()` method. There is no public unbound-server API.

For host installation, install the controller package and systemd example, add
the dedicated account's narrowly required Docker access, then enable the unit.
For containers, use the repository-root build context in the Compose example.
The reference Compose deployment has no runtime initializer or capability-bearing
process. The admitted image contains nonempty `state`, `socket`, and `data`
subdirectories owned by `1000:1000` with mode `0700`. Each named volume is
mounted at a parent path; Docker copies those seeded subdirectories into a
truly empty volume on first use. Controller and proxy remain `1000:1000`,
`cap_drop: ALL`, `no-new-privileges`, read-only-rootfs, and network-isolated.
Local Compose implements file-backed secrets as bind mounts and does not remap
their ownership. Provision `proxy-auth.key` and `audit-checkpoint.key` as
regular, non-linked files owned by `1000:1000`, mode `0600`, on a host path
whose ancestors are not group/world writable. The deploying administrator may
be root, but the long-running services remain uid/gid 1000 and therefore can
read only secrets provisioned for that identity. Do not loosen the files to
group/world readability to work around an ownership mismatch.
Do not reuse legacy volumes from the removed initializer: they lack the new
subdirectory contract and the services fail closed. Migrate explicitly by
stopping the stack, backing up the old volume data, creating fresh named
volumes, and restoring only after checking ownership, mode `0700`, regular
directories, and no symlinks as the service UID. Never grant a repair
container capabilities or run an automatic privileged migration.
The example uses `/run/docker.sock` inside the controller because the Alpine
runtime rejects symlinked socket path components; the host-side
`/var/run/docker.sock` path remains the conventional Docker socket.
The image and actions are digest/SHA pinned. A mounted Docker socket remains
host-privileged; prefer the constrained SSH or mTLS adapter across hosts.

Deploy hooks receive only `--service`, `--repo`, `--branch`, and `--sha`. They
must fetch the allowed repository, prove the SHA reachable from the requested
remote branch, deploy an immutable digest, run tests, then print exactly one JSON
object such as:

```json
{"repo":"https://git.example.invalid/team/example-api.git","branch":"release","sha":"0123456789012345678901234567890123456789","imageDigest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","deployedAt":"2026-08-26T00:00:00Z","testState":"passed","reachable":true,"branchVerified":true}
```

Any extra stdout, mutable tag, mismatch, failed test, or incomplete proof fails
without updating deployment state. Remote helpers must apply the same protocol
checks and expose only inventory/action/logs/deploy operations.

After a hook succeeds, the controller independently inventories every configured
container and requires the exact reported digest. `deploy.runtimePolicy`
separately controls running and healthy checks; both default to required when the
field is omitted. Disable either check only for a deliberate stopped-service or
no-healthcheck workflow.
