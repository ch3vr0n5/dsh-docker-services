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

The proxy sets only `x-dsh-proxy-assertion`. Its value is
`base64url(UTF-8 JSON) + "." + base64url(HMAC-SHA256(key, encoded JSON))`.
`iat`/`exp` are finite integer Unix seconds with at most a five-minute assertion
lifetime, actor/role/nonce are bounded identifiers, and each nonce is single-use.
Replay state is durably stored below `stateDir/auth-replay`, survives controller
restart, and is serialized across controller processes. The exported
`signProxyAssertion` helper is the reference implementation. The proxy must
remove any assertion or identity header received from its client before adding
its own.

For host installation, install the controller package and systemd example, add
the dedicated account's narrowly required Docker access, then enable the unit.
For containers, use the repository-root build context in the Compose example.
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
