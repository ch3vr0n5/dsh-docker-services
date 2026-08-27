# dsh-docker-services fixed-identity proxy

This process is the narrow trust bridge between one Harness deployment and one
controller. `startProxy()` is the only public startup API: it validates trusted
socket ancestry, authenticates and pins a bounded pool of Unix connections to
the controller, and binds its output socket at its final 0600/0660 mode before
serving. It never reconnects those lanes; restart the proxy after a controller
restart. Path replacement therefore cannot redirect live privileged traffic.

The proxy ignores caller identity headers, attaches a unique short-lived signed
assertion for one configured actor and role, and forwards only bounded requests.
Every ordinary request is separately MAC-bound with a binary, versioned
canonical record of its request ID/nonce, fixed identity, method, normalized
path/query, allowlisted headers, and exact body digest/length. The controller
buffers and MAC-binds the complete response back to that request before the
proxy forwards any byte to Harness.
It has no Docker socket, deployment hook, service secret root, or model-facing
configuration. Run a separate instance and signing key per trust domain.
