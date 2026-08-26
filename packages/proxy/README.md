# dsh-docker-services fixed-identity proxy

This process is the narrow trust bridge between one Harness deployment and one
controller. It listens on a private Unix socket, ignores all caller identity
headers, attaches a short-lived signed assertion for one configured actor and
role, and forwards only bounded HTTP requests to the private controller socket.
It has no Docker socket, deployment hook, service secret root, or model-facing
configuration. Run a separate instance and signing key per trust domain.
