# Deployment

Copy `examples/controller.json` to `/etc/dsh-docker-services/controller.json`,
replace every example service and repository, then provision the named deploy
and secret-test hooks as root-owned non-writable executables. Do not put secret
values in this file. Create a dedicated `dsh-controller` account, grant it only
the narrowly required Docker access, and grant the DSH process group read/write
access to `/run/dsh-docker-services/controller.sock`.

For a host installation, install the controller package, install
`examples/host/dsh-docker-services.service`, run `systemctl daemon-reload`, and
enable the unit. The supplied unit is a baseline: add your distribution's
Docker group policy and audit forwarding configuration.

For a container installation, use `examples/container/compose.yaml`. A mounted
Docker socket remains host-privileged; prefer the SSH or mTLS adapter when the
DSH host should not directly hold it. The SSH helper must deserialize the same
typed `RemoteCall` protocol and implement only inventory/action/logs/deploy.
The mTLS endpoint must require client certificates and reject any unrecognized
operation or service.

Configure the DSH plugin's socket, actor, and role through its Cordis config.
The example `dsh-viewer` role is deliberately read-only. Grant an operator role
only where service changes are intended. Install the published plugin artifact;
do not mount controller configuration into the browser/client environment.
