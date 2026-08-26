# dsh-docker-services plugin

This is the unprivileged DeepSeek Harness half of the project. It talks only to
an authenticating local proxy socket and exposes allowlisted operations; it
never selects identity/role, opens Docker sockets, executes commands, or stores
secrets.
