# dsh-docker-services plugin

This is the unprivileged DeepSeek Harness half of the project. It only talks to
the local controller socket and exposes its allowlisted operations; it never
opens Docker sockets, executes shell commands, or stores secrets.
