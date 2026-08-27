#!/bin/sh
set -eu

uid=1000
gid=1000
lock_wait_seconds=30

die() { echo "dsh volume initialization failed: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "must run as root"
[ "$#" -eq 4 ] || die "expected exactly four volume roots"

for root in "$@"; do
  case "$root" in
    /var/lib/dsh-docker-services|/run/dsh-docker-services|/run/dsh-docker-services-proxy|/var/lib/dsh-audit-checkpoint) ;;
    *) die "unexpected volume root: $root" ;;
  esac
  [ ! -L "$root" ] || die "volume root is a symlink: $root"
  [ -d "$root" ] || die "volume root is not a directory: $root"
done

for root in "$@"; do
  lock="$root/.dsh-volume-init.lock"
  elapsed=0
  while ! mkdir "$lock" 2>/dev/null; do
    [ ! -L "$lock" ] || die "lock path is a symlink: $lock"
    [ "$elapsed" -lt "$lock_wait_seconds" ] || die "timed out waiting for $lock"
    sleep 1
    elapsed=$((elapsed + 1))
  done
  chmod 0700 "$lock"
  cleanup() { rmdir "$lock" 2>/dev/null || true; }
  trap 'cleanup; exit 1' HUP INT TERM
  trap cleanup EXIT
  chown "$uid:$gid" "$root" || die "cannot set owner: $root"
  chmod 0700 "$root" || die "cannot set mode: $root"
  [ ! -L "$root" ] || die "volume root became a symlink: $root"
  [ -d "$root" ] || die "volume root changed type: $root"
  metadata=$(stat -c '%u:%g:%a:%F' "$root") || die "cannot inspect: $root"
  [ "$metadata" = "$uid:$gid:700:directory" ] || die "unexpected metadata for $root: $metadata"
  rmdir "$lock" || die "cannot release lock: $lock"
  trap - EXIT HUP INT TERM
done

echo "dsh writable volume roots initialized for $uid:$gid"
