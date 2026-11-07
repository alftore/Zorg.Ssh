#!/usr/bin/env bash
# Coverage-guided fuzzing of the wire decoders, in a Linux container, on Podman or Docker.
#
#   scripts/fuzz.sh <packet-reader|packet-reader-ctr-eam|kex-init|sftp-response> [seconds]
#
# SharpFuzz instruments Zorg.Ssh.dll inside the container, and libFuzzer drives tests/Zorg.Ssh.Fuzz. The
# corpus and any crash inputs live in the named volume zorg-ssh-fuzz, so a second run starts where the
# first stopped. The tree goes in as a tar stream, as in scripts/test-linux.sh. The default is 60 seconds.
set -euo pipefail

target="${1:-}"
seconds="${2:-60}"
case "$target" in packet-reader|packet-reader-ctr-eam|kex-init|sftp-response) ;; *) sed -n '2,8p' "$0"; exit 2 ;; esac
case "$seconds" in ''|*[!0-9]*) echo "seconds must be a number" >&2; exit 2 ;; esac

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

find_cli() {
  if [ -n "${ZORG_SSH_CONTAINER_CLI:-}" ]; then echo "$ZORG_SSH_CONTAINER_CLI"; return; fi
  for name in docker podman; do
    if command -v "$name" >/dev/null 2>&1; then command -v "$name"; return; fi
  done
  local known="${LOCALAPPDATA:-}/Programs/Podman/podman.exe"
  if [ -n "${LOCALAPPDATA:-}" ] && [ -x "$known" ]; then echo "$known"; return; fi
  echo "No docker or podman found. Set ZORG_SSH_CONTAINER_CLI." >&2
  exit 1
}
cli="$(find_cli)"
image=zorg-ssh-fuzz
name="zorg-ssh-fuzz-$$"

run_cli() { local limit="$1"; shift; timeout "$limit" "$cli" "$@"; }
cleanup() { run_cli 60 rm -f "$name" >/dev/null 2>&1 || true; }
files="$(mktemp)"
trap 'rm -f "$files"; cleanup' EXIT

echo "== Image $image"
run_cli 1500 build --network host -t "$image" -f scripts/linux/Dockerfile.fuzz scripts/linux

{ git ls-files -z --cached --others --exclude-standard | tr '\0' '\n'; } | sort -u | while IFS= read -r f; do
  [ -f "$f" ] && printf '%s\n' "$f"
done > "$files"

echo "== Run $target for $seconds s"
tar -cf - -T "$files" | run_cli $((seconds + 1500)) run --rm -i --network host --name "$name" \
    -v zorg-ssh-nuget:/root/.nuget/packages -v zorg-ssh-fuzz:/fuzz \
    "$image" sh -c "mkdir -p /src && tar -xf - -C /src && cd /src && sh scripts/linux/fuzz-inner.sh '$target' '$seconds'"
