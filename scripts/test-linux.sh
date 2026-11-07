#!/usr/bin/env bash
# The Linux gate: build and test Zorg.Ssh in a Linux container, on Podman or Docker.
#
#   scripts/test-linux.sh [--variant alpine|ubuntu] [--interop] [--aot] [--args "X"] [--repeat N] [--hide-ssh] [--no-peers]
#
#   --variant   alpine (default, musl, OpenSSL 3.5, so BCL ML-KEM runs) or ubuntu (glibc, OpenSSL 3.0).
#   --interop   Also run the interop suite. It starts peers as sibling containers through the Podman
#               machine's socket, so this needs Podman.
#   --aot       Also publish and run samples/Zorg.Ssh.AotSmoke with Native AOT.
#   --args "X"  Extra arguments for dotnet test, such as --args "--filter-class *HostileForwardingTests".
#   --repeat N  Run the unit tests N times in one container, to chase a flaky test.
#   --hide-ssh  Remove ssh and ssh-keygen in the container, to prove that a missing peer fails the run.
#   --no-peers  Don't set ZORG_REQUIRE_PEERS=1. By default a missing ssh or ssh-keygen fails a test.
#
# The tree goes in as a tar stream of the files git knows (tracked and untracked, not ignored), including
# uncommitted edits. Nothing is bind-mounted from the host. NuGet packages are cached in the named volume
# zorg-ssh-nuget. Every step has a timeout. Set ZORG_SSH_CONTAINER_CLI to force the container program.
set -euo pipefail

variant=alpine
interop=0
aot=0
peers=1
hide=0
testargs=
repeat=1
while [ $# -gt 0 ]; do
  case "$1" in
    --variant) variant="$2"; shift ;;
    --interop) interop=1 ;;
    --aot) aot=1 ;;
    --args) testargs="$2"; shift ;;
    --repeat) repeat="$2"; shift ;;
    --hide-ssh) hide=1 ;;
    --no-peers) peers=0 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done
case "$variant" in alpine|ubuntu) ;; *) echo "Unknown variant: $variant" >&2; exit 2 ;; esac

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
image="zorg-ssh-gate:$variant"
volume=zorg-ssh-nuget
name="zorg-ssh-gate-$$"

stage() { printf '\n== %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

# Every engine call has a timeout. Without one, a stalled engine hangs the run for ever.
run_cli() { local limit="$1"; shift; timeout "$limit" "$cli" "$@"; }

cleanup() { run_cli 60 rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# Host networking everywhere, on purpose. On the Podman machine used for development, the default rootless
# network gave about 100 KB/s, which is why apk and apt-get never finished and why a restore took minutes.
# With --network host the same download ran at full speed.
stage "Image $image"
start=$SECONDS
run_cli 1200 build --network host -t "$image" -f "scripts/linux/Dockerfile.$variant" scripts/linux
echo "image step: $((SECONDS - start)) s"

socket_args=()
env_args=(-e "ZORG_REQUIRE_PEERS=$peers" -e "ZORG_GATE_AOT=$aot" -e "ZORG_GATE_INTEROP=$interop" -e "ZORG_GATE_HIDE_SSH=$hide" -e "ZORG_GATE_TEST_ARGS=$testargs" -e "ZORG_GATE_REPEAT=$repeat")
# The fuzz tests read these, so a long run or a replay can be done in the container: ZORG_FUZZ_MINUTES=2 scripts/test-linux.sh --args "--filter-class *FuzzTests"
for fuzz_var in ZORG_FUZZ_MINUTES ZORG_FUZZ_SEED ZORG_FUZZ_TARGET ZORG_FUZZ_INPUT_SECONDS ZORG_FUZZ_VERBOSE; do
  if [ -n "${!fuzz_var:-}" ]; then env_args+=(-e "$fuzz_var=${!fuzz_var}"); fi
done
if [ "$interop" = 1 ]; then
  # The socket path is the one inside the Podman machine, where the engine runs.
  sock="$(run_cli 60 info --format '{{.Host.RemoteSocket.Path}}' | tr -d '\r')"
  sock="${sock#unix://}"
  if [ -z "$sock" ]; then echo "No Podman socket found. Interop needs Podman." >&2; exit 1; fi
  echo "podman socket in the machine: $sock"
  # The run uses host networking (see above), so the tests reach the peers on the machine loopback.
  socket_args=(--security-opt label=disable -v "$sock:/run/podman.sock")
  env_args+=(-e "CONTAINER_HOST=unix:///run/podman.sock" -e "ZORG_SSH_CONTAINER_CLI=podman")
fi

stage "Tree"
files="$(mktemp)"
trap 'rm -f "$files"; cleanup' EXIT
{ git ls-files -z --cached --others --exclude-standard | tr '\0' '\n'; } | sort -u | while IFS= read -r f; do
  [ -f "$f" ] && printf '%s\n' "$f"
done > "$files"
echo "$(wc -l < "$files") files"

stage "Run"
tar -cf - -T "$files" | run_cli 3000 run --rm -i --network host --name "$name" \
    -v "$volume:/root/.nuget/packages" \
    "${env_args[@]}" "${socket_args[@]}" \
    "$image" sh -c 'mkdir -p /src && tar -xf - -C /src && cd /src && sh scripts/linux/gate-inner.sh'
