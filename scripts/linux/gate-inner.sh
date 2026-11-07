#!/bin/sh
# Runs inside the Linux gate container, in a copy of the tree. scripts/test-linux.sh starts it.
# Every step has a timeout. busybox and GNU timeout both accept "timeout SECONDS COMMAND".
set -u

status=0
step() { printf '\n-- %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

# Prints how many tests were skipped for each reason, from xunit's console output.
skip_summary() {
  echo "skip reasons in $1:"
  awk '/^skipped /{ getline r; sub(/^ +/, "", r); n[r]++ } END { for (k in n) printf "%5d  %s\n", n[k], k }' "$1" | sort -rn
}

# Runs one test project with a limit, keeps the whole output in a file, and shows its end.
run_tests() {
  project="$1"; limit="$2"; log="$3"
  s=$(date +%s)
  # shellcheck disable=SC2086
  timeout "$limit" dotnet test --project "$project" --no-build -nologo ${ZORG_GATE_TEST_ARGS:-} > "$log" 2>&1
  code=$?
  grep -E '^(failed|Test run summary| +(total|failed|succeeded|skipped|duration):)' "$log"
  skip_summary "$log"
  echo "$project: exit $code in $(( $(date +%s) - s )) s"
  if [ "$code" -ne 0 ]; then
    status=1
    echo "---- failures in $log"
    awk '/^failed /{ p=1 } /^skipped /{ p=0 } /^Test run summary/{ p=0 } p' "$log" | head -n 120
  fi
}

if [ "${ZORG_GATE_HIDE_SSH:-0}" = 1 ]; then
  # Proves the required-peers switch: with no OpenSSH tools, the run must fail (or skip, if the switch is off).
  rm -f /usr/bin/ssh /usr/bin/ssh-keygen /usr/bin/ssh-agent /usr/bin/ssh-add /usr/bin/sftp
fi

step "Platform"
uname -a
head -2 /etc/os-release
ssh -V 2>&1 || echo "ssh: missing"
command -v ssh-keygen || echo "ssh-keygen: missing"
echo "dotnet $(dotnet --version)"
echo "ZORG_REQUIRE_PEERS=${ZORG_REQUIRE_PEERS:-0}"

step "Restore"
s=$(date +%s)
timeout 600 dotnet restore Zorg.Ssh.slnx -nologo -v q || { echo "RESTORE FAILED"; exit 1; }
echo "restore: $(( $(date +%s) - s )) s"

step "Build"
s=$(date +%s)
timeout 900 dotnet build Zorg.Ssh.slnx -nologo -v q --no-restore || { echo "BUILD FAILED"; exit 1; }
echo "build: $(( $(date +%s) - s )) s"

step "Unit tests"
n=0
while [ "$n" -lt "${ZORG_GATE_REPEAT:-1}" ]; do
  n=$((n + 1))
  [ "${ZORG_GATE_REPEAT:-1}" -gt 1 ] && echo "run $n of ${ZORG_GATE_REPEAT}"
  run_tests tests/Zorg.Ssh.Tests 900 /tmp/unit.log
done
# A long fuzz run (ZORG_FUZZ_MINUTES) leaves its summary here: what each target ran, and how deep it got.
if [ -f /tmp/zorg-fuzz-report.txt ]; then cat /tmp/zorg-fuzz-report.txt; fi

if [ "${ZORG_GATE_INTEROP:-0}" = 1 ]; then
  step "Interop tests"
  run_tests tests/Zorg.Ssh.InteropTests 1500 /tmp/interop.log
fi

if [ "${ZORG_GATE_AOT:-0}" = 1 ]; then
  step "Native AOT publish"
  if [ "$(uname -m)" = aarch64 ]; then arch=arm64; else arch=x64; fi
  if [ -f /etc/alpine-release ]; then rid="linux-musl-$arch"; else rid="linux-$arch"; fi
  s=$(date +%s)
  timeout 900 dotnet publish samples/Zorg.Ssh.AotSmoke -r "$rid" -c Release -o /tmp/aot > /tmp/aot.log 2>&1
  code=$?
  tail -n 5 /tmp/aot.log
  [ "$code" -eq 0 ] || { echo "AOT PUBLISH FAILED"; status=1; }
  if grep -E '\bIL[23][0-9]{3}\b' /tmp/aot.log; then echo "TRIM OR AOT WARNINGS"; status=1; fi
  echo "aot publish ($rid): $(( $(date +%s) - s )) s"
  if [ "$code" -eq 0 ]; then
    timeout 120 /tmp/aot/Zorg.Ssh.AotSmoke > /tmp/aot-run.log 2>&1
    code=$?
    grep -c '^ok' /tmp/aot-run.log | sed 's/$/ checks ok/'
    grep '^FAIL' /tmp/aot-run.log
    [ "$code" -eq 0 ] || { echo "AOT RUN FAILED (exit $code)"; status=1; }
  fi
fi

step "Done"
echo "gate status: $status"
exit "$status"
