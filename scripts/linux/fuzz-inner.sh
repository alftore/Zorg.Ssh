#!/bin/sh
# Runs inside the fuzz container, in a copy of the tree. scripts/fuzz.sh starts it.
# Usage: fuzz-inner.sh TARGET SECONDS
set -u
target="$1"
seconds="$2"
out=/tmp/fuzz-out
corpus="/fuzz/corpus/$target"
crashes=/fuzz/crashes

step() { printf '\n-- %s (%s)\n' "$1" "$(date +%H:%M:%S)"; }

step "Publish"
timeout 900 dotnet publish tests/Zorg.Ssh.Fuzz -c Release -o "$out" -nologo -v q || { echo "PUBLISH FAILED"; exit 1; }

step "Seed (before instrumenting: instrumented code needs the libFuzzer shared memory, and faults without it)"
mkdir -p "$corpus" "$crashes"
timeout 120 "$out/Zorg.Ssh.Fuzz" --seed /tmp/seed || { echo "SEEDING FAILED"; exit 1; }
cp --update=none /tmp/seed/"$target"/* "$corpus"/
echo "$(ls "$corpus" | wc -l) inputs in the corpus"

step "Instrument Zorg.Ssh.dll"
# Only the library under test. BouncyCastle and the BCL are left alone, so coverage is about our code.
timeout 300 sharpfuzz "$out/Zorg.Ssh.dll" || { echo "INSTRUMENTATION FAILED"; exit 1; }

step "Fuzz $target for $seconds s"
# -rss_limit_mb bounds libFuzzer's own process. The .NET child is a separate process. -timeout is per input.
timeout $((seconds + 120)) libfuzzer-dotnet --target_path="$out/Zorg.Ssh.Fuzz" --target_arg="$target" \
  -max_total_time="$seconds" -timeout=20 -rss_limit_mb=1024 -max_len=65536 -print_final_stats=1 \
  -artifact_prefix="$crashes/$target-" "$corpus"
code=$?
echo "libfuzzer exit: $code"

step "Crashes"
found=0
for f in "$crashes/$target"-*; do
  [ -f "$f" ] || continue
  found=1
  echo "$f ($(wc -c < "$f") bytes)"
  od -An -tx1 "$f" | head -n 40
done
[ "$found" = 0 ] && echo "none"
[ "$found" = 0 ] && [ "$code" -eq 0 ]
