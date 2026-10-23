#!/usr/bin/env bash
# Regenerate tests/fixtures/lab-run from a full lab scan.
#
#   bash scripts/capture-lab-run.sh                 # scan in a fresh container, as root
#   bash scripts/capture-lab-run.sh runs/<run-id>   # capture an existing run instead
#
# The container run is the reference: it runs as root, so UDP and SNMP are
# covered, and it uses the pinned tools from scripts/cloud-setup.sh. Needs
# Docker and network access for the setup downloads.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
dest="$repo/tests/fixtures/lab-run"

if [ $# -ge 1 ]; then
  run="$(cd "$1" && pwd)"
else
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  mkdir "$work/src" "$work/out"
  git -C "$repo" archive HEAD | tar x -C "$work/src"
  docker run --rm -v "$work/src:/src:ro" -v "$work/out:/out" ubuntu:24.04 bash -c '
    set -eo pipefail
    cp -r /src /w && cd /w
    bash scripts/cloud-setup.sh > /out/setup.log 2>&1
    export PATH=$HOME/.local/bin:$PATH
    (uv run --locked python -m tests.lab > /out/lab.log 2>&1 &)
    sleep 5
    uv run --locked extscan --runs-dir /out/runs run \
      --scope examples/lab/scope.json --policy examples/lab/policy.json > /out/run.log 2>&1
    { echo "nmap: $(nmap --version | head -1)"
      echo "sslscan: $(sslscan --version 2>&1 | head -1)"
      echo "nuclei: $(nuclei -version 2>&1 | grep -i "engine version")"
    } | sed -e "s/\x1b\[[0-9;]*m//g" -e "s/\t//g" > /out/versions.txt
    chown -R '"$(id -u):$(id -g)"' /out'
  run="$(find "$work/out/runs" -mindepth 1 -maxdepth 1 -type d | head -1)"
  cp "$work/out/versions.txt" "$work/out/run.log" "$run/"
fi

rm -rf "$dest"
mkdir -p "$dest/raw"
for f in run.json hosts.json services.json findings.json leads.json degradations.json \
         checkpoints.json commands.jsonl report.md report.json versions.txt run.log; do
  if [ -f "$run/$f" ]; then cp "$run/$f" "$dest/"; fi
done
for f in "$run"/raw/*.xml "$run"/raw/nuclei.jsonl "$run"/raw/nuclei-targets.txt \
         "$run"/raw/openapi-*.txt; do
  if [ -f "$f" ]; then cp "$f" "$dest/raw/"; fi
done

# Absolute paths from the machine that ran the scan become run-relative.
run_dir="${run%/}"
find "$dest" -type f -exec sed -i \
  -e "s|$run_dir|runs/$(basename "$run_dir")|g" \
  -e "s|/out/runs/|runs/|g" \
  -e "s|$HOME/|~/|g" -e "s|/root/|~/|g" {} +

echo "captured $(basename "$run_dir") into ${dest#"$repo"/}"
