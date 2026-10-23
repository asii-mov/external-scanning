#!/usr/bin/env bash
# Provision a fresh Linux box (a Claude Code cloud environment, CI, a VM) to
# run extscan, its tests, the fuzzer and the local lab. Safe to re-run.
#
#   bash scripts/cloud-setup.sh
#
# nuclei and its templates are pinned to the versions the lab results in
# tests/fixtures/lab-run were produced with, and both downloads are checked
# against a SHA-256 before use.
set -euo pipefail

NUCLEI_VERSION=3.4.10
NUCLEI_SHA256=234c12cc5288af071abdcd6f854245b6067345556e1235cf96b76725c1004357
TEMPLATES_VERSION=10.2.7
# GitHub archive tarballs are not guaranteed byte-stable. If this check fails
# after GitHub changes its archiver, re-pin from a trusted download.
TEMPLATES_SHA256=806f65af7808808144c555a424d253592ed5c0fb966b9595735004e2ae0e17f9

BIN="$HOME/.local/bin"
mkdir -p "$BIN"
export PATH="$BIN:$PATH"
SUDO=""
[ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null && SUDO="sudo"

if ! command -v nmap >/dev/null || ! command -v sslscan >/dev/null; then
  $SUDO apt-get update -qq
  $SUDO apt-get install -y -qq nmap sslscan openssl curl unzip
fi

if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | sh
fi

if [ "$(nuclei -version 2>&1 | grep -o "v$NUCLEI_VERSION" || true)" != "v$NUCLEI_VERSION" ]; then
  tmp="$(mktemp -d)"
  zip="nuclei_${NUCLEI_VERSION}_linux_amd64.zip"
  curl -sSLo "$tmp/$zip" \
    "https://github.com/projectdiscovery/nuclei/releases/download/v$NUCLEI_VERSION/$zip"
  echo "$NUCLEI_SHA256  $tmp/$zip" | sha256sum -c -
  unzip -oq "$tmp/$zip" nuclei -d "$BIN"
  rm -rf "$tmp"
fi

if [ ! -f "$HOME/nuclei-templates/.extscan-v$TEMPLATES_VERSION" ]; then
  tmp="$(mktemp -d)"
  curl -sSLo "$tmp/t.tar.gz" \
    "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v$TEMPLATES_VERSION.tar.gz"
  echo "$TEMPLATES_SHA256  $tmp/t.tar.gz" | sha256sum -c -
  rm -rf "$HOME/nuclei-templates"
  mkdir -p "$HOME/nuclei-templates"
  tar xzf "$tmp/t.tar.gz" -C "$HOME/nuclei-templates" --strip-components=1
  touch "$HOME/nuclei-templates/.extscan-v$TEMPLATES_VERSION"
  rm -rf "$tmp"
fi

uv sync --locked
uv run extscan doctor
