#!/usr/bin/env bash
# Build keenam image tool HydraSec (jalankan sekali sebelum compose up).
# Usage: bash tools/build-all.sh
set -euo pipefail
cd "$(dirname "$0")/.."

for t in nmap nuclei xsstrike xray sqlmap ffuf; do
  echo "== Building hydrasec/tool-${t}:latest =="
  docker build -t "hydrasec/tool-${t}:latest" "tools/${t}"
done

echo "Semua image tool selesai dibangun."
