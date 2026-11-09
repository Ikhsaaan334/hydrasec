#!/usr/bin/env bash
# HydraSec one-shot setup untuk mesin baru.
# Syarat: Docker Desktop berjalan + koneksi internet (build pertama mengunduh tool).
# Usage:  bash setup.sh
set -euo pipefail
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || {
  echo "ERROR: docker tidak ditemukan — install & jalankan Docker Desktop terlebih dahulu."
  exit 1
}

# .env opsional: compose punya default untuk semua variabel
[ -f .env ] || { cp .env.example .env; echo "[setup] .env dibuat dari .env.example"; }

echo "[setup] 1/2 — build keenam image tool (sekali saja, ±5-15 menit)"
bash tools/build-all.sh

echo "[setup] 2/2 — build & jalankan seluruh stack"
docker compose up -d --build

echo ""
echo "Selesai!  Web app : http://localhost:8080"
echo "           OTP    : http://localhost:8025  (MailPit)"
echo "Tunggu sekitar 30 detik setelah start (healthcheck) lalu buka web app."
