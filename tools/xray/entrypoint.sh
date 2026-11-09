#!/bin/sh
# entrypoint tool-xray — Deep Web Security Assessment (chaitin/xray)
# Argumen CLI lengkap diterima via CMD dari worker (array, tanpa shell), mis.:
#   --url <target> | --basic-crawler <target> | --plugins a,b | --json-output <file>
# Default config di-bake read-only di /opt/xray-default dan disalin ke working
# dir yang writable — xray menulis config secara atomik sehingga butuh izin
# tulis DIREKTORI (runtime berjalan sebagai uid acak non-root).
set -e

WORK=/tmp/xray-work
mkdir -p "$WORK"
cp /opt/xray-default/*.yaml "$WORK"/ 2>/dev/null || true
cd "$WORK"

exec /opt/xray/xray webscan "$@"
