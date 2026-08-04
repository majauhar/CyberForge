#!/usr/bin/env bash
# Build/cache the ready container for a batch of OSS-Fuzz projects in parallel.
cd "$(cd "$(dirname "$0")" && pwd)"
export PATH=$HOME/.local/bin:$PATH
PROJECTS="h3 guetzli fmt harfbuzz double-conversion pupnp quickjs c-blosc2 jq serenity simdjson libpng libjxl cjson mruby libzip libsrtp libsass assimp libsndfile openexr matio wabt yara wasm3"
run_setup(){ uv run vuljector setup "$1" >"setup_logs/setup_$1.log" 2>&1 && echo "[$(date +%H:%M:%S)] OK $1" || echo "[$(date +%H:%M:%S)] FAIL $1"; }
export -f run_setup
echo "=== setup batch START $(date) ==="
printf "%s\n" $PROJECTS | xargs -P 6 -I {} bash -c "run_setup {}"
echo "=== setup batch DONE $(date) ==="
