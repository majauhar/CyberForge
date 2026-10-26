#!/usr/bin/env bash
# Start the CyberForge LiteLLM proxy (OpenAI-compatible endpoint -> OpenRouter).
#
# Usage:
#   export OPENROUTER_API_KEY=sk-or-...        # your OpenRouter key
#   export LITELLM_MASTER_KEY=sk-proxy-...     # any secret; clients must send this
#   ./start_proxy.sh                            # listens on 0.0.0.0:4000
#
# Env overrides: PORT (default 4000), HOST (default 0.0.0.0), CONFIG (default ./config.yaml).
set -euo pipefail
cd "$(cd "$(dirname "$0")" && pwd)"

: "${OPENROUTER_API_KEY:?set OPENROUTER_API_KEY}"
: "${LITELLM_MASTER_KEY:?set LITELLM_MASTER_KEY (clients must send this exact value as their bearer token)}"
PORT="${PORT:-4000}"
HOST="${HOST:-127.0.0.1}"
CONFIG="${CONFIG:-config.yaml}"

# Prefer a dedicated venv at deploy/litellm/.proxyenv so the proxy's litellm
# version is independent of the project's pinned one. Create it once:
#   uv venv .proxyenv && uv pip install --python .proxyenv/bin/python 'litellm[proxy]'
if [ -x ".proxyenv/bin/litellm" ]; then
  LITELLM=".proxyenv/bin/litellm"
elif command -v litellm >/dev/null 2>&1; then
  LITELLM="litellm"
else
  echo "litellm not found. Create the venv:" >&2
  echo "  uv venv .proxyenv && uv pip install --python .proxyenv/bin/python 'litellm[proxy]'" >&2
  exit 1
fi

echo "Starting LiteLLM proxy on ${HOST}:${PORT} with ${CONFIG}"
exec "$LITELLM" --config "$CONFIG" --host "$HOST" --port "$PORT"
