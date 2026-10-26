# CyberForge ⇄ LiteLLM proxy ⇄ OpenRouter (GLM 5.3)

CyberForge calls models through LiteLLM. It has a built-in "OSS/OpenAI-compatible endpoint"
path: `RCHAT_OSS_API_BASE` / `RCHAT_OSS_API_KEY` in `src/.env` are bridged to `OPENAI_API_BASE` /
`OPENAI_API_KEY`, and any **bare** model id you pass to `vuljector` (e.g. `cyberforge-agent`) is
normalized to `openai/cyberforge-agent` and resolved by this proxy. So we run a LiteLLM proxy that
turns stable aliases into the real OpenRouter model (GLM 5.3).

```
vuljector <alias>  --openai/<alias>-->  LiteLLM proxy (:4000/v1)  --openrouter/z-ai/glm-5.3-->  OpenRouter
                         (src/.env RCHAT_OSS_*)       (config.yaml model_list)
```

## Verified
The full chain (env bridge -> `openai/<alias>` normalization -> litellm client -> proxy ->
chat-completions) was tested end-to-end with LiteLLM's `mock_response` in a sandbox where
OpenRouter egress is blocked. `/v1/models` lists the aliases, `/v1/chat/completions` returns
correctly, and a wrong key is rejected. On the VM the only change is that the proxy reaches the
real OpenRouter.

## One-time setup (on the T4 VM)
```bash
cd CyberForge/deploy/litellm
uv venv .proxyenv
uv pip install --python .proxyenv/bin/python 'litellm[proxy]'
cp env.proxy.example .env && $EDITOR .env      # set OPENROUTER_API_KEY + LITELLM_MASTER_KEY
```

## Run the proxy
```bash
cd CyberForge/deploy/litellm
set -a && source .env && set +a
./start_proxy.sh              # listens on 0.0.0.0:4000
# quick check (new shell):
curl -s http://localhost:4000/v1/models -H "Authorization: Bearer $LITELLM_MASTER_KEY"
```
Keep it running (tmux/screen or a systemd unit) while you run pilots.

## Point CyberForge at the proxy
In `CyberForge/src/.env`:
```ini
RCHAT_OSS_API_BASE=http://localhost:4000/v1
RCHAT_OSS_API_KEY=any-nonempty-string   # proxy is keyless; value is ignored but must be non-empty
```
Then pass a **bare alias** as the model id:
```bash
uv run vuljector run cjson static_analysis cyberforge-agent --num-vulnerabilities 2
uv run vuljector teacher-collect cjson --model-id cyberforge-teacher \
    --task-modes patch,poc-san --regimes faithful --limit 5
```

## Models
All three aliases point at `openrouter/z-ai/glm-5.3` in `config.yaml`. The `model_name` aliases
stay stable; change the slug in one place if you want a different model. Verify slugs at
<https://openrouter.ai/models>.
- `cyberforge-agent`   -> `openrouter/z-ai/glm-5.3`  (worker/agent)
- `cyberforge-teacher` -> `openrouter/z-ai/glm-5.3`  (teacher-collect)
- `gemma-4-31b-base`   -> `openrouter/z-ai/glm-5.3`  (alias the paper scripts use)

## Alternative: no proxy
Since `OPENROUTER_API_KEY` is already allow-listed by CyberForge's agent env, you can skip the
proxy and pass a provider-prefixed id directly:
```ini
# src/.env
OPENROUTER_API_KEY=sk-or-...
```
```bash
uv run vuljector run cjson static_analysis openrouter/z-ai/glm-5.3 --num-vulnerabilities 2
```
Use the proxy when you want stable aliases, central key/rate-limit/cost control, or to keep the
paper's bare-name scripts working.

## Troubleshooting (common T4 issues)
- **`ModuleNotFoundError: No module named 'prisma'`** — this build of litellm routes requests
  through its DB-backed key auth when `master_key` is set. This config ships **keyless** (no
  `general_settings`/`master_key`) to avoid that; don't re-add `master_key` unless you also install
  and generate prisma.
- **401 from proxy** — only if you re-enabled `master_key`; keyless needs no client key.
- **`NotFoundError: model ... does not exist`** — the bare alias isn't in `config.yaml`
  `model_list`, or you passed a provider-prefixed id that bypassed the proxy. Check
  `curl /v1/models`.
- **Connection refused from vuljector** — proxy not running, wrong port, or (if CyberForge runs in
  a container that isn't host-networked) `localhost` doesn't reach the host; use the host IP or
  `--network host`. With mini-swe-agent the LLM call is made from the **host** process, so
  `localhost:4000` normally works.
- **OpenRouter 402 / rate limit** — out of credits or model requires more; pick another slug or
  top up. `drop_params: true` is set so unsupported params won't hard-fail.
- **Long agent runs time out** — `request_timeout: 600` is set in `config.yaml`; raise if needed.
- **TLS/verify errors** — CyberForge sets `litellm.ssl_verify=False` and `PYTHONHTTPSVERIFY=0`
  automatically when `RCHAT_OSS_API_BASE` is set, so the local http proxy is fine.
