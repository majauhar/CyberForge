# CyberForge Pilot — VM Runbook

Reproducing [CyberForge (arXiv:2608.06471)](https://cyb3rforge.github.io) at **pilot scale**
(a few projects, a handful of injected vulnerabilities), not the full 80-project / 1,034-instance
corpus. Models are served via OpenRouter (GLM 5.3) through a local LiteLLM proxy
(see `deploy/litellm/`).

This runbook is for the **VM** (Docker + open network). The data-generation phases run inside
OSS-Fuzz Docker containers and need container registries + Hugging Face.

---

## 0. Verified in the cloud sandbox
- Install clean (`uv sync`); `vuljector` CLI works; 23/23 bundled unit tests pass.
- Selection phase (`static_analysis`) runs host-side (no container, no LLM): produced 30 candidates.
- LiteLLM proxy wiring verified end-to-end with mock responses (see `deploy/litellm/README.md`).

Blocked in the sandbox (work on the VM): container registries (`registry-1.docker.io`, `gcr.io`),
`huggingface.co`, and `openrouter.ai` — all 403 by egress policy.

---

## 1. Prerequisites (VM)
- Linux x86_64, Python >= 3.13, [`uv`](https://github.com/astral-sh/uv), Docker (run without sudo).
- Disk: ~5-10 GB per project image; 60 GB free is plenty for a 2-3 project pilot.
- Network: `github.com`, `registry-1.docker.io`, `huggingface.co`, `openrouter.ai`.
```bash
python3 --version && uv --version && docker run --rm hello-world
```

## 2. Code + install
```bash
cd /path/to/CyberForge          # this fork, pulled on the T4
uv sync
uv run vuljector --help
```

## 3. Model access (OpenRouter GLM 5.3 via LiteLLM proxy)
Follow `deploy/litellm/README.md`:
```bash
cd deploy/litellm
uv venv .proxyenv && uv pip install --python .proxyenv/bin/python 'litellm[proxy]'
cp env.proxy.example .env && $EDITOR .env   # OPENROUTER_API_KEY + LITELLM_MASTER_KEY
set -a && source .env && set +a && ./start_proxy.sh   # keep running (tmux)
```
Then in `CyberForge/src/.env`:
```ini
RCHAT_OSS_API_BASE=http://localhost:4000/v1
RCHAT_OSS_API_KEY=<same as LITELLM_MASTER_KEY>
```
Model ids are bare aliases: `cyberforge-agent`, `cyberforge-teacher` (both -> `z-ai/glm-5.3`).

## 4. Get ONE prebuilt project (skip OSS-Fuzz + `init`)
The HF dataset ships initialized project defs with prebuilt Docker Hub images; no OSS-Fuzz clone,
no `init` (which would build from `gcr.io`).
```bash
# from the CyberForge PARENT dir
uv run --project CyberForge python -c "from huggingface_hub import snapshot_download as s; s(repo_id='AmL-hug/cyberforge-projects', repo_type='dataset', local_dir='cyberforge-oss-fuzz-projects')"
ln -s "$(pwd)/cyberforge-oss-fuzz-projects" CyberForge/vuljector-projects
cd CyberForge && ls vuljector-projects | head        # pick a small one: cjson, jq, libpng, c-blosc2
export PILOT=cjson
uv run vuljector setup "$PILOT"                        # pulls vuljector/<project>:setup (no build)
```

## 5. Pilot A — generate a few injected vulnerabilities
```bash
uv run vuljector run "$PILOT" static_analysis cyberforge-agent --num-vulnerabilities 2
uv run vuljector report "$PILOT"
```
Outputs: `runs/injection/<project>/<run_id>/attempt_NN/` and verified cases under
`vuljector-projects/<project>/vulnerabilities/vulnerability_N/`.

Other selection strategies (interchangeable): `static_analysis` (no LLM), `codeql`, `llm_explore`,
`fuzz_guided`.

## 6. Pilot B — teacher trajectories (SFT data)
```bash
uv run vuljector teacher-collect "$PILOT" --model-id cyberforge-teacher \
    --task-modes patch,poc-san --regimes faithful --limit 5
```
Outputs -> `runs/teacher_collection/<project>/<run_id>/` (`collection_summary.json`,
`success_paths.json`, ...).

## 7. (Optional) Fine-tuning
Separate repo `CyberForge-training` (README links `github.com/vuljector/CyberForge-training`) —
does not resolve publicly yet; confirm the URL with the authors. Needs a GPU (paper: 1x H200,
LoRA r=32 a=64 dropout 0.05 lr 1e-4 3 epochs). Out of scope for a CPU data-gen pilot.

## 8. Minimal pilot (copy-paste)
```bash
cd /path/to/CyberForge && uv sync
# proxy up (section 3) and src/.env wired, then:
cd .. && uv run --project CyberForge python -c "from huggingface_hub import snapshot_download as s; s(repo_id='AmL-hug/cyberforge-projects', repo_type='dataset', local_dir='cyberforge-oss-fuzz-projects')"
ln -s "$(pwd)/cyberforge-oss-fuzz-projects" CyberForge/vuljector-projects
cd CyberForge && export PILOT=cjson
uv run vuljector setup "$PILOT"
uv run vuljector run "$PILOT" static_analysis cyberforge-agent --num-vulnerabilities 2
uv run vuljector report "$PILOT"
uv run vuljector teacher-collect "$PILOT" --model-id cyberforge-teacher --task-modes patch,poc-san --regimes faithful --limit 5
```
