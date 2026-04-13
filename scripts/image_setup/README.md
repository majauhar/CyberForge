# Image Setup Scripts

This directory contains the scripts added for stricter image setup, fuzz-target validation, and historical bug replay experiments.

## What Changed In This Branch

This clone is focused on making OSS-Fuzz-style project images usable for historical bug reproduction.

Key runtime/setup changes live outside this directory in:
- `src/setup/container_runtime.py`
- `src/vuljector/run_setup.py`
- `src/verifier/pipeline.py`

Those changes make Vuljector behave more strictly during setup and replay:
- `build.sh` is treated as a real setup step instead of a best-effort step.
- ready images are expected to have actual executable fuzz targets in `/out`.
- setup records and reuses `/out` manifests.
- replay experiments can rebuild fuzz targets before validating the vulnerable and secure states.
- the build environment includes a compatibility shim for `LIB_FUZZING_ENGINE` when the default path is stale.

## Scripts

### `audit_project_ready_images.py`

Builds or refreshes ready images for a list of projects, then inspects `/out` and records which executables were actually produced.

Use it when you want to answer:
- did setup succeed cleanly?
- which fuzz targets exist in the image?
- which projects are immediately usable for replay?

Example:

```bash
python3 scripts/image_setup/audit_project_ready_images.py \
  --projects-csv scripts/image_setup/evaluation_projects.csv
```

### `audit_historical_bug_reversal_readiness.py`

Reads a historical bug reproduction manifest and compares the mined `fuzz_target` values against the executables actually built in each project image.

Use it when you want to answer:
- which historical bug records have a local testcase?
- which have a fix commit?
- which name a fuzz target?
- which named fuzz targets are actually present in the built image?

Example:

```bash
python3 scripts/image_setup/audit_historical_bug_reversal_readiness.py \
  --manifest /path/to/reversal_inputs_manifest.jsonl
```

### `run_historical_bug_reversal_experiments.py`

Runs narrow historical bug reversal experiments from a manifest-backed case list.

For each selected case, the script:
- ensures setup has completed,
- resets to the secure base commit,
- tries to reverse the fix commit,
- rebuilds fuzz targets,
- replays the testcase on the reversed state,
- resets to the secure state,
- rebuilds again,
- reruns validation using Vuljector’s verifier flow.

Example:

```bash
python3 scripts/image_setup/run_historical_bug_reversal_experiments.py \
  --manifest /path/to/reversal_inputs_manifest.jsonl \
  --case quickjs:410939009
```

## Project List

`evaluation_projects.csv` is currently scoped to the C/C++ pilot projects:
- `harfbuzz`
- `assimp`
- `openh264`
- `c-blosc`
- `hunspell`
- `hdf5`
- `quickjs`

## Using Vuljector In This Setup

The intended flow in this branch is:

1. Prepare or obtain a historical bug reproduction manifest from the mining clone.
2. Run `audit_project_ready_images.py` to confirm the project images build real fuzz targets.
3. Run `audit_historical_bug_reversal_readiness.py` to compare mined targets against built executables.
4. Run `run_historical_bug_reversal_experiments.py` on a small batch of promising cases.

The standard project setup path is still the normal Vuljector path:

```bash
PYTHONPATH=src python -m vuljector.cli setup quickjs
```

This branch just makes that setup path stricter and more useful for historical bug replay.

## Notes

- This clone is intentionally focused on image setup and replay mechanics, not mining.
- The manifest consumed here is expected to come from the mining clone’s `scripts/reproduction/` pipeline.
- Builds can still be slow on cross-architecture Docker setups, especially when `amd64` images are being built on an `arm64` host.
