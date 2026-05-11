# Fuzzing Scripts

Utilities in this directory support fuzz-guided selection, patch-guided
validation, and manual experiment workflows.

## Layout

- `*.py`: reusable CLI helpers for offline metadata mining, harness mapping,
  result normalization, and validation summaries.
- `test_fuzz_native_pipeline.sh`: end-to-end smoke script for the fuzz-native
  pipeline.
- `manual/`: ad hoc experiment launchers that are safe to keep in-repo. They
  write logs under `runs/manual_fuzz_validation/`, which is already git-ignored.

## Conventions

- Scripts should resolve paths relative to the repo root so they can be run
  from any working directory.
- Scripts that import modules from `src/` should prepend `src/` to
  `PYTHONPATH`/`sys.path` explicitly.
- Manual launchers must never embed secrets. Set provider credentials in the
  shell environment before running them.
