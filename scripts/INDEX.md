# Mining Scripts

The mining scripts are organized by job.

## `fetch_sources/`

Pull raw records from external sources.

Main entry points:
- `fetch_sources/mine_oss_fuzz_osv_records.py`
- `fetch_sources/mine_cross_ecosystem_osv_records.py`
- `fetch_sources/mine_arvo_records.py`
- `fetch_sources/mine_oss_fuzz_issue_tracker_records.py`
- `fetch_sources/discover_oss_fuzz_issue_tracker_records.py`
- `fetch_sources/mine_github_issue_records.py`
- `fetch_sources/mine_oss_fuzz_failure_records.py`

## `build_records/`

Merge or normalize mined records into richer corpora and indexes.

Main entry points:
- `build_records/build_rich_oss_fuzz_records.py`
- `build_records/build_canonical_vulnerability_index.py`
- `build_records/build_legacy_vulnerability_index.py`
- `build_records/cache_oss_fuzz_issue_pages.py`

## `reproduction/`

Turn mined metadata into local reproduction assets.

Main entry points:
- `reproduction/download_oss_fuzz_testcases.py`
- `reproduction/build_historical_bug_reproduction_manifest.py`

## `mining_helpers/`

Shared helper modules used by the entry-point scripts. These are not usually run directly.

## Suggested Order

1. Run one or more source miners in `fetch_sources/`.
2. Build rich records with `build_records/build_rich_oss_fuzz_records.py`.
3. Build a canonical index with `build_records/build_canonical_vulnerability_index.py`.
4. Download testcase blobs with `reproduction/download_oss_fuzz_testcases.py`.
5. Build a historical bug reproduction manifest with `reproduction/build_historical_bug_reproduction_manifest.py`.

## Notes

- `scripts/oss_fuzz_full.csv` is the shared project metadata CSV used by several miners.
- The scripts are designed to run from anywhere; each one resolves repo-relative paths on its own.
