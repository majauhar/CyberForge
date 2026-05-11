# scripts/

Offline utilities and operational helpers for preparing, analyzing, and
manually exercising the Vuljector pipeline.

Most scripts do not require a running container or API key. Fuzzing/manual
helpers are grouped separately under `scripts/fuzzing/`.

---

## `select_projects.py` — OSS-Fuzz project selector

Reads `oss_fuzz_full.csv` (1 339 OSS-Fuzz projects with GitHub metadata, CVE data, and
fuzzing configuration) and selects a balanced subset for pipeline runs.

### Hard filters (project is dropped if any fail)

| Filter | Rule |
|---|---|
| Dockerfile present | `has_dockerfile = Yes` |
| Language | `python`, `c`, `c++`, or `javascript` |
| LOC range | 4 000 – 1 000 000 |
| ASAN | required for `c` / `c++`; JS is exempt |

### Priority ranking (within each language group)

1. LOC in sweet zone `[25k – 200k]`
2. GitHub stars (descending)
3. Days since last push (ascending)
4. NVD CVE count (descending)
5. OSS-Fuzz quality score (descending)

### Quota logic

`--total N` is split equally across three groups: **Python**, **C/C++**, **JavaScript**.
If a group can't fill its share (JS is typically the bottleneck), the shortfall is
redistributed to the groups that still have supply.

Domain minimums are guaranteed first (crypto ≥ 4, networking ≥ 4, data-parsing ≥ 3,
web-framework ≥ 3, database ≥ 2) before filling language quotas.

### Usage

```bash
# default: select 300 projects, write selected_projects.json
python scripts/select_projects.py

# custom total and output path
python scripts/select_projects.py --total 100 --out my_selection.json

# point at a different CSV
python scripts/select_projects.py --csv scripts/oss_fuzz_full.csv --total 50

# exclude already initialized projects
python scripts/select_projects.py \
  --csv scripts/oss_fuzz_full.csv \
  --total 200 \
  --exclude-dir /home/anl31/documents/code/vuljector/vuljector-projects \
  --out scripts/selected_projects.json

# exclude a previous selection JSON to produce a non-overlapping next batch
python scripts/select_projects.py \
  --csv scripts/oss_fuzz_full.csv \
  --total 200 \
  --exclude-json scripts/selected_projects.json \
  --out scripts/selected_projects_next.json
```

`--exclude-dir` and `--exclude-json` are related but not redundant:

- `--exclude-dir` skips projects that already exist as subdirectories under a local workspace such as `vuljector-projects/`.
- `--exclude-json` skips names from an earlier selection file, which is useful before those projects have been initialized or when you want a second non-overlapping batch.

### Output

A JSON file with a `meta` block (filters, quotas, priority order) and a `projects` array.
Each entry includes `name`, `github_slug`, `main_repo`, `language`, `domains`, `loc`,
`github_stars`, `nvd_cve_count`, `nvd_cwes`, and the `selection_reason` (which pass picked it).

```json
{
  "meta": {
    "total_selected": 300,
    "quotas": { "python": 101, "c_cpp": 101, "javascript": 18 },
    ...
  },
  "projects": [
    {
      "name": "curl",
      "github_slug": "curl/curl",
      "language": "c",
      "domains": ["networking", "crypto"],
      "loc": 173210,
      "github_stars": 35800,
      "nvd_cve_count": 187,
      "selection_reason": "domain_min:networking"
    },
    ...
  ]
}
```

The output file can then be fed directly to batch pipeline runs via `scripts/batch_init.sh`.
