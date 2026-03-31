"""Run CodeQL queries and parse results into structured dicts.

Three-tier strategy:
  1. Run `*_pairs.ql`         — taint-tracked paths (source → sink), path_length ≥ 1
  2. Run `*_sinks.ql`         — all sinks + file-scope checkpoint, path_length = 0
  3. Run `*_combinatorial.ql` — all (sink × checkpoint) pairs in same function, path_length = -1

Merge priority:
  - Taint results first, deduped by (sink_file, sink_line, sink_kind).
  - Sink-only fills gaps where taint didn't reach (same dedup key).
  - Combinatorial added as additional candidates, deduped by
    (sink_file, sink_line, sink_kind, cp_file, cp_line) — one per unique pair.
    This mirrors the AST pipeline's BFS pairing but scoped to function level.
"""

from __future__ import annotations

import csv
import logging
import subprocess
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# Language → (pack subdirectory, taint query, sink-only query, combinatorial query)
_LANG_PACKS: dict[str, tuple[str, str, str, str]] = {
    "python":     ("python",     "python_pairs.ql", "python_sinks.ql", "python_combinatorial.ql"),
    "javascript": ("javascript", "js_pairs.ql",     "js_sinks.ql",     "js_combinatorial.ql"),
    "cpp":        ("cpp",        "cpp_pairs.ql",     "cpp_sinks.ql",    "cpp_combinatorial.ql"),
}

# Column headers returned by each query (must match SELECT order in .ql files)
_RESULT_COLUMNS = [
    "sink_url",        # CodeQL URL: file://path:line:col:endline:endcol
    "sink_file",       # absolute file path
    "sink_line",       # line number (int)
    "sink_function",   # enclosing function / method name
    "sink_text",       # source text of the sink expression
    "sink_kind",       # operation type label (e.g. "sql_exec", "subprocess")
    "source_url",      # CodeQL URL of the taint source
    "source_file",     # absolute file path of the source
    "source_line",     # line number of the source (int)
    "cp_url",          # CodeQL URL of checkpoint guard (empty if unsanitized)
    "cp_file",         # file of checkpoint
    "cp_line",         # line of checkpoint (int; 0 if absent)
    "cp_text",         # source text of the guard expression
    "cp_kind",         # checkpoint type label (e.g. "null_check"; empty if absent)
    "path_length",     # call steps source→sink (int); 0 means sink-only (no source)
    "query_id",        # which query produced this result
]


def _ql_root() -> Path:
    """Return the root ql/ directory containing per-language subdirectories."""
    return Path(__file__).parent / "ql"


def run_queries(
    cli: Path,
    db_path: Path,
    language: str,
    project: str,
) -> list[dict]:
    """Run Vuljector QL queries (taint + sink-only) and return merged results.

    Returns a list of result dicts with keys matching _RESULT_COLUMNS.
    Taint-tracked results take priority when the same sink is found by both queries.
    Empty list if the language has no queries.
    """
    pack_info = _LANG_PACKS.get(language)
    if not pack_info:
        logger.warning("[%s] No CodeQL query for language %r — skipping.", project, language)
        return []

    pack_subdir, pairs_ql, sinks_ql, combinatorial_ql = pack_info
    pack_dir = _ql_root() / pack_subdir

    _ensure_qlpack(cli, pack_dir, project)

    # Run all three queries independently (non-fatal on individual failure)
    taint_results        = _run_one_query(cli, db_path, pack_dir / pairs_ql,        language, project)
    sink_results         = _run_one_query(cli, db_path, pack_dir / sinks_ql,         language, project)
    combinatorial_results = _run_one_query(cli, db_path, pack_dir / combinatorial_ql, language, project)

    return _merge(taint_results, sink_results, combinatorial_results, project)


def _merge(
    taint_results: list[dict],
    sink_results: list[dict],
    combinatorial_results: list[dict],
    project: str,
) -> list[dict]:
    """Three-tier merge: taint → sink-only → combinatorial.

    Taint and sink-only are deduplicated by (sink_file, sink_line, sink_kind):
      one result per unique sink location, taint takes priority over sink-only.

    Combinatorial pairs are deduplicated by (sink_file, sink_line, sink_kind, cp_file, cp_line):
      one result per unique (sink, checkpoint) pair — multiple rows per sink are allowed
      because each pair represents a distinct injection scenario.
    """
    def _sink_key(row: dict) -> tuple:
        return (row.get("sink_file", ""), row.get("sink_line", 0), row.get("sink_kind", ""))

    def _pair_key(row: dict) -> tuple:
        return (
            row.get("sink_file", ""), row.get("sink_line", 0), row.get("sink_kind", ""),
            row.get("cp_file", ""),   row.get("cp_line", 0),
        )

    seen_sink: set[tuple] = set()
    seen_pair: set[tuple] = set()
    merged: list[dict] = []

    # Tier 1: taint-tracked (path_length ≥ 1)
    for row in taint_results:
        k = _sink_key(row)
        if k not in seen_sink:
            seen_sink.add(k)
            merged.append(row)

    # Tier 2: sink-only (path_length = 0) — fills gaps not covered by taint
    so_added = 0
    for row in sink_results:
        k = _sink_key(row)
        if k not in seen_sink:
            seen_sink.add(k)
            merged.append(row)
            so_added += 1

    # Tier 3: combinatorial (path_length = -1) — one per (sink, checkpoint) pair
    comb_added = 0
    for row in combinatorial_results:
        k = _pair_key(row)
        if k not in seen_pair:
            seen_pair.add(k)
            merged.append(row)
            comb_added += 1

    logger.info(
        "[%s] Merged: %d taint + %d sink-only + %d combinatorial = %d total",
        project, len(taint_results), so_added, comb_added, len(merged),
    )
    return merged


def _run_one_query(
    cli: Path,
    db_path: Path,
    ql_path: Path,
    language: str,
    project: str,
) -> list[dict]:
    """Compile and run a single QL query, return parsed rows. Non-fatal on failure."""
    if not ql_path.exists():
        logger.warning("[%s] QL query not found, skipping: %s", project, ql_path)
        return []

    with tempfile.NamedTemporaryFile(suffix=".bqrs", delete=False) as tmp_bqrs:
        bqrs_path = Path(tmp_bqrs.name)
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False, mode="w") as tmp_csv:
        csv_path = Path(tmp_csv.name)

    try:
        run_cmd = [
            str(cli), "query", "run",
            str(ql_path),
            f"--database={db_path}",
            f"--output={bqrs_path}",
        ]
        logger.info("[%s] Running CodeQL query: %s", project, ql_path.name)
        logger.debug("[%s] Command: %s", project, " ".join(run_cmd))

        result = subprocess.run(run_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error(
                "[%s] CodeQL query %s failed.\nstdout: %s\nstderr: %s",
                project, ql_path.name, result.stdout, result.stderr,
            )
            # Non-fatal: return empty list so the other query can still contribute
            return []

        decode_cmd = [
            str(cli), "bqrs", "decode",
            str(bqrs_path),
            "--format=csv",
            f"--output={csv_path}",
        ]
        result = subprocess.run(decode_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            logger.error("[%s] bqrs decode failed: %s", project, result.stderr)
            return []

        return _parse_csv(csv_path, language, project)

    finally:
        bqrs_path.unlink(missing_ok=True)
        csv_path.unlink(missing_ok=True)


def _ensure_qlpack(cli: Path, ql_dir: Path, project: str) -> None:
    """Run `codeql pack install` to resolve query pack dependencies (idempotent)."""
    qlpack = ql_dir / "qlpack.yml"
    if not qlpack.exists():
        return

    lock = ql_dir / "codeql-pack.lock.yml"
    if lock.exists():
        return

    logger.info("[%s] Installing QL pack dependencies in %s", project, ql_dir)
    result = subprocess.run(
        [str(cli), "pack", "install", str(ql_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        logger.warning(
            "[%s] `codeql pack install` failed (non-fatal).\nstderr: %s",
            project, result.stderr,
        )


def _parse_csv(csv_path: Path, language: str, project: str) -> list[dict]:
    """Parse decoded CSV output into result dicts."""
    rows: list[dict] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        raw_rows = list(reader)

    if not raw_rows:
        return []

    # Skip header row if present
    data_rows = (
        raw_rows[1:]
        if raw_rows[0] and not raw_rows[0][0].startswith("file://")
        else raw_rows
    )

    for row in data_rows:
        if len(row) < len(_RESULT_COLUMNS):
            row = row + [""] * (len(_RESULT_COLUMNS) - len(row))

        d = dict(zip(_RESULT_COLUMNS, row))
        d["language"] = language

        for field in ("sink_line", "cp_line", "path_length", "source_line"):
            try:
                d[field] = int(d[field]) if d.get(field) else 0
            except (ValueError, TypeError):
                d[field] = 0

        rows.append(d)

    logger.info("[%s] %s returned %d results.", project, Path(csv_path).stem, len(rows))
    return rows
