"""Generate a CVE JSON 5.0 advisory for an injected vulnerability."""

from __future__ import annotations

import csv
import json
import logging
import math
from datetime import UTC, datetime
from pathlib import Path

from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, run_agent_task
from utils.agent.prompts import CVE_REPORT_TASK, SECURITY_SYSTEM_TEMPLATE
from utils.paths import cwe_categories_csv

logger = logging.getLogger(__name__)


def _load_cwe_map() -> dict[str, tuple[str, str]]:
    """Return {cwe_id: (description, group)} loaded from the approved CWE CSV."""
    result: dict[str, tuple[str, str]] = {}
    with cwe_categories_csv().open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            result[f"CWE-{row['CWE#'].strip()}"] = (
                row["Description"].strip(),
                row["CWE Group"].strip(),
            )
    return result


_CWE_MAP: dict[str, tuple[str, str]] = _load_cwe_map()


def generate_cve_report(
    *,
    runtime: ContainerRuntime,
    project: str,
    vulnerability_id: str,
    model_id: str,
    patch_diff: str,
    exploit_script: str,
    intended_cwe_group: str,
    intended_cwe_id: str,
) -> str:
    """Run a mini-swe-agent task in the project container to produce a CVE JSON 5.0 record.

    The agent analyses the diff and exploit, writes /tmp/cve_analysis.json with the
    security findings, and this function assembles the final CVE record.
    Returns the JSON string, or an empty string on failure.
    """
    task_prompt = CVE_REPORT_TASK.format(
        project=project,
        patch_diff=patch_diff,
        exploit_script=exploit_script,
        intended_cwe_group=intended_cwe_group or "unknown",
        intended_cwe_id=intended_cwe_id or "unknown",
    )

    agent_req = AgentRequest(
        model_id=model_id,
        prompt=task_prompt,
        workdir=runtime.repo_dir_in_container,
        system_template=SECURITY_SYSTEM_TEMPLATE,
        step_limit=8,
        cost_limit=0.5,
        extract_paths=["/tmp/cve_analysis.json"],
    )

    # Make the approved CWE list available inside the container for validation.
    runtime.copy_to(cwe_categories_csv(), "/tmp/cwe_categories.csv")

    logger.info("[%s] Generating CVE report (model=%s, vuln=%s)", project, model_id, vulnerability_id)
    resp = run_agent_task(runtime, agent_req)

    analysis_raw = resp.extracted_files.get("/tmp/cve_analysis.json", "")
    if not analysis_raw:
        logger.warning("[%s] CVE report: agent did not produce /tmp/cve_analysis.json", project)
        return ""

    return _assemble_cve_record(
        project=project,
        vulnerability_id=vulnerability_id,
        intended_cwe_group=intended_cwe_group,
        intended_cwe_id=intended_cwe_id,
        analysis_raw=analysis_raw,
    )


def _cvss31_score(vector: str) -> tuple[float, str]:
    """Compute CVSS 3.1 base score and severity from a vector string.

    Returns (score, severity) or (0.0, "") on parse failure.
    """
    AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC  = {"L": 0.77, "H": 0.44}
    PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
    PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed
    UI  = {"N": 0.85, "R": 0.62}
    CIA = {"N": 0.00, "L": 0.22, "H": 0.56}

    try:
        parts = dict(m.split(":") for m in vector.split("/")[1:])
        scope = parts["S"]
        pr_table = PR_C if scope == "C" else PR_U
        ess = 8.22 * AV[parts["AV"]] * AC[parts["AC"]] * pr_table[parts["PR"]] * UI[parts["UI"]]
        isc_base = 1 - (1 - CIA[parts["C"]]) * (1 - CIA[parts["I"]]) * (1 - CIA[parts["A"]])
        if isc_base <= 0:
            return 0.0, "NONE"
        isc = 6.42 * isc_base if scope == "U" else 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        raw = min(isc + ess, 10.0) if scope == "U" else min(1.08 * (isc + ess), 10.0)
        score = math.ceil(raw * 10) / 10
    except (KeyError, ValueError, ZeroDivisionError):
        return 0.0, ""

    if score == 0.0:
        severity = "NONE"
    elif score < 4.0:
        severity = "LOW"
    elif score < 7.0:
        severity = "MEDIUM"
    elif score < 9.0:
        severity = "HIGH"
    else:
        severity = "CRITICAL"
    return score, severity


def write_cve_report(vuln_dir: Path, report_json: str) -> None:
    """Write the CVE JSON record to ``<vuln_dir>/cve_report.json``."""
    (vuln_dir / "cve_report.json").write_text(report_json, encoding="utf-8")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _assemble_cve_record(
    *,
    project: str,
    vulnerability_id: str,
    intended_cwe_group: str,
    intended_cwe_id: str,
    analysis_raw: str,
) -> str:
    try:
        analysis = json.loads(analysis_raw)
    except json.JSONDecodeError as exc:
        logger.warning("[%s] CVE analysis JSON parse error: %s", project, exc)
        return ""

    # Infer group from the approved CWE list based on what the agent selected.
    selected_cwe_id = analysis.get("cwe_id", "")
    cwe_entry = _CWE_MAP.get(selected_cwe_id)
    if cwe_entry:
        cwe_group = cwe_entry[1]
    else:
        logger.warning("[%s] cwe_id %r not found in approved list, falling back to intended group", project, selected_cwe_id)
        cwe_group = intended_cwe_group

    cvss_score, cvss_severity = _cvss31_score(analysis.get("cvss_vector", ""))

    cve_id = f"CVE-VULJECTOR-{project}-{vulnerability_id}"
    record = {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.0.0",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "containers": {
            "cna": {
                "providerMetadata": {"shortName": "Vuljector"},
                "title": analysis.get("title", ""),
                "descriptions": [{"lang": "en", "value": analysis.get("description", "")}],
                "affected": [{
                    "vendor": "open-source",
                    "product": project,
                    "versions": [{"version": "0", "status": "affected"}],
                    "defaultStatus": "unknown",
                }],
                "problemTypes": [{
                    "descriptions": [{
                        "lang": "en",
                        "description": f"{analysis.get('cwe_id', '')}: {analysis.get('vulnerability_type', '')}",
                        "cweId": analysis.get("cwe_id", ""),
                        "type": "CWE",
                    }],
                }],
                "metrics": [{
                    "cvssV3_1": {
                        "version": "3.1",
                        "vectorString": analysis.get("cvss_vector", ""),
                        "baseScore": cvss_score,
                        "baseSeverity": cvss_severity,
                    },
                    "scenarios": [{"lang": "en", "value": "GENERAL"}],
                }],
                "references": [{"url": f"https://github.com/vuljector/vuljector-projects/{project}"}],
                "x_vuljector": {
                    "vulnerability_id": vulnerability_id,
                    "intended_cwe_group": intended_cwe_group,
                    "intended_cwe_id": intended_cwe_id,
                    "cwe_group": cwe_group,
                    "impact": analysis.get("impact", ""),
                    "proof_of_concept": analysis.get("proof_of_concept", ""),
                    "fix": analysis.get("fix", ""),
                },
            },
        },
    }

    logger.info("[%s] CVE record assembled: %s", project, cve_id)
    return json.dumps(record, indent=2)
