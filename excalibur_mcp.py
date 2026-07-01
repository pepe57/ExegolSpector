# /// script
# requires-python = ">=3.10"
# dependencies = ["mcp[cli]>=1.2.0"]
# ///
"""Excalibur MCP server — agentic interface between Hermes and nuclei.

Exposes a small, focused toolset (not 65 — just what a bug-bounty loop needs):

    excalibur_scan     run nuclei against a target, return a run handle
    excalibur_report   parse a nuclei run into a submission-ready report (scope-enforced)
    excalibur_scope_check   test whether a host is in scope before acting

Run standalone:
    uv run excalibur_mcp.py

Wire into Hermes (~/.hermes/config.yaml):
    mcp_servers:
      - name: excalibur
        transport: stdio
        command: uv
        args: ["run", "/ABSOLUTE/PATH/excalibur_mcp.py"]
        enabled: true
"""
from __future__ import annotations

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

import excalibur as core  # the tested engine lives next door

mcp = FastMCP("excalibur")

# Work area for scans/reports (override with EXCALIBUR_DATA)
import os
DATA = Path(os.environ.get("EXCALIBUR_DATA", Path(__file__).parent / "data"))
DATA.mkdir(parents=True, exist_ok=True)


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name)[:40]


@mcp.tool()
def excalibur_scan(target: str, tags: str = "cve,exposure,misconfig,tech",
                   severity: str = "low,medium,high,critical") -> str:
    """Run nuclei against a target and return a JSON handle to the raw results.

    Args:
        target: URL or host to scan (e.g. https://target.com).
        tags: nuclei -tags filter.
        severity: nuclei -severity filter.

    Returns a JSON string: {jsonl_path, raw_findings, target}.
    """
    jsonl_path = DATA / f"nuclei_{_safe(target)}.jsonl"
    count = core.run_nuclei(target, tags, severity, jsonl_path)
    return json.dumps({
        "target": target,
        "jsonl_path": str(jsonl_path),
        "raw_findings": count,
        "next": "call excalibur_report with this jsonl_path to get a submission report",
    })


@mcp.tool()
def excalibur_report(jsonl_path: str, target: str = "", program: str = "",
                     platform: str = "", scope_file: str = "") -> str:
    """Turn a nuclei JSONL run into a scope-enforced, submission-ready report.

    Args:
        jsonl_path: path returned by excalibur_scan.
        target: target name for the report header.
        program: bug bounty program name.
        platform: ywh | immunefi | hackerone.
        scope_file: optional scope file (JSON or include:/exclude: YAML).
                    Out-of-scope findings are DROPPED before reporting.

    Returns a JSON summary including report_path, counts, and actionable findings.
    """
    p = Path(jsonl_path)
    if not p.exists():
        return json.dumps({"error": f"jsonl not found: {jsonl_path}"})
    target = target or p.stem
    findings = core.parse_jsonl(p)

    dropped = []
    if scope_file:
        scope = core.load_scope(scope_file)
        findings, dropped = core.apply_scope(findings, scope)

    report_md = core.build_report(findings, target, program, platform)
    report_path = DATA / f"report_{_safe(target)}.md"
    report_path.write_text(report_md, encoding="utf-8")

    actionable = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
    return json.dumps({
        "target": target,
        "report_path": str(report_path),
        "total_in_scope": len(findings),
        "actionable": len(actionable),
        "out_of_scope_dropped": len(dropped),
        "severity_counts": core._severity_counts(findings),
        "actionable_findings": [
            {"name": f["name"], "severity": f["severity"], "matched_at": f["matched_at"],
             "cve": f["cve"], "cwe": f["cwe"]} for f in actionable
        ],
    }, ensure_ascii=False)


@mcp.tool()
def excalibur_scope_check(host: str, scope_file: str) -> str:
    """Check whether a host is in scope. Use BEFORE scanning or submitting.

    Args:
        host: hostname or URL to test.
        scope_file: scope file (JSON or include:/exclude: YAML).

    Returns JSON: {host, in_scope: bool}.
    """
    scope = core.load_scope(scope_file)
    return json.dumps({"host": host, "in_scope": core.in_scope(host, scope)})


if __name__ == "__main__":
    mcp.run()
