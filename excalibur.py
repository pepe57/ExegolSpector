#!/usr/bin/env python3
"""Excalibur — bug-bounty reporting orchestrator.

Does NOT reinvent scanning. It drives the real tools you already have
(nuclei, optionally subfinder/httpx), parses their JSONL, dedupes and
ranks findings, and emits submission-ready Markdown reports — the one
thing nuclei and Mando do not produce.

Pipeline:  target -> [subfinder] -> [httpx] -> nuclei -jsonl -> parse -> report

Usage:
    excalibur.py -u https://target.com
    excalibur.py -u https://target.com --tags cve,exposure --severity medium,high,critical
    excalibur.py --jsonl existing-nuclei-output.jsonl        # report from a prior scan
    excalibur.py -u https://target.com --program "Acme YWH" --platform ywh -o out/
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


def which_or_die(binary: str) -> str:
    path = shutil.which(binary) or shutil.which(f"/opt/homebrew/bin/{binary}")
    if not path:
        sys.exit(f"[!] required tool not found on PATH: {binary}")
    return path


def run_nuclei(target: str, tags: str, severity: str, out_jsonl: Path) -> int:
    """Run nuclei against a single target, writing JSONL. Returns finding count."""
    nuclei = which_or_die("nuclei")
    cmd = [nuclei, "-u", target, "-jsonl", "-o", str(out_jsonl), "-silent"]
    if tags:
        cmd += ["-tags", tags]
    if severity:
        cmd += ["-severity", severity]
    print(f"[*] running: {' '.join(cmd)}", file=sys.stderr)
    try:
        subprocess.run(cmd, check=False, timeout=1800)
    except subprocess.TimeoutExpired:
        print("[!] nuclei timed out (30m cap); using partial results", file=sys.stderr)
    return sum(1 for _ in out_jsonl.open()) if out_jsonl.exists() else 0


def parse_jsonl(path: Path) -> list[dict]:
    """Load nuclei JSONL into normalized finding dicts, deduped by (template, matched-at)."""
    seen: set[tuple] = set()
    findings: list[dict] = []
    for line in path.open("r", encoding="utf-8"):
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = raw.get("info", {})
        classification = info.get("classification") or {}
        key = (raw.get("template-id"), raw.get("matched-at"))
        if key in seen:
            continue
        seen.add(key)
        findings.append({
            "template_id": raw.get("template-id", "unknown"),
            "name": info.get("name", raw.get("template-id", "Unknown")),
            "severity": (info.get("severity") or "unknown").lower(),
            "description": (info.get("description") or "").strip(),
            "remediation": (info.get("remediation") or "").strip(),
            "tags": info.get("tags") or [],
            "references": info.get("reference") or [],
            "cve": _as_list(classification.get("cve-id")),
            "cwe": _as_list(classification.get("cwe-id")),
            "matched_at": raw.get("matched-at") or raw.get("host", ""),
            "url": raw.get("url") or raw.get("matched-at", ""),
            "type": raw.get("type", ""),
            "extracted": raw.get("extracted-results") or [],
            "curl": (raw.get("curl-command") or "").strip(),
            "template_url": raw.get("template-url", ""),
        })
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 5), f["name"]))
    return findings


def _as_list(val) -> list:
    if not val:
        return []
    return val if isinstance(val, list) else [val]


# ---------------------------------------------------------------------------
# Scope enforcement — the critical guard before any submission.
# A scope file is simple YAML-ish/JSON:  {"include": [...], "exclude": [...]}
# Patterns are shell globs matched against the finding host (e.g. "*.target.com").
# ---------------------------------------------------------------------------
import fnmatch
import re as _re


def load_scope(path) -> dict:
    """Load a scope file (JSON, or a minimal include:/exclude: YAML). Never raises."""
    if not path:
        return {"include": [], "exclude": []}
    p = Path(path)
    if not p.exists():
        return {"include": [], "exclude": []}
    text = p.read_text(encoding="utf-8")
    # Try JSON first
    try:
        data = json.loads(text)
        return {"include": _as_list(data.get("include")), "exclude": _as_list(data.get("exclude"))}
    except json.JSONDecodeError:
        pass
    # Minimal YAML: lines under `include:` / `exclude:` as `- pattern`
    include, exclude, bucket = [], [], None
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("include:"):
            bucket = include
            continue
        if s.startswith("exclude:"):
            bucket = exclude
            continue
        if s.startswith("- ") and bucket is not None:
            bucket.append(s[2:].strip().strip("'\""))
    return {"include": include, "exclude": exclude}


def _host_of(matched_at: str) -> str:
    """Extract bare host from a matched-at value (strip scheme, port, path)."""
    h = _re.sub(r"^[a-z]+://", "", matched_at or "")
    h = h.split("/")[0].split(":")[0]
    return h.lower()


def in_scope(matched_at: str, scope: dict) -> bool:
    """True if host matches an include pattern and no exclude pattern.

    Empty include list = permissive (everything in, minus excludes).
    """
    host = _host_of(matched_at)
    if not host:
        return False
    for pat in scope.get("exclude", []):
        if fnmatch.fnmatch(host, pat.lower()):
            return False
    includes = scope.get("include", [])
    if not includes:
        return True
    return any(fnmatch.fnmatch(host, pat.lower()) for pat in includes)


def apply_scope(findings: list[dict], scope: dict) -> tuple[list[dict], list[dict]]:
    """Split findings into (in_scope, out_of_scope)."""
    keep, drop = [], []
    for f in findings:
        (keep if in_scope(f["matched_at"], scope) else drop).append(f)
    return keep, drop


def _severity_counts(findings: list[dict]) -> dict:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def build_report(findings: list[dict], target: str, program: str, platform: str) -> str:
    """Render submission-ready Markdown from parsed findings."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = _severity_counts(findings)

    lines = [
        f"# Bug Bounty Report — {target}",
        "",
        f"- **Program**: {program or '(unspecified)'}",
        f"- **Platform**: {platform or '(unspecified)'}",
        f"- **Generated**: {now}",
        f"- **Total findings**: {len(findings)}",
        "",
        "## Severity summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in sorted(counts, key=lambda s: SEV_ORDER.get(s, 5)):
        lines.append(f"| {SEV_EMOJI.get(sev,'')} {sev} | {counts[sev]} |")
    lines += ["", "---", ""]

    # Only actionable severities get a full submission block
    actionable = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
    if not actionable:
        lines.append("_No actionable (low+) findings — only informational detections._\n")

    for i, f in enumerate(actionable, 1):
        lines += _finding_block(i, f)

    # Informational appendix, compact
    info_only = [f for f in findings if f["severity"] == "info"]
    if info_only:
        lines += ["## Appendix — informational detections", ""]
        for f in info_only:
            extra = f" — {', '.join(f['extracted'][:3])}" if f["extracted"] else ""
            lines.append(f"- `{f['template_id']}` {f['name']} @ {f['matched_at']}{extra}")
        lines.append("")

    return "\n".join(lines)


def _finding_block(idx: int, f: dict) -> list[str]:
    sev = f["severity"]
    block = [
        f"## {idx}. {SEV_EMOJI.get(sev,'')} {f['name']} ({sev})",
        "",
        f"- **Affected**: `{f['matched_at']}`",
        f"- **Template**: [{f['template_id']}]({f['template_url']})" if f["template_url"]
        else f"- **Template**: `{f['template_id']}`",
    ]
    if f["cve"]:
        block.append(f"- **CVE**: {', '.join(f['cve'])}")
    if f["cwe"]:
        block.append(f"- **CWE**: {', '.join(str(c).upper() for c in f['cwe'])}")
    if f["extracted"]:
        block.append(f"- **Evidence**: {', '.join(str(e) for e in f['extracted'][:5])}")
    block.append("")

    if f["description"]:
        block += ["### Description", "", f["description"], ""]
    if f["curl"]:
        block += ["### Reproduction", "", "```bash", f["curl"], "```", ""]
    if f["remediation"]:
        block += ["### Remediation", "", f["remediation"], ""]
    if f["references"]:
        block += ["### References", ""]
        block += [f"- {r}" for r in f["references"][:6]]
        block.append("")
    block += ["---", ""]
    return block


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Excalibur — bug bounty reporting orchestrator")
    ap.add_argument("-u", "--url", help="target URL/host to scan with nuclei")
    ap.add_argument("--jsonl", help="use an existing nuclei JSONL file instead of scanning")
    ap.add_argument("--tags", default="cve,exposure,misconfig,tech",
                    help="nuclei -tags (default: cve,exposure,misconfig,tech)")
    ap.add_argument("--severity", default="low,medium,high,critical",
                    help="nuclei -severity filter (default: low+)")
    ap.add_argument("--program", default="", help="program name for the report header")
    ap.add_argument("--platform", default="", help="ywh | immunefi | hackerone ...")
    ap.add_argument("--scope", default="", help="scope file (JSON or include:/exclude: YAML)")
    ap.add_argument("--json", action="store_true", help="also emit machine-readable JSON summary")
    ap.add_argument("-o", "--outdir", default=".", help="output directory")
    args = ap.parse_args(argv)

    if not args.url and not args.jsonl:
        ap.error("provide -u/--url to scan, or --jsonl to report from an existing scan")

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.jsonl:
        jsonl_path = Path(args.jsonl)
        target = args.url or jsonl_path.stem
        if not jsonl_path.exists():
            sys.exit(f"[!] JSONL not found: {jsonl_path}")
    else:
        target = args.url
        safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
        jsonl_path = outdir / f"nuclei_{safe}.jsonl"
        n = run_nuclei(target, args.tags, args.severity, jsonl_path)
        print(f"[+] nuclei produced {n} raw finding line(s)", file=sys.stderr)

    findings = parse_jsonl(jsonl_path)

    # Scope enforcement — drop out-of-scope BEFORE building a submittable report
    dropped: list[dict] = []
    if args.scope:
        scope = load_scope(args.scope)
        findings, dropped = apply_scope(findings, scope)
        if dropped:
            print(f"[!] {len(dropped)} finding(s) dropped as OUT OF SCOPE", file=sys.stderr)

    report_md = build_report(findings, target, args.program, args.platform)

    safe = "".join(c if c.isalnum() else "_" for c in target)[:40]
    report_path = outdir / f"report_{safe}.md"
    report_path.write_text(report_md, encoding="utf-8")

    actionable = [f for f in findings if f["severity"] in ("critical", "high", "medium", "low")]
    print(f"[+] {len(findings)} in-scope finding(s), {len(actionable)} actionable -> {report_path}",
          file=sys.stderr)

    if args.json:
        summary = {
            "target": target,
            "report_path": str(report_path),
            "total_in_scope": len(findings),
            "actionable": len(actionable),
            "out_of_scope_dropped": len(dropped),
            "severity_counts": _severity_counts(findings),
            "actionable_findings": [
                {"name": f["name"], "severity": f["severity"], "matched_at": f["matched_at"],
                 "cve": f["cve"], "cwe": f["cwe"]} for f in actionable
            ],
        }
        print(json.dumps(summary, indent=2, ensure_ascii=False))

    # Exit code contract for agentic loops:
    #   0 = no actionable findings   2 = actionable findings present
    return 2 if actionable else 0


if __name__ == "__main__":
    raise SystemExit(main())
