"""Tests for the Excalibur engine. Run: python3 -m pytest test_excalibur.py -v

No network, no nuclei binary needed — everything is driven from fixture JSONL
and synthetic findings, so the suite is deterministic and CI-safe.
"""
import json
from pathlib import Path

import excalibur as core


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------
SAMPLE_JSONL = "\n".join([
    json.dumps({
        "template-id": "weak-cipher-suites", "matched-at": "example.com:443",
        "type": "ssl",
        "info": {"name": "Weak Cipher Suites", "severity": "low",
                 "description": "Weak cipher.", "tags": ["ssl"],
                 "classification": {"cve-id": None, "cwe-id": ["cwe-327"]}},
        "extracted-results": ["tls10"]}),
    # duplicate of the above (same template + matched-at) -> must be deduped
    json.dumps({
        "template-id": "weak-cipher-suites", "matched-at": "example.com:443",
        "type": "ssl", "info": {"name": "Weak Cipher Suites", "severity": "low"}}),
    json.dumps({
        "template-id": "CVE-2021-1234", "matched-at": "https://example.com/app",
        "url": "https://example.com/app", "type": "http",
        "info": {"name": "Critical RCE", "severity": "critical",
                 "description": "RCE.", "remediation": "Patch now.",
                 "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"],
                 "classification": {"cve-id": "CVE-2021-1234", "cwe-id": ["cwe-94"]}},
        "curl-command": "curl https://example.com/app"}),
    json.dumps({
        "template-id": "tech-detect", "matched-at": "https://example.com",
        "type": "http", "info": {"name": "Tech Detect", "severity": "info"}}),
    json.dumps({
        "template-id": "leak", "matched-at": "https://admin.example.com/secret",
        "type": "http", "info": {"name": "Secret Leak", "severity": "high"}}),
    "",  # blank line — must be skipped
    "{ not valid json",  # garbage — must be skipped
])


def _write(tmp_path, name, content) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# --------------------------------------------------------------------------
# parse_jsonl
# --------------------------------------------------------------------------
def test_parse_dedup_and_skip_garbage(tmp_path):
    f = _write(tmp_path, "s.jsonl", SAMPLE_JSONL)
    findings = core.parse_jsonl(f)
    # 4 valid unique templates (dup removed, blank + garbage skipped)
    ids = [x["template_id"] for x in findings]
    assert ids.count("weak-cipher-suites") == 1
    assert len(findings) == 4


def test_parse_sorts_by_severity(tmp_path):
    f = _write(tmp_path, "s.jsonl", SAMPLE_JSONL)
    findings = core.parse_jsonl(f)
    # critical must come before high before low before info
    sevs = [x["severity"] for x in findings]
    assert sevs.index("critical") < sevs.index("high") < sevs.index("low") < sevs.index("info")


def test_parse_extracts_cve_cwe_and_curl(tmp_path):
    f = _write(tmp_path, "s.jsonl", SAMPLE_JSONL)
    findings = {x["template_id"]: x for x in core.parse_jsonl(f)}
    rce = findings["CVE-2021-1234"]
    assert rce["cve"] == ["CVE-2021-1234"]
    assert rce["cwe"] == ["cwe-94"]
    assert rce["curl"] == "curl https://example.com/app"
    assert rce["remediation"] == "Patch now."


# --------------------------------------------------------------------------
# scope
# --------------------------------------------------------------------------
def test_load_scope_json(tmp_path):
    f = _write(tmp_path, "sc.json", json.dumps({"include": ["*.x.com"], "exclude": ["a.x.com"]}))
    scope = core.load_scope(f)
    assert scope == {"include": ["*.x.com"], "exclude": ["a.x.com"]}


def test_load_scope_yaml(tmp_path):
    y = "include:\n  - '*.x.com'\n  - x.com\nexclude:\n  - admin.x.com\n"
    f = _write(tmp_path, "sc.yaml", y)
    scope = core.load_scope(f)
    assert "*.x.com" in scope["include"]
    assert "admin.x.com" in scope["exclude"]


def test_in_scope_include_exclude():
    scope = {"include": ["*.x.com", "x.com"], "exclude": ["admin.x.com"]}
    assert core.in_scope("https://api.x.com/p", scope) is True
    assert core.in_scope("x.com:443", scope) is True
    assert core.in_scope("admin.x.com", scope) is False        # excluded
    assert core.in_scope("evil.com", scope) is False           # not included
    assert core.in_scope("x.com.attacker.net", scope) is False  # suffix spoof


def test_in_scope_empty_include_is_permissive():
    scope = {"include": [], "exclude": ["bad.com"]}
    assert core.in_scope("anything.com", scope) is True
    assert core.in_scope("bad.com", scope) is False


def test_apply_scope_splits(tmp_path):
    f = _write(tmp_path, "s.jsonl", SAMPLE_JSONL)
    findings = core.parse_jsonl(f)
    scope = {"include": ["example.com", "*.example.com"], "exclude": ["admin.example.com"]}
    keep, drop = core.apply_scope(findings, scope)
    # the admin.example.com "Secret Leak" high finding must be dropped
    assert any(x["template_id"] == "leak" for x in drop)
    assert all(x["template_id"] != "leak" for x in keep)


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------
def test_build_report_contains_actionable_and_appendix(tmp_path):
    f = _write(tmp_path, "s.jsonl", SAMPLE_JSONL)
    findings = core.parse_jsonl(f)
    md = core.build_report(findings, "example.com", "Prog", "ywh")
    assert "# Bug Bounty Report — example.com" in md
    assert "Critical RCE" in md          # actionable block
    assert "CVE-2021-1234" in md
    assert "curl https://example.com/app" in md  # reproduction
    assert "Appendix — informational" in md      # info goes to appendix
    assert "Tech Detect" in md


def test_severity_counts():
    findings = [{"severity": "low"}, {"severity": "low"}, {"severity": "info"}]
    assert core._severity_counts(findings) == {"low": 2, "info": 1}
