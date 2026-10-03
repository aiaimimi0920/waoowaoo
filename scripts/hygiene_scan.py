"""Validate offline CLI findings and emit redacted advisory or strict reports."""
from collections import Counter
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile
from dependency_scan import MAX_BYTES, MAX_PACKAGES, no_duplicate_keys
from security_report import ReportError

VERSIONS = {"gitleaks": "8.30.1", "zizmor": "1.30.1"}
SEVERITIES = {"Informational": 11, "Low": 12, "Medium": 13, "High": 14}

class HygieneError(ValueError):
    pass

def require(condition, code):
    if not condition:
        raise HygieneError(code)

def array_report(path):
    require(not path.is_symlink(), "unsafe_result_file")
    with path.open("rb") as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "unsafe_result_file")
        raw = stream.read(MAX_BYTES + 1)
    require(len(raw) <= MAX_BYTES, "result_limit_exceeded")
    document = json.loads(raw, object_pairs_hook=no_duplicate_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    require(isinstance(document, list) and len(document) <= MAX_PACKAGES, "invalid_finding_array")
    return document

def identity(*parts):
    return hashlib.sha256(json.dumps(parts, ensure_ascii=True).encode()).hexdigest()

def validate_findings(tool, status, findings, advisory=False):
    require(tool in VERSIONS and type(status) is int, "unexpected_tool_status")
    require(isinstance(findings, list) and len(findings) <= MAX_PACKAGES, "invalid_finding_array")
    rules, severities, keys = Counter(), Counter(), []
    for row in findings:
        require(isinstance(row, dict), "invalid_finding")
        if tool == "gitleaks":
            rule = row.get("RuleID")
            source, line, commit = row.get("File"), row.get("StartLine"), row.get("Commit", "")
            require(isinstance(source, str) and 0 < len(source) <= 4096
                    and type(line) is int and line >= 1 and isinstance(commit, str), "invalid_finding_location")
            keys.append(identity(rule, source, line, commit))
        else:
            rule = row.get("ident")
            determination = row.get("determinations")
            require(isinstance(determination, dict) and row.get("ignored") is False, "ignored_or_invalid_finding")
            severity = determination.get("severity")
            require(severity in SEVERITIES, "invalid_finding_severity")
            severities[severity] += 1
            locations = row.get("locations")
            require(isinstance(locations, list) and bool(locations), "missing_finding_location")
            positions = []
            for location in locations:
                require(isinstance(location, dict), "invalid_finding_location")
                point = location.get("concrete", {}).get("location", {}).get("start_point", {})
                source = location.get("symbolic", {}).get("key", {}).get("Local", {}).get("verbatim_path")
                require(isinstance(source, str) and type(point.get("row")) is int
                        and type(point.get("column")) is int, "invalid_finding_location")
                positions.append((source, point["row"], point["column"]))
            keys.append(identity(rule, positions))
        require(isinstance(rule, str) and re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", rule), "unsafe_rule_id")
        rules[rule] += 1
    expected = (10 if findings else 0) if tool == "gitleaks" else (
        max(SEVERITIES[level] for level in severities) if findings else 0)
    require(status == expected, "execution_or_result_mismatch")
    report = {"tool": tool, "version": VERSIONS[tool], "analysis_complete": True,
              "report_valid": True, "raw_exit": status, "finding_count": len(findings),
              "findings_present": bool(findings), "findings_exit": int(bool(findings)),
              "policy": "development_advisory" if advisory else "strict",
              "by_rule": [{"id": rule, "count": count} for rule, count in sorted(rules.items())],
              "by_severity": [{"level": level, "count": count} for level, count in sorted(severities.items())],
              "finding_keys": sorted(keys)}
    return report, 0 if advisory else int(bool(findings))

def execute(binary, arguments, stdout, stderr):
    environment = {key: os.environ[key] for key in [
        "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT"] if key in os.environ}
    with stdout.open("wb") as output, stderr.open("wb") as error:
        result = subprocess.run([str(binary), *arguments], stdout=output, stderr=error,
                                stdin=subprocess.DEVNULL, env=environment, timeout=600, check=False)
    return result.returncode

def scan_gitleaks(binary, root, evidence, mode="git"):
    evidence.mkdir(parents=True, exist_ok=True)
    report = evidence / "gitleaks.json"
    report.unlink(missing_ok=True)
    config = evidence / "default.toml"
    config.write_text("[extend]\nuseDefault = true\n", encoding="utf-8")
    empty_ignore = evidence / "empty-ignore"
    empty_ignore.mkdir(exist_ok=True)
    if mode == "git":
        inventory = subprocess.run(["git", "-C", str(root), "ls-files"], stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, timeout=30, check=False)
        require(inventory.returncode == 0 and bool(inventory.stdout.strip()), "empty_git_input")
        shallow = subprocess.run(["git", "-C", str(root), "rev-parse", "--is-shallow-repository"],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
        require(shallow.returncode == 0 and shallow.stdout.strip() == b"false", "incomplete_git_history")
    arguments = [mode, str(root), "--no-banner", "--no-color", "--redact=100",
                 "--exit-code=10", "--report-format=json", "--report-path=" + str(report),
                 "--config=" + str(config), "--gitleaks-ignore-path=" + str(empty_ignore),
                 "--ignore-gitleaks-allow", "--timeout=540", "--log-level=error"]
    status = execute(binary, arguments, evidence / "gitleaks.stdout", evidence / "gitleaks.stderr")
    require(status in {0, 10}, "gitleaks_execution_failed")
    return status, array_report(report)

def scan_zizmor(binary, target, evidence):
    evidence.mkdir(parents=True, exist_ok=True)
    output = evidence / "zizmor.json"
    output.unlink(missing_ok=True)
    status = execute(binary, ["--offline", "--strict-collection", "--persona=auditor",
                             "--format=json-v1", str(target)], output, evidence / "zizmor.stderr")
    require(status in {0, 11, 12, 13, 14}, "zizmor_execution_failed")
    return status, array_report(output)

def write_summary(reports):
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    lines = ["## Offline security hygiene", "",
             "Only validated findings are advisory; execution/parse/report failures still fail.", ""]
    for report in reports:
        lines += [report["tool"] + ": " + str(report["finding_count"]) + " findings; raw exit " + str(report["raw_exit"]) + ".",
                  "| Rule | Count |", "| --- | ---: |"]
        lines += ["| " + row["id"] + " | " + str(row["count"]) + " |" for row in report["by_rule"]]
        lines.append("")
    lines += ["Artifact contains all tracking keys and counts, with no secrets, source, messages or raw locations.",
              "Gitleaks covers fetched Git history; Zizmor runs offline, so online-only audits are not covered."]
    try:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n\n")
    except OSError:
        raise ReportError("summary_write_failed") from None

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--advisory", action="store_true")
    args = parser.parse_args()
    try:
        root = Path.cwd().resolve()
        private = root / ".tmp/hygiene-private"
        destination = root / ".tmp/redacted/hygiene.json"
        require(not any(p.is_symlink() for p in [root / ".tmp", private,
                destination.parent, destination]), "unsafe_report_path")
        binaries = root / ".tmp/security-tools"
        reports, outcomes = [], []
        with tempfile.TemporaryDirectory(prefix="security-hygiene-") as temporary:
            evidence = Path(temporary)
            for tool in VERSIONS:
                binary = binaries / tool
                require(binary.is_file() and not binary.is_symlink(), "missing_security_tool")
                if tool == "gitleaks":
                    status, findings = scan_gitleaks(binary, root, evidence / tool)
                else:
                    target = root / ".github/workflows"
                    require(target.is_dir() and bool(list(target.glob("*.yml"))), "empty_workflow_input")
                    status, findings = scan_zizmor(binary, target, evidence / tool)
                report, outcome = validate_findings(tool, status, findings, args.advisory)
                reports.append(report)
                outcomes.append(outcome)
            write_summary(reports)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps({"reports": reports}, indent=2) + "\n", encoding="utf-8")
            print(json.dumps({"analysis_complete": True, "policy": "development_advisory" if args.advisory else "strict",
                              "tools": [{"tool": r["tool"], "raw_exit": r["raw_exit"], "finding_count": r["finding_count"]} for r in reports]}))
            return max(outcomes)
    except Exception:
        print(json.dumps({"analysis_complete": False, "report_valid": False,
                          "error": "hygiene_execution_or_report_failed"}))
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
