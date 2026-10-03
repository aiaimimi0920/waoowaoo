"""Write bounded security metadata to a PR run summary, without source content."""
import os
import re
from pathlib import Path


class ReportError(ValueError):
    """Constant errors only; never expose the output path or scanner content."""


def count(value):
    if type(value) is not int or not 0 <= value <= 100_000:
        raise ReportError("invalid_report_count")
    return value


def write_step_summary(kind, facts):
    destination = os.environ.get("GITHUB_STEP_SUMMARY")
    if not destination:
        return
    if kind not in {"CodeQL", "Dependency security"}:
        raise ReportError("invalid_report_kind")
    policies = {"development_advisory": "development advisory",
                "strict": "strict findings gate", "inventory_only": "inventory report"}
    if facts.get("policy") not in policies:
        raise ReportError("invalid_report_policy")
    lines = ["## " + kind, "", "Policy: " + policies[facts["policy"]], ""]
    if kind == "CodeQL":
        lines += [f"Findings: {count(facts['result_count'])}.",
                  f"High or standard-error findings: {count(facts['finding_gate']['blocked_result_count'])}.",
                  "", "| Rule | Count |", "| --- | ---: |"]
        for row in facts["by_rule"][:2_000]:
            if not re.fullmatch(r"[a-z]+/[a-z0-9/-]+", row["rule_id"]):
                raise ReportError("invalid_report_rule")
            lines.append(f"| {row['rule_id']} | {count(row['count'])} |")
    else:
        lines += [f"Inventoried packages: {count(facts['package_count'])}.",
                  f"Dependency SARIF findings: {count(facts['sarif_result_count'])}.",
                  f"Preserved scanner/reporter exits: {count(facts['scanner_exit'])}/{count(facts['reporter_exit'])}."]
    lines += ["", "The workflow uploads complete validated SARIF; verify its upload step status.",
              "Findings are tracked in existing Security alerts; this report creates no duplicate issues."]
    repository = os.environ.get("GITHUB_REPOSITORY", "")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", repository):
        lines += ["", f"[Security alerts](https://github.com/{repository}/security/code-scanning)"]
    try:
        with Path(destination).open("a", encoding="utf-8") as stream:
            stream.write("\n".join(lines) + "\n\n")
    except OSError:
        raise ReportError("summary_write_failed") from None
