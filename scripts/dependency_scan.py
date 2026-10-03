"""Run pinned OSV binaries with exit-status and artifact checks before upload."""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import uuid
from pathlib import Path

from check_security_inputs import validate
from security_report import ReportError, write_step_summary
from sarif_coverage import CoverageError, expected_findings, expected_row_count, validate_coverage

IMAGE = "ghcr.io/google/osv-scanner-action@sha256:dcd947131d8d11b8d0964de6590661fb921a4ecbd7b90a7cb21083acfc3fd8cc"
VERSION = "2.5.1"
MAX_BYTES = 20 * 1024 * 1024
MAX_PACKAGES = 100_000


class ScanError(ValueError):
    """Only constant error codes may reach the job log."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ScanError(code)


def no_duplicate_keys(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "invalid_result_json")
        result[key] = value
    return result


def read_json(path: Path) -> dict:
    require(not path.is_symlink(), "unsafe_result_file")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "unsafe_result_file")
            raw = stream.read(MAX_BYTES + 1)
        require(len(raw) <= MAX_BYTES, "result_limit_exceeded")
        document = json.loads(raw, object_pairs_hook=no_duplicate_keys,
                              parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except ScanError:
        raise
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise ScanError("missing_or_invalid_result_json") from None
    require(isinstance(document, dict), "invalid_result_json")
    return document


def inventory(path: Path, scanner_exit: int, lockfile: str) -> dict:
    require(scanner_exit in {0, 1}, "scanner_execution_failed")
    document = read_json(path)
    sources = document.get("results")
    require(isinstance(sources, list) and 0 < len(sources) <= 100,
            "missing_package_inventory")
    package_count = vulnerability_count = 0
    occurrences = set()
    go_modules = set()
    for source in sources:
        require(isinstance(source, dict), "invalid_package_inventory")
        location = source.get("source")
        require(isinstance(location, dict) and location.get("type") == "lockfile"
                and location.get("path") == "/github/workspace/" + lockfile,
                "unexpected_scanned_input")
        packages = source.get("packages")
        require(isinstance(packages, list) and bool(packages), "missing_package_inventory")
        package_count += len(packages)
        require(package_count <= MAX_PACKAGES, "result_limit_exceeded")
        for entry in packages:
            require(isinstance(entry, dict), "invalid_package_inventory")
            package = entry.get("package")
            require(isinstance(package, dict), "invalid_package_inventory")
            for field in ["name", "version", "ecosystem"]:
                require(isinstance(package.get(field), str)
                        and 0 < len(package[field]) <= 512, "invalid_package_inventory")
            if lockfile == "go.mod":
                go_modules.add((package["name"], package["version"], package["ecosystem"]))
            vulnerabilities = entry.get("vulnerabilities", [])
            groups = entry.get("groups", [])
            require(isinstance(vulnerabilities, list) and isinstance(groups, list),
                    "invalid_vulnerability_inventory")
            identifiers = set()
            for vulnerability in vulnerabilities:
                require(isinstance(vulnerability, dict)
                        and isinstance(vulnerability.get("id"), str)
                        and 0 < len(vulnerability["id"]) <= 160,
                        "invalid_vulnerability_inventory")
                identifiers.add(vulnerability["id"])
            grouped = set()
            for group in groups:
                require(isinstance(group, dict) and isinstance(group.get("ids"), list)
                        and bool(group["ids"]), "invalid_vulnerability_inventory")
                ids = group["ids"]
                require(all(isinstance(item, str) and 0 < len(item) <= 160 for item in ids),
                        "invalid_vulnerability_inventory")
                grouped.update(ids)
                occurrences.add((location["path"], package["name"], package["version"],
                                 package["ecosystem"], tuple(sorted(ids))))
            require(identifiers <= grouped, "ungrouped_vulnerability_inventory")
            vulnerability_count += len(identifiers)
    require(bool(vulnerability_count) == (scanner_exit == 1), "scanner_result_mismatch")
    facts = {"package_count": package_count, "vulnerability_records": vulnerability_count,
             "expected_sarif_results": expected_row_count(document)}
    if lockfile == "go.mod":
        require(len(go_modules) <= 500, "result_limit_exceeded")
        facts["go_module_inventory"] = [dict(zip(["name", "version", "ecosystem"], row))
                                         for row in sorted(go_modules)]
    return facts


def validate_sarif(path: Path, expected: int) -> int:
    document = read_json(path)
    runs = document.get("runs")
    require(document.get("version") == "2.1.0" and isinstance(runs, list)
            and len(runs) == 1, "invalid_reporter_sarif")
    run = runs[0]
    require(isinstance(run, dict), "invalid_reporter_sarif")
    tool = run.get("tool")
    require(isinstance(tool, dict) and isinstance(tool.get("driver"), dict),
            "invalid_reporter_sarif")
    require(tool["driver"].get("name") == "osv-scanner"
            and tool["driver"].get("version") == VERSION, "unexpected_reporter_tool")
    results = run.get("results")
    require(isinstance(results, list) and len(results) == expected,
            "reporter_result_mismatch")
    require(all(isinstance(item, dict) and isinstance(item.get("ruleId"), str)
                for item in results), "invalid_reporter_sarif")
    return len(results)


class BinaryRunner:
    """Only hosted CI may run these credential-free, owned containers."""

    def __init__(self, root: Path, evidence: Path):
        require(os.environ.get("GITHUB_ACTIONS") == "true"
                and sys.platform == "linux", "hosted_linux_required")
        self.root = root.resolve()
        self.evidence = evidence.resolve()
        self.evidence.mkdir(parents=True, exist_ok=True)
        self.counter = 0

    def execute(self, binary: str, arguments: list[str], *, offline: bool = False) -> int:
        require(binary in {"osv-scanner", "osv-reporter"}, "invalid_tool")
        name = "osv-gate-" + uuid.uuid4().hex
        command = ["docker", "run", "--detach", "--name", name, "--read-only",
                   "--cap-drop=ALL", "--memory=1g", "--cpus=2",
                   "--tmpfs", "/tmp:rw,nosuid,noexec,size=128m",
                   "--env", "XDG_CACHE_HOME=/tmp/cache",
                   "--mount", f"type=bind,source={self.root},target=/github/workspace,readonly",
                   "--mount", f"type=bind,source={self.evidence},target=/evidence,readonly",
                   "--workdir", "/github/workspace", "--entrypoint", "/bin/sh"]
        if offline:
            command.extend(["--network", "none"])
        command.extend([IMAGE, "-c", "while :; do sleep 30; done"])
        self.counter += 1
        log = self.evidence / f"tool-{self.counter}.log"
        try:
            with log.open("wb") as stream:
                started = subprocess.run(command, stdin=subprocess.DEVNULL,
                                         stdout=subprocess.DEVNULL, stderr=stream,
                                         timeout=60, check=False)
                require(started.returncode == 0, "container_start_failed")
                result = subprocess.run(["docker", "exec", name, "/root/" + binary,
                                         *arguments], stdin=subprocess.DEVNULL,
                                        stdout=stream, stderr=stream, timeout=600,
                                        check=False)
            if result.returncode in {0, 1} and "--version" not in arguments:
                output_name = "results.json" if binary == "osv-scanner" else "results.sarif"
                with (self.evidence / output_name).open("wb") as artifact:
                    copy = subprocess.run(["docker", "exec", name, "cat", "/tmp/" + output_name],
                                          stdout=artifact, stderr=subprocess.DEVNULL,
                                          timeout=30, check=False)
                require(copy.returncode == 0, "missing_tool_output")
            if result.returncode not in {0, 1}:
                diagnostic = log.read_bytes()[:4096].lower()
                categories = [label for label, marker in [
                    ("permission_denied", b"permission denied"),
                    ("read_only_filesystem", b"read-only file system"),
                    ("invalid_argument", b"flag provided but not defined"),
                    ("missing_input", b"no such file"),
                    ("no_packages", b"no packages")
                ] if marker in diagnostic]
                print(json.dumps({"tool": binary, "exit": result.returncode,
                                  "error_categories": categories}))
            return result.returncode
        except (OSError, subprocess.SubprocessError):
            raise ScanError("tool_execution_failed") from None
        finally:
            # The UUID belongs to this invocation, never an existing container.
            subprocess.run(["docker", "rm", "--force", name],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=30, check=False)

    def verify_versions(self) -> None:
        for binary in ["osv-scanner", "osv-reporter"]:
            status = self.execute(binary, ["--version"], offline=True)
            require(status == 0, "tool_version_failed")
            log = (self.evidence / f"tool-{self.counter}.log").read_bytes()[:4096]
            require(re.search(rb"osv-scanner version:\s*2\.5\.1(?:\s|$)", log) is not None,
                    "unexpected_tool_version")


def scan(runner: BinaryRunner, lockfile: str, extra: list[str] | None = None) -> int:
    arguments = ["scan", "--all-packages", "--format=json",
                 "--output-file=/tmp/results.json", "--lockfile=/github/workspace/" + lockfile]
    if lockfile == "go.mod":
        arguments.append("--no-call-analysis=go")
    arguments.extend(extra or [])
    status = runner.execute("osv-scanner", arguments, offline=bool(extra))
    log = (runner.evidence / f"tool-{runner.counter}.log").read_bytes()[:MAX_BYTES]
    match = re.search(rb"Scanned /github/workspace/" + re.escape(lockfile.encode())
                      + rb" file and found ([0-9]+) packages", log)
    runner.extracted_package_count = int(match.group(1)) if match else None
    return status


def report(runner: BinaryRunner, new: str = "/evidence/results.json") -> int:
    return runner.execute("osv-reporter", ["--new=" + new, "--fail-on-vuln=true",
                          "--output-files=sarif:/tmp/results.sarif"], offline=True)


def validate_report(runner: BinaryRunner, facts: dict, scanner_exit: int,
                    reporter_exit: int) -> dict:
    require(reporter_exit in {0, 1}, "reporter_execution_failed")
    source_document = read_json(runner.evidence / 'results.json')
    sarif_document = read_json(runner.evidence / 'results.sarif')
    semantic_expected = None
    coverage_error = None
    identity_complete = False
    try:
        identities, _ = expected_findings(source_document)
        semantic_expected = len(identities)
        identity_complete = validate_coverage(source_document, sarif_document)['sarif_identity_complete']
    except (CoverageError, KeyError, TypeError, AttributeError) as error:
        coverage_error = str(error) if isinstance(error, CoverageError) else 'invalid_identity_structure'
    runs = sarif_document.get('runs', [])
    actual = len(runs[0].get('results', [])) if isinstance(runs, list) and len(runs) == 1 else None
    if actual != facts['expected_sarif_results'] or not identity_complete:
        print(json.dumps({'analysis_complete': False, 'report_valid': False,
            'error_kind': 'sarif_identity_diagnostic',
            'scanner_exit': scanner_exit, 'reporter_exit': reporter_exit,
            'package_count': facts['package_count'], 'vulnerability_records': facts['vulnerability_records'],
            'expected_local_group_occurrences': facts['expected_sarif_results'],
            'expected_semantic_occurrences': semantic_expected, 'actual_sarif_rows': actual,
            'identity_verification_complete': identity_complete, 'coverage_error': coverage_error}))
    count = validate_sarif(runner.evidence / "results.sarif", facts["expected_sarif_results"])
    require(reporter_exit == scanner_exit, "reporter_exit_mismatch")
    try:
        coverage = validate_coverage(read_json(runner.evidence / 'results.json'),
                                     read_json(runner.evidence / 'results.sarif'))
    except (CoverageError, KeyError, TypeError, AttributeError):
        raise ScanError('sarif_identity_coverage_failed') from None
    return {**facts, "sarif_result_count": count, "scanner_exit": scanner_exit,
            "reporter_exit": reporter_exit, "analysis_complete": True,
            "report_valid": True, **coverage}


def complete_scan(runner: BinaryRunner, scanner_exit: int, lockfile: str) -> dict:
    facts = inventory(runner.evidence / "results.json", scanner_exit, lockfile)
    facts["extracted_package_count"] = getattr(runner, "extracted_package_count", None)
    return validate_report(runner, facts, scanner_exit, report(runner))


def findings_exit(facts: dict, advisory: bool = False) -> int:
    require(facts.get("analysis_complete") is True and facts.get("report_valid") is True
            and facts.get('sarif_identity_complete') is True,
            "incomplete_scan_cannot_be_advisory")
    scanner_exit, reporter_exit = facts.get("scanner_exit"), facts.get("reporter_exit")
    require(type(scanner_exit) is int and scanner_exit in {0, 1}
            and type(reporter_exit) is int and reporter_exit == scanner_exit,
            "unexpected_findings_exit")
    count, expected = facts.get("sarif_result_count"), facts.get("expected_sarif_results")
    require(type(count) is int and type(expected) is int and 0 <= count <= MAX_PACKAGES
            and count == expected and bool(count) == (scanner_exit == 1),
            "invalid_advisory_report")
    facts.update(policy="development_advisory" if advisory else "strict",
                 findings_present=scanner_exit == 1, findings_exit=scanner_exit,
                 report_success=advisory or scanner_exit == 0)
    return 0 if advisory else scanner_exit


def set_upload_output(valid: bool) -> None:
    destination = os.environ.get("GITHUB_OUTPUT")
    if destination:
        with open(destination, "a", encoding="utf-8") as stream:
            stream.write("report_valid=" + str(valid).lower() + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ecosystem", choices=["gomod", "npm"])
    parser.add_argument("--advisory", action="store_true")
    args = parser.parse_args()
    set_upload_output(False)
    try:
        root = Path.cwd().resolve()
        validate(root, args.ecosystem)
        evidence = root / ".tmp/dependency-security"
        require(evidence.resolve().is_relative_to(root)
                and not any(path.is_symlink() for path in [root / ".tmp", evidence]),
                "unsafe_evidence_directory")
        runner = BinaryRunner(root, evidence)
        for name in ["results.json", "results.sarif"]:
            (evidence / name).unlink(missing_ok=True)
        runner.verify_versions()
        lockfile = "go.mod" if args.ecosystem == "gomod" else "package-lock.json"
        scanner_exit = scan(runner, lockfile)
        facts = complete_scan(runner, scanner_exit, lockfile)
        status = findings_exit(facts, args.advisory)
        set_upload_output(True)
        write_step_summary("Dependency security", facts)
        print(json.dumps(facts, sort_keys=True))
        return status
    except ReportError:
        facts.update(report_success=False, error_kind="reporting_failure",
                     error="summary_write_failed")
        print(json.dumps(facts, sort_keys=True))
        return 2
    except ScanError as error:
        print(json.dumps({"analysis_complete": False, "report_valid": False,
                          "error_kind": "tool_or_artifact_failure", "error": str(error)}))
        return 2
    except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
        print(json.dumps({"analysis_complete": False, "report_valid": False,
                          "error_kind": "tool_or_artifact_failure",
                          "error": "invalid_scan_inputs_or_execution"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
