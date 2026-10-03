"""Check mode boundaries and redacted run reports without executing production."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependency_scan import ScanError, findings_exit
from security_report import ReportError, write_step_summary


class ReportingPolicyTests(unittest.TestCase):
    def facts(self, status=1):
        return {"analysis_complete": True, "report_valid": True, 'sarif_identity_complete': True,
                "scanner_exit": status, "reporter_exit": status,
                "sarif_result_count": status, "expected_sarif_results": status,
                "package_count": 1}

    def test_valid_vulnerability_is_advisory_but_default_remains_strict(self):
        facts = self.facts()
        self.assertEqual(findings_exit(facts), 1)
        self.assertEqual(findings_exit(facts, advisory=True), 0)
        self.assertEqual(facts["findings_exit"], 1)
        self.assertEqual(facts["sarif_result_count"], 1)

    def test_healthy_valid_results_pass_both_modes(self):
        self.assertEqual(findings_exit(self.facts(0)), 0)
        self.assertEqual(findings_exit(self.facts(0), advisory=True), 0)

    def test_unknown_exits_or_unvalidated_results_never_become_advisory_success(self):
        for change in [{"scanner_exit": 127}, {"reporter_exit": 127},
                       {"analysis_complete": False}, {"report_valid": False},
                       {'sarif_identity_complete': False},
                       {"sarif_result_count": 0}, {"expected_sarif_results": 2},
                       {"sarif_result_count": None, "expected_sarif_results": None}]:
            facts = self.facts()
            facts.update(change)
            with self.subTest(change=change), self.assertRaises(ScanError):
                findings_exit(facts, advisory=True)

    def test_summary_is_redacted_and_does_not_create_issues(self):
        with tempfile.TemporaryDirectory(prefix="security-report-fixture-") as directory:
            destination = Path(directory) / "summary.md"
            facts = self.facts()
            findings_exit(facts, advisory=True)
            facts["message"] = "PRIVATE_REPORT_MUST_NOT_BE_EMITTED"
            facts["source"] = "PRIVATE_REPORT_MUST_NOT_BE_EMITTED"
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(destination),
                                        "GITHUB_REPOSITORY": "aiaimimi0920/waoowaoo"}):
                write_step_summary("Dependency security", facts)
                write_step_summary("Dependency security", facts)
            report = destination.read_text(encoding="utf-8")
            self.assertNotIn("PRIVATE_REPORT", report)
            self.assertIn("Preserved scanner/reporter exits: 1/1", report)
            self.assertIn("/security/code-scanning", report)
            self.assertIn("creates no duplicate issues", report)

    def test_summary_write_failure_is_not_suppressed(self):
        with tempfile.TemporaryDirectory(prefix="security-report-fixture-") as directory:
            facts = self.facts()
            findings_exit(facts, advisory=True)
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": directory}):
                with self.assertRaises(ReportError):
                    write_step_summary("Dependency security", facts)


if __name__ == "__main__":
    unittest.main(verbosity=2)
