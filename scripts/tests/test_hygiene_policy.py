"""Meaningful negative boundaries and redaction of validated tool reports."""
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hygiene_scan import HygieneError, validate_findings

class HygienePolicyTests(unittest.TestCase):
    def leak(self):
        return {"RuleID": "github-pat", "File": "PRIVATE_SOURCE.js", "StartLine": 1,
                "Secret": "PRIVATE_SECRET", "Match": "PRIVATE_SOURCE"}
    def audit(self, severity="High"):
        return {"ident": "template-injection", "ignored": False,
                "determinations": {"severity": severity},
                "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "PRIVATE_SOURCE.yml"}}},
                               "concrete": {"location": {"start_point": {"row": 1, "column": 2}},
                                            "feature": "PRIVATE_SECRET"}}]}
    def test_valid_leak_is_advisory_and_default_is_strict(self):
        report, status = validate_findings("gitleaks", 10, [self.leak()])
        self.assertEqual(status, 1)
        report, status = validate_findings("gitleaks", 10, [self.leak()], True)
        self.assertEqual(status, 0)
        self.assertEqual(report["raw_exit"], 10)
        self.assertEqual(report["finding_count"], 1)
        self.assertNotIn("PRIVATE_", json.dumps(report))
        self.assertEqual(len(report["finding_keys"][0]), 64)
    def test_zizmor_severity_exit_codes_preserved(self):
        for severity, code in [("Informational", 11), ("Low", 12), ("Medium", 13), ("High", 14)]:
            report, status = validate_findings("zizmor", code, [self.audit(severity)], True)
            self.assertEqual(status, 0)
            self.assertEqual(report["raw_exit"], code)
            self.assertNotIn("PRIVATE_", json.dumps(report))
    def test_zero_findings_pass_both_modes(self):
        for tool in ["gitleaks", "zizmor"]:
            for advisory in [True, False]:
                self.assertEqual(validate_findings(tool, 0, [], advisory)[1], 0)
    def test_execution_errors_cannot_turn_into_advisory_success(self):
        for tool in ["gitleaks", "zizmor"]:
            for status in [1, 2, 3, 127, -1]:
                with self.subTest(tool=tool, status=status), self.assertRaises(HygieneError):
                    validate_findings(tool, status, [], True)
    def test_zero_cannot_hide_real_findings(self):
        for tool, row in [("gitleaks", self.leak()), ("zizmor", self.audit())]:
            with self.assertRaises(HygieneError):
                validate_findings(tool, 0, [row], True)
    def test_finding_exit_cannot_replace_empty_or_wrong_severity_results(self):
        for tool, status in [("gitleaks", 10), ("zizmor", 14)]:
            with self.assertRaises(HygieneError):
                validate_findings(tool, status, [], True)
        with self.assertRaises(HygieneError):
            validate_findings("zizmor", 13, [self.audit()], True)
    def test_malformed_findings_and_ignores_fail(self):
        for row in [None, {}, {"RuleID": "bad|id", "File": "x", "StartLine": 1}]:
            with self.assertRaises((HygieneError, TypeError, AttributeError)):
                validate_findings("gitleaks", 10, [row], True)
        row = self.audit()
        row["ignored"] = True
        with self.assertRaises(HygieneError):
            validate_findings("zizmor", 14, [row], True)

if __name__ == "__main__":
    unittest.main(verbosity=2)
