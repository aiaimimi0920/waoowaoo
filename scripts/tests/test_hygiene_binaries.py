"""Hosted-only, synthetic offline binary fixtures; no live credentials."""
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hygiene_scan import HygieneError, scan_gitleaks, scan_zizmor, validate_findings

BINARIES = Path.cwd() / ".tmp/security-tools"

class RealHygieneTests(unittest.TestCase):
    def test_synthetic_secret_preserves_raw_exit_and_redacts_report(self):
        with tempfile.TemporaryDirectory(prefix="leak-fixture-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            synthetic = "gh" + "p_" + "aB7cD9eF2gH4iJ6kL8mN0oP3qR5sT1uV2wX4"
            (source / "fixture.txt").write_text("token = " + synthetic, encoding="utf-8")
            status, rows = scan_gitleaks(BINARIES / "gitleaks", source, root / "evidence", "dir")
            self.assertEqual(status, 10)
            self.assertGreater(len(rows), 0)
            report, process_status = validate_findings("gitleaks", status, rows, True)
            self.assertEqual(process_status, 0)
            self.assertEqual(report["finding_count"], len(rows))
            self.assertEqual(validate_findings("gitleaks", status, rows)[1], 1)
            self.assertNotIn(synthetic, str(report))
    def test_clean_secret_fixture_is_valid_zero(self):
        with tempfile.TemporaryDirectory(prefix="clean-fixture-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            (source / "fixture.txt").write_text("ordinary harmless fixture", encoding="utf-8")
            status, rows = scan_gitleaks(BINARIES / "gitleaks", source, root / "evidence", "dir")
            self.assertEqual(status, 0)
            self.assertEqual(rows, [])
            self.assertEqual(validate_findings("gitleaks", status, rows, True)[1], 0)
    def test_real_zizmor_finding_keeps_high_exit(self):
        with tempfile.TemporaryDirectory(prefix="audit-fixture-") as temporary:
            root = Path(temporary)
            workflow = root / "fixture.yml"
            workflow.write_text("name: fixture\non: issues\npermissions: {}\njobs:\n  fixture:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo ${{ github.event.issue.title }}\n", encoding="utf-8")
            status, rows = scan_zizmor(BINARIES / "zizmor", workflow, root / "evidence")
            self.assertEqual(status, 14)
            self.assertTrue(any(r["ident"] == "template-injection" for r in rows))
            self.assertEqual(validate_findings("zizmor", status, rows, True)[1], 0)
            self.assertEqual(validate_findings("zizmor", status, rows)[1], 1)
    def test_bad_yaml_cannot_report_success(self):
        with tempfile.TemporaryDirectory(prefix="bad-audit-fixture-") as temporary:
            root = Path(temporary)
            workflow = root / "fixture.yml"
            workflow.write_text("jobs: [unterminated", encoding="utf-8")
            with self.assertRaises((HygieneError, ValueError)):
                scan_zizmor(BINARIES / "zizmor", workflow, root / "evidence")

if __name__ == "__main__":
    unittest.main(verbosity=2)
