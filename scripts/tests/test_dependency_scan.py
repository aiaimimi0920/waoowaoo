"""Exercise actual pinned OSV scanner/reporter binaries on synthetic fixtures."""
from pathlib import Path
import json
import os
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dependency_scan import (BinaryRunner, ScanError, complete_scan, inventory,
                             report, scan, validate_report, validate_sarif, findings_exit)


class RealBinaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("GITHUB_ACTIONS") != "true" or sys.platform != "linux":
            raise unittest.SkipTest("Real pinned binaries run on hosted Ubuntu")
        cls.advisory = json.loads((Path(__file__).parent / "fixtures/osv-known-vulnerability.json")
                                  .read_text(encoding="utf-8"))

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="osv-binary-fixture-")
        self.addCleanup(self.directory.cleanup)
        parent = Path(self.directory.name)
        self.root = parent / "project"
        self.root.mkdir()
        self.out = parent / "output"
        self.runner = BinaryRunner(self.root, self.out)
        # This tiny offline DB is fixed test data, never a production exception.
        for suffix in ["osv-scalibr/Go/all.zip"]:
            archive = self.out / "db" / suffix
            archive.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(archive, "w") as stream:
                stream.writestr("GO-2021-0053.json", json.dumps(self.advisory))

    def fixture(self, version="1.3.2"):
        (self.root / "go.mod").write_text(
            f"module fixture\n\ngo 1.24.10\n\nrequire github.com/gogo/protobuf v{version}\n",
            encoding="utf-8")
        return scan(self.runner, "go.mod",
                    ["--offline-vulnerabilities", "--local-db-path=/evidence/db", "--no-resolve"])

    def test_healthy_input_is_completed_with_nonempty_package_inventory(self):
        self.runner.verify_versions()
        status = self.fixture()
        self.assertEqual(status, 0)
        facts = complete_scan(self.runner, status, "go.mod")
        self.assertTrue(facts["analysis_complete"])
        self.assertGreater(facts["package_count"], 0)
        self.assertEqual(facts["sarif_result_count"], 0)
        self.assertEqual(findings_exit(facts), 0)
        self.assertEqual(findings_exit(facts, advisory=True), 0)
        self.assertEqual(facts["extracted_package_count"], 2)
        self.assertEqual(facts["package_count"], 1)
        self.assertEqual(facts["go_module_inventory"], [{"name": "github.com/gogo/protobuf",
                         "version": "1.3.2", "ecosystem": "Go"}])

    def test_known_vulnerability_retains_exit_and_sarif(self):
        status = self.fixture("1.3.1")
        self.assertEqual(status, 1)
        facts = complete_scan(self.runner, status, "go.mod")
        self.assertEqual(facts["scanner_exit"], 1)
        self.assertEqual(facts["reporter_exit"], 1)
        self.assertGreater(facts["sarif_result_count"], 0)
        self.assertTrue(facts["report_valid"])
        self.assertEqual(findings_exit(facts), 1)
        self.assertEqual(findings_exit(facts, advisory=True), 0)
        self.assertEqual(facts["scanner_exit"], 1)
        self.assertEqual(facts["reporter_exit"], 1)

    def test_real_sarif_same_count_wrong_identity_is_rejected(self):
        self.assertEqual(self.fixture("1.3.1"), 1)
        facts = complete_scan(self.runner, 1, "go.mod")
        self.assertTrue(facts["sarif_identity_complete"])
        original = json.loads((self.out / "results.sarif").read_text(encoding="utf-8"))
        for mode in ["package", "version", "uri", "fingerprint", "alias"]:
            modified = json.loads(json.dumps(original))
            row = modified["runs"][0]["results"][0]
            if mode == "package":
                row["message"]["text"] = row["message"]["text"].replace("github.com/gogo/protobuf", "fixture/other")
            elif mode == "version":
                row["message"]["text"] = row["message"]["text"].replace("1.3.1", "1.3.2")
            elif mode == "uri":
                row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "other.lock"
            elif mode == "fingerprint":
                row["partialFingerprints"]["primaryLocationLineHash"] = "0" * 64
            else:
                modified["runs"][0]["tool"]["driver"]["rules"][0]["deprecatedIds"] = []
            (self.out / "results.sarif").write_text(json.dumps(modified), encoding="utf-8")
            with self.subTest(mode=mode), self.assertRaisesRegex(ScanError, "sarif_identity_coverage_failed"):
                validate_report(self.runner, facts, 1, facts["reporter_exit"])


    def test_missing_json_reproduces_upstream_zero_but_guard_rejects_it(self):
        self.assertEqual(report(self.runner, "/evidence/missing.json"), 0)
        self.assertEqual(validate_sarif(self.out / "results.sarif", 0), 0)
        with self.assertRaises(ScanError):
            complete_scan(self.runner, 0, "go.mod")

    def test_malformed_json_reproduces_upstream_zero_but_guard_rejects_it(self):
        (self.out / "results.json").write_text("PRIVATE_MALFORMED_FIXTURE", encoding="utf-8")
        self.assertEqual(report(self.runner), 0)
        self.assertEqual(validate_sarif(self.out / "results.sarif", 0), 0)
        with self.assertRaises(ScanError):
            complete_scan(self.runner, 0, "go.mod")

    def test_unsupported_scanner_exit_cannot_reuse_valid_results(self):
        self.assertEqual(self.fixture(), 0)
        status = self.runner.execute("osv-scanner", ["scan", "--definitely-invalid"], offline=True)
        self.assertNotIn(status, {0, 1})
        with self.assertRaisesRegex(ScanError, "scanner_execution_failed"):
            complete_scan(self.runner, status, "go.mod")

    def test_zero_input_is_a_real_scanner_failure(self):
        (self.root / "package-lock.json").write_text(json.dumps({
            "name": "empty-fixture", "lockfileVersion": 3,
            "packages": {"": {"name": "empty-fixture", "version": "1.0.0"}}
        }), encoding="utf-8")
        status = scan(self.runner, "package-lock.json", ["--offline-vulnerabilities",
                      "--local-db-path=/evidence/db", "--no-resolve"])
        self.assertNotIn(status, {0, 1})
        with self.assertRaises(ScanError):
            complete_scan(self.runner, status, "package-lock.json")

    def test_empty_json_inventory_is_not_completed_analysis(self):
        (self.out / "results.json").write_text('{"results":[]}', encoding="utf-8")
        with self.assertRaisesRegex(ScanError, "missing_package_inventory"):
            complete_scan(self.runner, 0, "go.mod")

    def test_reporter_nonstandard_exit_remains_a_failure(self):
        self.assertEqual(self.fixture(), 0)
        facts = inventory(self.out / "results.json", 0, "go.mod")
        status = self.runner.execute("osv-reporter", ["--new=/evidence/results.json",
                                     "--output-files=unsupported:/tmp/results.sarif",
                                     "--fail-on-vuln=true"], offline=True)
        self.assertNotIn(status, {0, 1})
        self.assertGreater(facts["package_count"], 0)
        with self.assertRaisesRegex(ScanError, "reporter_execution_failed"):
            validate_report(self.runner, facts, 0, status)

    def test_reporter_zero_cannot_replace_known_vulnerability_results(self):
        self.assertEqual(self.fixture("1.3.1"), 1)
        facts = inventory(self.out / "results.json", 1, "go.mod")
        self.assertEqual(report(self.runner, "/evidence/missing.json"), 0)
        with self.assertRaisesRegex(ScanError, "reporter_result_mismatch"):
            validate_report(self.runner, facts, 1, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
