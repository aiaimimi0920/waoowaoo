import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("../summarize_codeql_results.py", import.meta.url));
const privateText = "PRIVATE_MESSAGE_SNIPPET_FLOW_TOKEN";

function result() {
  return {
    ruleId: "js/path-injection",
    message: { text: privateText },
    locations: [{ physicalLocation: {
      artifactLocation: { uri: "src/example.ts", uriBaseId: "%SRCROOT%" },
      region: { startLine: 12, snippet: { text: privateText } },
    } }],
    codeFlows: [{ message: { text: privateText } }],
    partialFingerprints: { secret: privateText },
  };
}

function payload(results = [result()]) {
  return {
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "CodeQL", rules: [{
        id: "js/path-injection",
        defaultConfiguration: { level: "warning" },
        properties: { "security-severity": "7.8" },
        fullDescription: { text: privateText },
      }] } },
      invocations: [{ executionSuccessful: true }],
      results,
    }],
  };
}

function inventory(documents, { maxResults, prepare, failOnFindings = false, advisory = false,
  summary = false, brokenSummary = false } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "codeql-summary-"));
  try {
    documents.forEach((document, index) => fs.writeFileSync(
      path.join(directory, `${index}.sarif`),
      typeof document === "string" ? document : JSON.stringify(document),
    ));
    prepare?.(directory);
    const args = [script, directory];
    if (failOnFindings) args.push("--fail-on-findings");
    if (advisory) args.push("--advisory");
    const summaryPath = path.join(directory, "summary.md");
    if (maxResults !== undefined) args.push("--max-results", String(maxResults));
    const output = spawnSync(process.env.PYTHON || "python3", args, {
      encoding: "utf8", timeout: 10_000, maxBuffer: 1_000_000,
      env: { ...process.env, GITHUB_STEP_SUMMARY: brokenSummary ? directory : summary ? summaryPath : "" },
    });
    assert.ifError(output.error);
    assert.equal(output.stderr, "");
    assert.ok(!output.stdout.includes(privateText));
    assert.ok(!output.stdout.includes(directory));
    const summaryText = summary && fs.existsSync(summaryPath) ? fs.readFileSync(summaryPath, "utf8") : "";
    assert.ok(!summaryText.includes(privateText));
    assert.ok(!summaryText.includes(directory));
    return { status: output.status, report: JSON.parse(output.stdout), summaryText };
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
}

test("inventory emits only allowed metadata, not source or private scanner details", () => {
  const { status, report } = inventory([payload()]);
  assert.equal(status, 0);
  assert.equal(report.analysis_complete, true);
  assert.equal(report.inventory_complete, true);
  assert.equal(report.count_kind, "sarif_results_not_github_open_alerts");
  assert.deepEqual(report.results, [{
    rule_id: "js/path-injection", path: "src/example.ts", line: 12,
    level: "warning", security_severity: "7.8",
  }]);
});

test("counts include all files and runs after the emitted-row cap", () => {
  const document = payload([result(), result()]);
  document.runs.push(payload().runs[0]);
  const { status, report } = inventory([document, payload()], { maxResults: 2 });
  assert.equal(status, 0);
  assert.equal(report.result_count, 4);
  assert.equal(report.file_count, 2);
  assert.equal(report.run_count, 3);
  assert.equal(report.emitted_count, 2);
  assert.equal(report.omitted_count, 2);
  assert.equal(report.truncated, true);
  assert.deepEqual(report.by_rule, [{ rule_id: "js/path-injection", count: 4 }]);
});

test("valid zero and parser warnings remain distinguishable from analysis failures", () => {
  const document = payload([]);
  document.runs[0].invocations[0].toolExecutionNotifications = [
    { level: "warning", message: { text: privateText } },
  ];
  const { status, report } = inventory([document]);
  assert.equal(status, 0);
  assert.equal(report.result_count, 0);
  assert.equal(report.diagnostics.warning_count, 1);
  assert.equal(report.analysis_complete, true);
});

for (const mode of ["failed", "error"]) {
  test(`scanner ${mode} preserves findings but marks analysis incomplete`, () => {
    const document = payload();
    const invocation = document.runs[0].invocations[0];
    if (mode === "failed") invocation.executionSuccessful = false;
    else invocation.toolExecutionNotifications = [{ level: "error", message: { text: privateText } }];
    const { status, report } = inventory([document]);
    assert.equal(status, 2);
    assert.equal(report.error, "analysis_incomplete");
    assert.equal(report.inventory_complete, true);
    assert.equal(report.analysis_complete, false);
    assert.equal(report.result_count, 1);
  });
}

for (const document of ["not JSON", {}, { version: "2.1.0", runs: [] }]) {
  test(`malformed SARIF cannot produce complete zero: ${JSON.stringify(document)}`, () => {
    const { status, report } = inventory([document]);
    assert.equal(status, 2);
    assert.equal(report.inventory_complete, false);
    assert.equal(report.analysis_complete, false);
    assert.equal(report.result_count, undefined);
  });
}

test("missing SARIF files fail closed", () => {
  const { status, report } = inventory([]);
  assert.equal(status, 2);
  assert.equal(report.error, "missing_sarif");
});

for (const uri of ["../secret", "/tmp/secret", "https://host/path", "a?token=secret", "a%2F..%2Fsecret", "a\nsecret"]) {
  test(`unsafe location is rejected: ${JSON.stringify(uri)}`, () => {
    const document = payload();
    document.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = uri;
    const { status, report } = inventory([document]);
    assert.equal(status, 2);
    assert.equal(report.error, "invalid_location");
    assert.equal(report.result_count, undefined);
  });
}

test("invalid results after the output cap still invalidate the inventory", () => {
  const document = payload([result(), result()]);
  document.runs[0].results[1].ruleId = privateText;
  const { status, report } = inventory([document], { maxResults: 1 });
  assert.equal(status, 2);
  assert.equal(report.inventory_complete, false);
});

test("indexed artifacts and rule references retain severity", () => {
  const document = payload();
  const run = document.runs[0];
  run.artifacts = [{ location: { uri: "src/indexed.ts", uriBaseId: "%SRCROOT%" } }];
  run.results[0].ruleIndex = 0;
  delete run.results[0].ruleId;
  run.results[0].locations[0].physicalLocation.artifactLocation = { index: 0 };
  const { status, report } = inventory([document]);
  assert.equal(status, 0);
  assert.equal(report.results[0].path, "src/indexed.ts");
  assert.equal(report.results[0].security_severity, "7.8");
});

test("SARIF extension component references use extension rules", () => {
  const document = payload();
  const run = document.runs[0];
  run.tool.extensions = [{ name: "extensions", rules: [{
    id: "rust/path-injection", properties: { "security-severity": "8.1" },
  }] }];
  run.results[0].rule = { index: 0, toolComponent: { index: 0, name: "extensions" } };
  delete run.results[0].ruleId;
  const { status, report } = inventory([document]);
  assert.equal(status, 0);
  assert.equal(report.results[0].rule_id, "rust/path-injection");
  assert.equal(report.results[0].security_severity, "8.1");
});

test("symlink SARIF inputs are rejected", { skip: process.platform === "win32" }, () => {
  const { status, report } = inventory([payload()], { prepare(directory) {
    fs.symlinkSync(path.join(directory, "0.sarif"), path.join(directory, "linked.sarif"));
  } });
  assert.equal(status, 2);
  assert.equal(report.error, "unsafe_input");
});

test("oversized SARIF files are rejected before parsing", () => {
  const { status, report } = inventory([payload()], { prepare(directory) {
    fs.truncateSync(path.join(directory, "0.sarif"), 20 * 1024 * 1024 + 1);
  } });
  assert.equal(status, 2);
  assert.equal(report.error, "input_limit_exceeded");
});

test("workflow preserves full scanning, source coverage and private SARIF boundary", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/codeql.yml", import.meta.url), "utf8");
  for (const required of [
    'CODEQL_ACTION_DIFF_INFORMED_QUERIES: "false"', "queries: security-extended",
    "language: javascript-typescript", "language: actions",
    "category: /language:${{ matrix.language }}", "output: .tmp/codeql-results",
    "node --test scripts/tests/codeql-summary.test.mjs",
    "python3 scripts/summarize_codeql_results.py .tmp/codeql-results --advisory",
    "if: ${{ !cancelled() }}", "security-events: write",
  ]) assert.ok(workflow.includes(required), `missing workflow contract: ${required}`);
  assert.ok(!workflow.includes("upload-artifact"));
  assert.ok(!workflow.includes("continue-on-error"));
});

test("invalid output limits fail without a finding count", () => {
  const { status, report } = inventory([payload()], { maxResults: 0 });
  assert.equal(status, 2);
  assert.equal(report.result_count, undefined);
});

test("missing execution evidence cannot report completed analysis", () => {
  const document = payload([]);
  delete document.runs[0].invocations;
  const { status, report } = inventory([document]);
  assert.equal(status, 2);
  assert.equal(report.error, "missing_execution_status");
  assert.equal(report.analysis_complete, false);
});

test("invalid CLI arguments produce a safe error without counts", () => {
  const { status, report } = inventory([payload()], { maxResults: privateText });
  assert.equal(status, 2);
  assert.equal(report.error, "invalid_arguments");
  assert.equal(report.result_count, undefined);
});
test("all CodeQL actions are immutable and Go extraction requires a build", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/codeql.yml", import.meta.url), "utf8");
  for (const line of workflow.matchAll(/uses:\s+(\S+)/g)) assert.match(line[1], /@[a-f0-9]{40}$/);
  if (workflow.includes("language: go")) {
    assert.ok(workflow.includes("build-mode: manual"));
    assert.ok(workflow.includes("go test ./..."));
    assert.ok(workflow.includes("go build ./..."));
  }
});

for (const [label, severity, level, expected] of [
  ["below high warning", "6.9", "warning", 0],
  ["high threshold is inclusive", "7", "warning", 1],
  ["high 7.8 is retained", "7.8", "warning", 1],
  ["standard error below high", "6.1", "error", 1],
  ["standard error without security severity", null, "error", 1],
  ["warning without security severity", null, "warning", 0],
]) test(`finding gate handles ${label}`, () => {
  const document = payload();
  document.runs[0].results[0].level = level;
  document.runs[0].tool.driver.rules[0].properties =
    severity === null ? {} : { "security-severity": severity };
  const { status, report } = inventory([document], { failOnFindings: true });
  assert.equal(status, expected);
  assert.equal(report.analysis_complete, true);
  assert.equal(report.result_count, 1);
  assert.equal(report.results.length, 1);
  assert.equal(report.finding_gate.blocked_result_count, expected);
  assert.equal(report.finding_gate.passed, expected === 0);
  if (expected) assert.equal(report.error_kind, "finding_gate");
});
test("empty completed analysis passes enforced finding gate", () => {
  const { status, report } = inventory([payload([])], { failOnFindings: true });
  assert.equal(status, 0);
  assert.equal(report.finding_gate.passed, true);
  assert.equal(report.result_count, 0);
});
test("high findings beyond emitted cap still fail while totals remain", () => {
  const document = payload([result(), result()]);
  document.runs[0].tool.driver.rules[0].properties = { "security-severity": "6.9" };
  document.runs[0].tool.driver.rules.push({
    id: "js/code-injection", properties: { "security-severity": "7.8" },
  });
  document.runs[0].results[1].ruleId = "js/code-injection";
  const { status, report } = inventory([document], { maxResults: 1, failOnFindings: true });
  assert.equal(status, 1);
  assert.equal(report.result_count, 2);
  assert.equal(report.omitted_count, 1);
  assert.equal(report.finding_gate.blocked_result_count, 1);
  assert.equal(report.by_rule.find(row => row.rule_id === "js/code-injection").count, 1);
});
test("diagnostic failures retain their separate classification with the finding gate", () => {
  const document = payload();
  document.runs[0].invocations[0].executionSuccessful = false;
  const { status, report } = inventory([document], { failOnFindings: true });
  assert.equal(status, 2);
  assert.equal(report.error_kind, "scanner_diagnostics");
  assert.equal(report.result_count, 1);
  assert.equal(report.finding_gate.passed, false);
});

for (const [label, document] of [
  ["high findings", payload()],
  ["standard errors", (() => {
    const document = payload(); document.runs[0].results[0].level = "error";
    document.runs[0].tool.driver.rules[0].properties = { "security-severity": "6.1" };
    return document;
  })()],
]) test(`advisory reports ${label} without blocking valid analysis`, () => {
  const { status, report, summaryText } = inventory([document], { advisory: true, summary: true });
  assert.equal(status, 0);
  assert.equal(report.policy, "development_advisory");
  assert.equal(report.findings_exit, 1);
  assert.equal(report.report_success, true);
  assert.equal(report.finding_gate.enforced, false);
  assert.equal(report.result_count, 1);
  assert.equal(report.results.length, 1);
  assert.ok(summaryText.includes("development advisory"));
  assert.ok(summaryText.includes("js/path-injection"));
});
test("advisory zero findings also produces a successful report", () => {
  const { status, report } = inventory([payload([])], { advisory: true });
  assert.equal(status, 0);
  assert.equal(report.findings_present, false);
  assert.equal(report.report_success, true);
});
for (const [label, document] of [
  ["malformed JSON", privateText],
  ["missing execution", (() => { const p = payload(); delete p.runs[0].invocations; return p; })()],
  ["failed invocation", (() => { const p = payload(); p.runs[0].invocations[0].executionSuccessful = false; return p; })()],
]) test(`advisory cannot swallow ${label}`, () => {
  const { status, report } = inventory([document], { advisory: true });
  assert.equal(status, 2);
  assert.equal(report.analysis_complete, false);
});
test("summary output failure remains a failure with findings retained", () => {
  const { status, report } = inventory([payload()], { advisory: true, brokenSummary: true });
  assert.equal(status, 2);
  assert.equal(report.error_kind, "reporting_failure");
  assert.equal(report.report_success, false);
  assert.equal(report.result_count, 1);
});
test("conflicting strict/advisory policies fail rather than choose a weaker mode", () => {
  const { status, report } = inventory([payload()], { advisory: true, failOnFindings: true });
  assert.equal(status, 2);
  assert.equal(report.error, "invalid_arguments");
});

test("advisory still fails on absent SARIF and diagnostic errors", () => {
  assert.equal(inventory([], { advisory: true }).status, 2);
  const document = payload();
  document.runs[0].invocations[0].toolExecutionNotifications = [
    { level: "error", message: { text: privateText } },
  ];
  const { status, report } = inventory([document], { advisory: true });
  assert.equal(status, 2);
  assert.equal(report.error_kind, "scanner_diagnostics");
  assert.equal(report.result_count, 1);
  assert.equal(report.report_success, false);
});
test("advisory counts all high findings beyond its emitted row cap", () => {
  const { status, report } = inventory([payload([result(), result()])],
    { advisory: true, maxResults: 1 });
  assert.equal(status, 0);
  assert.equal(report.findings_exit, 1);
  assert.equal(report.result_count, 2);
  assert.equal(report.finding_gate.blocked_result_count, 2);
  assert.equal(report.omitted_count, 1);
});
