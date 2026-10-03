import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

const script = fileURLToPath(new URL("../check_security_inputs.py", import.meta.url));
const privateText = "PRIVATE_INPUT_MUST_NOT_BE_PRINTED";
const validGo = { "go.mod": "module fixture\n\ngo 1.24.10\n",
  "go.sum": `example.invalid/dependency v1.0.0 h1:${"A".repeat(43)}=\n` };
const validNpm = { "package.json": JSON.stringify({ name: "fixture", dependencies: { sample: "1.0.0" } }),
  "package-lock.json": JSON.stringify({ name: "fixture", lockfileVersion: 3,
    packages: { "": { dependencies: { sample: "1.0.0" } },
      "node_modules/sample": { version: "1.0.0" } } }) };

function check(ecosystem, files, extra = []) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "scan-inputs-"));
  try {
    for (const [name, value] of Object.entries(files)) fs.writeFileSync(path.join(directory, name), value);
    const output = spawnSync(process.env.PYTHON || "python3",
      [script, ecosystem, "--root", directory, ...extra],
      { encoding: "utf8", timeout: 40_000, maxBuffer: 1_000_000 });
    assert.ifError(output.error);
    assert.ok(!(output.stdout + output.stderr).includes(privateText));
    return output;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

for (const [ecosystem, files] of [["gomod", validGo], ["npm", validNpm]]) {
  test(`${ecosystem} committed inputs validate`, () => assert.equal(check(ecosystem, files).status, 0));
  for (const name of Object.keys(files)) test(`${ecosystem} missing ${name} fails closed`, () => {
    const missing = { ...files }; delete missing[name];
    const output = check(ecosystem, missing);
    assert.equal(output.status, 2);
    assert.equal(JSON.parse(output.stdout).inputs_valid, false);
  });
}
for (const [ecosystem, files] of [
  ["gomod", { ...validGo, "go.mod": privateText }],
  ["gomod", { ...validGo, "go.sum": privateText }],
  ["npm", { ...validNpm, "package-lock.json": privateText }],
  ["npm", { ...validNpm, "package-lock.json": "{}" }],
  ["npm", { ...validNpm, "package.json": JSON.stringify({ name: "other" }) }],
]) test(`${ecosystem} malformed or mismatched inputs fail without content`, () => {
  const output = check(ecosystem, files);
  assert.equal(output.status, 2);
  assert.equal(JSON.parse(output.stdout).inputs_valid, false);
});

test("illegal scanner-contract arguments cannot succeed", () => {
  assert.equal(check("gomod", validGo, ["--unexpected"]).status, 2);
});

test("oversized input is rejected", () => {
  assert.equal(check("gomod", { ...validGo, "go.sum": " ".repeat(5 * 1024 * 1024 + 1) }).status, 2);
});

test("declared direct dependency without its actual locked entry fails", () => {
  const lock = JSON.parse(validNpm["package-lock.json"]);
  delete lock.packages["node_modules/sample"];
  assert.equal(check("npm", { ...validNpm, "package-lock.json": JSON.stringify(lock) }).status, 2);
});

for (const [label, manifest, packages] of [
  ["alias", { dependencies: { alias: "npm:sample@1.0.0" } },
    { "node_modules/alias": { name: "sample", version: "1.0.0" } }],
  ["link", { dependencies: { sample: "file:packages/sample" } },
    { "node_modules/sample": { resolved: "packages/sample", link: true },
      "packages/sample": { name: "sample", version: "1.0.0" } }],
  ["absent optional", { optionalDependencies: { sample: "1.0.0" } }, {}],
]) test(`npm native lock semantics accept ${label}`, () => {
  const fixture = { name: "fixture", version: "1.0.0", ...manifest };
  const files = { "package.json": JSON.stringify(fixture),
    "package-lock.json": JSON.stringify({ name: "fixture", version: "1.0.0",
      lockfileVersion: 3, packages: { "": fixture, ...packages } }) };
  assert.equal(check("npm", files).status, 0);
});

const repositoryRoot = new URL("../../", import.meta.url);
if (fs.existsSync(new URL("package.json", repositoryRoot))) {
  const actualManifest = fs.readFileSync(new URL("package.json", repositoryRoot), "utf8");
  const actualLock = fs.readFileSync(new URL("package-lock.json", repositoryRoot), "utf8");
  test("actual repository direct lock resolutions validate", () => {
    assert.equal(check("npm", { "package.json": actualManifest, "package-lock.json": actualLock }).status, 0);
  });
  test("deleting actual declared root dependency fails", () => {
    const manifest = JSON.parse(actualManifest);
    const lock = JSON.parse(actualLock);
    const name = Object.keys(manifest.dependencies || manifest.devDependencies)[0];
    assert.ok(name);
    delete lock.packages["node_modules/" + name];
    assert.equal(check("npm", { "package.json": actualManifest,
      "package-lock.json": JSON.stringify(lock) }).status, 2);
  });
}

const transitiveLock = () => ({ name: "fixture", lockfileVersion: 3, packages: {
  "": { dependencies: { sample: "1.0.0" } },
  "node_modules/sample": { version: "1.0.0", dependencies: { child: "^1.0.0" } },
  "node_modules/child": { version: "1.0.0" },
} });
test("complete mandatory transitive lock graph validates", () => {
  assert.equal(check("npm", { ...validNpm, "package-lock.json": JSON.stringify(transitiveLock()) }).status, 0);
});
for (const mode of ["missing", "incompatible version"]) test(`transitive ${mode} fails with unchanged declarations`, () => {
  const lock = transitiveLock();
  if (mode === "missing") delete lock.packages["node_modules/child"];
  else lock.packages["node_modules/child"].version = "2.0.0";
  assert.equal(check("npm", { ...validNpm, "package-lock.json": JSON.stringify(lock) }).status, 2);
});
for (const [label, optional, cpu, expected] of [
  ["inapplicable optional platform subtree", true, ["wasm32"], 0],
  ["inapplicable required platform", false, ["wasm32"], 2],
  ["applicable optional subtree with missing mandatory child", true, [process.arch], 2],
]) test(`native graph handles ${label}`, () => {
  const field = optional ? "optionalDependencies" : "dependencies";
  const declaration = { name: "fixture", [field]: { sample: "1.0.0" } };
  const lock = { name: "fixture", lockfileVersion: 3, packages: { "": declaration,
    "node_modules/sample": { version: "1.0.0", cpu, optional,
      dependencies: { child: "1.0.0" } } } };
  assert.equal(check("npm", { "package.json": JSON.stringify(declaration),
    "package-lock.json": JSON.stringify(lock) }).status, expected);
});

test("public dependency workflow validates exits before native SARIF upload", () => {
  const workflow = fs.readFileSync(new URL("../../.github/workflows/dependency-security.yml", import.meta.url), "utf8");
  for (const text of ["needs: verify-inputs", "steps.scan.outputs.report_valid == 'true'",
    "python3 scripts/tests/test_dependency_scan.py", "python3 scripts/dependency_scan.py npm --advisory",
    "security-events: write", "contents: read", "actions: read",
    "category: .github/workflows/dependency-security.yml:osv-scan"])
    assert.ok(workflow.includes(text), text);
  for (const forbidden of ["ignore-unfixed", "--config", "continue-on-error", "secrets: inherit",
    "pull_request_target", "workflow_call:", "contents: write", "osv-scanner-reusable.yml"])
    assert.ok(!workflow.includes(forbidden), forbidden);
  for (const use of workflow.matchAll(/uses:\s+(\S+)/g)) assert.match(use[1], /@[a-f0-9]{40}$/);
});
