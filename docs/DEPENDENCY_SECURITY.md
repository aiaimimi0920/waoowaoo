# Security scans and development reports

SARIF validation matches all alias groups, package/version identities, lock URIs
and OSV 2.5.1 primaryLocationLineHash fingerprints, not just counts or unique IDs.
Same-count substitutions, duplicate rows hiding another version/location,
missing aliases and mismatched fingerprints fail. A real reporter fixture tests
these mutations before CI scans the repository.

Dependabot updates the existing root npm lock and GitHub Actions weekly with
bounded concurrency. Runtime/tooling minor and patch updates are grouped;
major updates remain separate and are not automatically approved.

Dependency Security, CodeQL and Security Hygiene run on pull requests to main,
main pushes, weekly schedules or manual dispatch. No application service,
maintenance, release/package build, signing or deployment is invoked.

## Valid findings and failures

Only completed and validated finding-only output reports development success.
Raw exits and complete findings remain visible. Unknown exits, malformed/empty
inventory, lock mismatch, scanner/download/hash/version/diagnostic/report/upload
failures still fail CI. No continue-on-error, exception, ignore-unfixed,
auto-dismiss, approval or publishing is added.

OSV scanner/reporter 2.5.1 comes from the reviewed immutable OCI digest.
The scanner explicitly consumes root package-lock.json. Root declarations and
the applicable complete npm dependency graph are validated offline using bundled
npm Arborist, including aliases, links, mandatory transitive children and
applicable optional dependencies. OSV scans all root-lock packages without
platform filtering. Inventory must be nonempty and scanner 0/1, reporter 0/1,
vulnerabilities, SARIF counts and reporter version must agree. The reporter retains
--fail-on-vuln=true. python3 scripts/dependency_scan.py npm is strict by default;
the workflow explicitly adds --advisory and uploads complete validated SARIF.

CodeQL uses fixed trusted action SHAs, security-extended, full-branch analysis,
stable language categories and none build mode for JavaScript/TypeScript and
Actions. Full SARIF is uploaded. Analysis completion and diagnostics are
separate from findings. The bounded summary counts all results even beyond its
emitted-row limit, without messages, snippets or code flows. Its strict entrypoint
adds --fail-on-findings: severity >=7 or standard error fails. CI explicitly uses
--advisory; absent/invalid SARIF or diagnostic errors still fail.

Gitleaks 8.30.1 and Zizmor 1.30.1 use official release archives verified by exact
SHA-256 before execution. Gitleaks scans non-shallow Git history with built-in
rules, no local ignore file or allow comments, and finding code 10. Zizmor uses
offline/strict-collection/auditor/JSON-v1; finding exits 11/12/13/14 must match
highest severity. Online-only Zizmor audits are not covered. Security Hygiene
defaults strict; its workflow explicitly adds --advisory.

Synthetic binary fixtures run outside the checkout with no live credentials.
Hygiene artifacts contain every finding's count/rule/hashed tracking key, without
secrets, source, messages or raw locations; retention is 14 days. Full raw hygiene
data exists only in the ephemeral validation process. Reports do not claim every
historical match is a real production credential.

## Native coverage and deployment boundary

Code files and CLI success do not prove native security switches are enabled.
Actual successful SARIF upload must be checked separately. Account settings,
branch protection, paid plans and credentials are not changed. Reports go to
GITHUB_STEP_SUMMARY and the PR description; no Issues write permission is used.
No upload-failure injection has been performed; ordinary upload failures fail CI.

Before merge, check existing status/checks and deployment integrations in addition
to repository workflows. An empty prior-head check list does not prove absence of
external Git deployments. Product package/dependency locks and Docker config are
unchanged.

## Verification

    python scripts/check_security_inputs.py npm
    node --test scripts/tests/codeql-summary.test.mjs scripts/tests/security-inputs.test.mjs
    python scripts/tests/test_security_policy.py
    python scripts/tests/test_hygiene_policy.py

Real OSV/container and downloaded CLI fixture tests run in hosted CI. Existing
application test:regression is separate: it includes billing/database integration
bootstrap and has not been invoked by this configuration-only change. Security
scanner test success does not claim all application regression checks passed.
