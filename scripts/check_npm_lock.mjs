/** Validate the applicable virtual dependency graph using npm's own resolver. */
import fs from "node:fs";
import { createRequire } from "node:module";

try {
  const [root, npmCli, cache] = process.argv.slice(2);
  if (!root || !npmCli || !cache) throw Error("invalid_arguments");
  const require = createRequire(npmCli);
  const Arborist = require("@npmcli/arborist");
  const { checkPlatform } = require("npm-install-checks");
  const lock = JSON.parse(fs.readFileSync(root + "/package-lock.json", "utf8"));
  const tree = await new Arborist({ path: root, cache, offline: true,
    ignoreScripts: true, audit: false }).loadVirtual();
  if (tree.inventory.size > 50_000) throw Error("graph_limit_exceeded");
  const pending = [[tree, false]], visited = new Map(), applicable = new Set();
  let edges = 0, skippedOptionalPlatforms = 0, absentOptionalEdges = 0;
  while (pending.length) {
    const [node, optionalChain] = pending.pop();
    const bit = optionalChain ? 1 : 2;
    if ((visited.get(node) || 0) & bit) continue;
    visited.set(node, (visited.get(node) || 0) | bit);
    if (!Object.hasOwn(lock.packages, node.location)) throw Error("missing_locked_node");
    applicable.add(node.location);
    for (const edge of node.edgesOut.values()) {
      if (++edges > 250_000) throw Error("graph_limit_exceeded");
      if (edge.error) {
        if (edge.error === "MISSING" && edge.optional) {
          absentOptionalEdges++;
          continue;
        }
        throw Error("invalid_required_resolution");
      }
      if (!edge.to) {
        if (edge.optional) { absentOptionalEdges++; continue; }
        throw Error("missing_resolution");
      }
      const target = edge.to.isLink ? edge.to.target : edge.to;
      if (!target || !Object.hasOwn(lock.packages, target.location))
        throw Error("missing_locked_link_target");
      const nextOptional = optionalChain || edge.optional;
      try { checkPlatform(target.package); }
      catch (error) {
        if (error.code !== "EBADPLATFORM" || !nextOptional)
          throw Error("invalid_required_platform");
        skippedOptionalPlatforms++;
        continue;
      }
      pending.push([target, nextOptional]);
    }
  }
  console.log(JSON.stringify({ graph_valid: true,
    locked_nodes: tree.inventory.size, applicable_nodes: applicable.size,
    checked_edges: edges, skipped_optional_platform_edges: skippedOptionalPlatforms,
    absent_optional_edges: absentOptionalEdges,
    npm_version: require("../package.json").version,
    arborist_version: require("@npmcli/arborist/package.json").version }));
} catch {
  console.log(JSON.stringify({ graph_valid: false, error: "invalid_npm_lock_graph" }));
  process.exitCode = 2;
}
