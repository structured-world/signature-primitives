import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parse } from "yaml";

// Publication must depend on the one canonical CI graph, not consume a runner
// while polling another run. PR check IDs and the OIDC workflow stay stable.
const load = name => parse(readFileSync(new URL(`../workflows/${name}`, import.meta.url), "utf8"));
const release = load("release-plz.yml");
const ci = load("ci.yml");
assert.equal(release.jobs.validation?.uses, "./.github/workflows/ci.yml");
assert.equal(release.jobs.publish.needs, "validation");
assert.ok(Object.hasOwn(ci.on, "workflow_call"));
assert.ok(ci.on.pull_request !== undefined);
assert.equal(ci.on.push, undefined);
assert.deepEqual(Object.keys(ci.jobs), ["release-gates", "test", "alloc", "msrv", "package"]);
assert.ok(release.on.push.branches.includes("main"));
assert.equal(release.on.workflow_run, undefined);
for (const configuration of [ci, release]) {
  for (const job of Object.values(configuration.jobs)) {
    for (const step of job.steps ?? []) {
      assert.doesNotMatch(step.run ?? "", /release_ci\.py|cargo.*install cargo-nextest/);
    }
  }
}
for (const job of [ci.jobs.test, release.jobs.registry]) {
  const install = job.steps.find(step => step.name === "Test runner");
  assert.match(install.uses, /^taiki-e\/install-action@[a-f0-9]{40}$/);
  assert.deepEqual(install.with, { tool: "cargo-nextest@0.9.146", fallback: "none" });
}
assert.equal(release.jobs.publish.steps.length, 3);
assert.doesNotMatch(JSON.stringify(release), /BOOTSTRAP_TOKEN|CARGO_REGISTRY_TOKEN|first-ltv|first-cades/);
console.log("PASS: native exact-revision CI dependencies and prebuilt test runners.");
