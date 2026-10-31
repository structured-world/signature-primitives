import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Parser, Lexer, Evaluator, data } from "@actions/expressions";
import { parse } from "yaml";
import "./pipeline_test.mjs";

const load = name => parse(readFileSync(new URL(`../workflows/${name}`, import.meta.url), "utf8"));
const workflow = load("release-plz.yml");
const ci = load("ci.yml");
const publish = workflow.jobs.publish;
const preparation = workflow.jobs["release-pr"];
const registry = workflow.jobs.registry;
const release = publish.steps.find(step => step.with?.command === "release");

function context(value) {
  if (typeof value === "string") return new data.StringData(value);
  if (typeof value === "boolean") return new data.BooleanData(value);
  return new data.Dictionary(...Object.entries(value).map(([key, value]) => ({ key, value: context(value) })));
}
function evaluate(expression, values) {
  const tokens = new Lexer(expression).lex().tokens;
  const expr = new Parser(tokens, ["github", "inputs", "needs", "steps"], []).parse();
  const result = new Evaluator(expr, context(values)).evaluate();
  assert.ok(result instanceof data.BooleanData);
  return result.value;
}
function canPublish({ event = "push", branch = "main", repository = "structured-world/signature-primitives", result = "success" } = {}) {
  return evaluate(publish.if, {
    github: { repository, event_name: event, ref: `refs/heads/${branch}` },
    needs: { validation: { result } },
  });
}
// OIDC rejects workflow_run. Native dependency success admits only this
// push/dispatch, never an older workflow or a skipped/failed validation job.
for (const event of ["push", "workflow_dispatch"]) assert.equal(canPublish({ event }), true);
for (const event of ["workflow_run", "pull_request", "pull_request_target"]) assert.equal(canPublish({ event }), false);
for (const result of ["failure", "cancelled", "skipped", "", "pending"]) assert.equal(canPublish({ result }), false);
assert.equal(canPublish({ branch: "feature" }), false);
assert.equal(canPublish({ repository: "attacker/signature-primitives" }), false);
assert.equal(publish.environment, "release");
assert.equal(publish.permissions["id-token"], "write");
assert.equal(publish.concurrency["cancel-in-progress"], false);
assert.equal(release.with.config, "release-plz.toml");
assert.equal(release.env.CARGO_REGISTRY_TOKEN, undefined);
assert.equal(release.if, undefined);

// Preparation and registry checks cannot drift to a later main while another
// exact revision is publishing. No next release is prepared during publication.
assert.equal(preparation.needs, "publish");
assert.equal(registry.needs, "publish");
for (const job of [publish, preparation, registry]) {
  const checkout = job.steps.find(step => step.uses?.startsWith("actions/checkout@"));
  assert.equal(checkout.with.ref, "${{ github.sha }}");
  assert.equal(checkout.with["fetch-depth"], 0);
  assert.equal(checkout.with["persist-credentials"], false);
}
for (const result of ["success", "failure", "skipped", "cancelled", ""]) {
  for (const event of ["push", "workflow_dispatch", "workflow_run", "pull_request"]) {
    assert.equal(evaluate(preparation.if, {
      github: { repository: "structured-world/signature-primitives", event_name: event, ref: "refs/heads/main" },
      needs: { publish: { result } },
    }), result === "success" && ["push", "workflow_dispatch"].includes(event));
  }
}
for (const created of ["true", "false", ""]) {
  const released = evaluate(publish.outputs.released.slice(3, -2).trim(), {
    steps: { release: { outputs: { releases_created: created } } },
  });
  assert.equal(released, created === "true");
  const state = { needs: { publish: { outputs: { released: String(released) } } } };
  assert.equal(evaluate(registry.if, state), released);
}

// Execute the real branch-attachment step in a disposable repository. A local
// later main must not replace the exact published source used by release-plz.
const branchStep = preparation.steps.find(step => step.name === "Attach preparation to the published revision");
assert.ok(preparation.steps.indexOf(branchStep) < preparation.steps.findIndex(step => step.with?.command === "release-pr"));
const checkout = mkdtempSync(join(tmpdir(), "signature-primitives-release-branch-"));
try {
  const git = (...args) => execFileSync("git", args, { cwd: checkout, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
  git("init", "--initial-branch=main");
  writeFileSync(join(checkout, "source"), "published");
  git("add", "source");
  git("-c", "user.name=Release test", "-c", "user.email=release-test@example.invalid", "commit", "-m", "published");
  const published = git("rev-parse", "HEAD");
  writeFileSync(join(checkout, "source"), "later main");
  git("add", "source");
  git("-c", "user.name=Release test", "-c", "user.email=release-test@example.invalid", "commit", "-m", "later main");
  git("checkout", "--detach", published);
  execFileSync("bash", ["-eu", "-c", branchStep.run], { cwd: checkout, env: { ...process.env, GITHUB_SHA: published }, stdio: "pipe" });
  assert.equal(git("branch", "--show-current"), "main");
  assert.equal(git("rev-parse", "HEAD"), published);
  assert.equal(readFileSync(join(checkout, "source"), "utf8"), "published");
} finally {
  rmSync(checkout, { recursive: true, force: true });
}

// Keep both PDF test tools before published-package qualification and retain
// the original stable compiler contract on every actual workflow command.
const qualification = registry.steps.findIndex(step => step.run === "bash scripts/qualify-registry.sh");
const oracles = registry.steps.findIndex(step => step.name === "PDF interoperability tools");
assert.ok(oracles >= 0 && oracles < qualification);
assert.equal(registry.steps[oracles].if, undefined);
assert.equal(registry.steps[oracles].run, "sudo apt-get update && sudo apt-get install --yes qpdf openssl");
for (const configuration of [ci, workflow]) {
  for (const job of Object.values(configuration.jobs)) {
    for (const step of job.steps ?? []) {
      for (const match of (step.run ?? "").matchAll(/rustup toolchain install (\S+)/g)) assert.equal(match[1], "stable");
      for (const match of (step.run ?? "").matchAll(/cargo \+(\S+)/g)) assert.equal(match[1], "stable");
    }
  }
}
assert.ok(ci.jobs.msrv.steps.some(step => step.run === "cargo +stable check --locked --workspace --all-targets"));
assert.match(readFileSync(new URL("../../rust-toolchain.toml", import.meta.url), "utf8"), /^channel = "stable"$/m);
const qualificationScript = readFileSync(new URL("../../scripts/qualify-registry.sh", import.meta.url), "utf8");
assert.doesNotMatch(qualificationScript, /\bmsrv\b/);
assert.deepEqual([...qualificationScript.matchAll(/cargo \+(\S+)/g)].map(match => match[1]), ["stable", "stable", "stable", "stable"]);
function ciGroup(event, sha, ref = "refs/heads/main") {
  return ci.concurrency.group.replace(/\$\{\{(.*?)\}\}/g, (_, expression) => {
    const expr = new Parser(new Lexer(expression.trim()).lex().tokens, ["github"], []).parse();
    return new Evaluator(expr, context({ github: { event_name: event, sha, ref } })).evaluate().coerceString();
  });
}
assert.notEqual(ciGroup("push", "release-sha"), ciGroup("push", "follow-up-sha"));
assert.equal(ciGroup("pull_request", "old-sha", "refs/pull/10/merge"), ciGroup("pull_request", "new-sha", "refs/pull/10/merge"));
const merge = load("dependabot-merge.yml");
assert.deepEqual(merge.on.workflow_run.workflows, [ci.name, workflow.name]);
assert.equal(merge.jobs.merge.steps[0].with.ref, "${{ github.event.repository.default_branch }}");
assert.equal(merge.jobs.merge.steps.at(-1).env.MERGE_PLAN, "${{ steps.inspect.outputs.plan }}");
console.log("PASS: native publication gates, source identity, OIDC, release ordering and unchanged validation requirements.");
