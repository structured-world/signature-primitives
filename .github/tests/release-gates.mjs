import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Parser, Lexer, Evaluator, data } from "@actions/expressions";
import { parse } from "yaml";

const workflow = parse(readFileSync(new URL("../workflows/release-plz.yml", import.meta.url), "utf8"));
const publish = workflow.jobs.publish;
const release = publish.steps.find((step) => step.with?.command === "release");
assert.ok(release, "the production publishing step must exist");

function context(value) {
  if (typeof value === "string") return new data.StringData(value);
  if (typeof value === "boolean") return new data.BooleanData(value);
  return new data.Dictionary(...Object.entries(value).map(([key, value]) => ({ key, value: context(value) })));
}

function evaluate(expression, values) {
  const tokens = new Lexer(expression).lex().tokens;
  const expr = new Parser(tokens, ["github", "inputs", "needs"], []).parse();
  const result = new Evaluator(expr, context(values)).evaluate();
  assert.ok(result instanceof data.BooleanData);
  return result.value;
}

function canPublish({ event = "workflow_run", source = "push", outcome = "success", repository = "structured-world/signature-primitives", headRepository = repository, branch = "main", verifyOnly = false } = {}) {
  const values = {
    github: {
      repository, event_name: event, ref: `refs/heads/${branch}`,
      event: { workflow_run: { event: source, conclusion: outcome, head_repository: { full_name: headRepository } } },
    },
    inputs: { verify_only: verifyOnly },
  };
  return evaluate(publish.if, values);
}

// OIDC refuses workflow_run. Both supported triggers must pass the exact-SHA
// CI gate before authentication; a dispatch is no CI bypass.
assert.equal(canPublish(), false);
assert.equal(canPublish({ event: "push" }), true);
assert.equal(canPublish({ event: "workflow_dispatch" }), true);
assert.equal(canPublish({ event: "pull_request" }), false);
assert.equal(canPublish({ event: "push", branch: "feature" }), false);
assert.equal(canPublish({ event: "workflow_dispatch", branch: "feature" }), false);
assert.equal(canPublish({ event: "push", repository: "attacker/signature-primitives" }), false);
assert.equal(workflow.on.workflow_run, undefined, "CI completion must not start a parallel preparation run");
assert.equal(publish.environment, "release");
assert.equal(publish.permissions["id-token"], "write");
const gate = publish.steps.findIndex(step => step.run?.includes("release_ci.py"));
assert.ok(gate >= 0 && gate < publish.steps.indexOf(release));
assert.equal(publish.steps[0].with.ref, "${{ github.sha }}");
assert.equal(publish.permissions.actions, "read");
assert.equal(publish.concurrency["cancel-in-progress"], false);
assert.ok(workflow.on.push.branches.includes("main"));
assert.equal(release.if, undefined);
console.log("PASS: supported main triggers require exact-SHA CI before OIDC publication.");

// CI completion used to prepare the next release while the second package was
// still publishing, yielding a spurious version-only 0.1.5 after 0.1.4.
const preparation = workflow.jobs["release-pr"];
assert.equal(preparation.needs, "publish", "preparation must await the actual publisher");
assert.equal(preparation.steps.find(step => step.uses?.startsWith("actions/checkout@")).with.ref, "${{ github.sha }}");
function canPrepare(result, event = "push", branch = "main", repository = "structured-world/signature-primitives") {
  return evaluate(preparation.if, {
    github: { repository, event_name: event, ref: `refs/heads/${branch}` },
    needs: { publish: { result } },
  });
}
assert.equal(canPrepare("success"), true);
assert.equal(canPrepare("success", "workflow_dispatch"), true);
for (const result of ["failure", "cancelled", "skipped", ""]) assert.equal(canPrepare(result), false);
for (const event of ["workflow_run", "pull_request"]) assert.equal(canPrepare("success", event), false);
assert.equal(canPrepare("success", "push", "feature"), false);
assert.equal(canPrepare("success", "push", "main", "attacker/signature-primitives"), false);
console.log("PASS: preparation follows successful publication of the same main revision.");

// release-plz 0.3.171 refuses detached HEAD. Execute the actual workflow step:
// an existing local main must not move preparation away from the published SHA.
const branchStep = preparation.steps.find(step => step.name === "Attach preparation to the published revision");
assert.ok(branchStep, "a SHA checkout must be attached before invoking release-pr");
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
  assert.equal(git("branch", "--show-current"), "");
  execFileSync("bash", ["-eu", "-c", branchStep.run], { cwd: checkout, env: { ...process.env, GITHUB_SHA: published }, stdio: "pipe" });
  assert.equal(git("branch", "--show-current"), "main");
  assert.equal(git("rev-parse", "HEAD"), published);
  assert.equal(readFileSync(join(checkout, "source"), "utf8"), "published");
} finally {
  rmSync(checkout, { recursive: true, force: true });
}
console.log("PASS: actual preparation step attaches main without substituting a later revision.");

const ci = parse(readFileSync(new URL("../workflows/ci.yml", import.meta.url), "utf8"));
function ciGroup(event, sha, ref = "refs/heads/main") {
  return ci.concurrency.group.replace(/\$\{\{(.*?)\}\}/g, (_, expression) => {
    const tokens = new Lexer(expression.trim()).lex().tokens;
    const expr = new Parser(tokens, ["github"], []).parse();
    return new Evaluator(expr, context({ github: { event_name: event, sha, ref } })).evaluate().coerceString();
  });
}
// Distinct main commits must not cancel running OR queued release validation.
assert.notEqual(ciGroup("push", "release-sha"), ciGroup("push", "follow-up-sha"));
// PR updates may still replace obsolete validation without dropping a release.
assert.equal(ciGroup("pull_request", "old-sha", "refs/pull/10/merge"), ciGroup("pull_request", "new-sha", "refs/pull/10/merge"));
console.log("PASS: successive main pushes keep distinct CI groups; PR updates share their cancellation group.");

// Review submissions wake trusted main automation without exposing merge credentials.
const wake = parse(readFileSync(new URL("../workflows/dependabot-review.yml", import.meta.url), "utf8"));
const merge = parse(readFileSync(new URL("../workflows/dependabot-merge.yml", import.meta.url), "utf8"));
assert.ok(wake.on.pull_request_review.types.includes("submitted"));
assert.deepEqual(wake.permissions, {});
assert.ok(merge.on.workflow_run.workflows.includes(wake.name));
assert.equal(merge.jobs.merge.steps[0].with.ref, "${{ github.event.repository.default_branch }}");
console.log("PASS: submitted reviews wake trusted default-branch merge automation through an unprivileged signal.");
