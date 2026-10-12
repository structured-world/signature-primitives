import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
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
  const expr = new Parser(tokens, ["github", "inputs"], []).parse();
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
  return evaluate(publish.if, values) && evaluate(release.if, values);
}

// A dispatch must never bypass the CI trigger, even with explicitly false input.
assert.equal(canPublish({ event: "workflow_dispatch", verifyOnly: false }), false);
assert.equal(canPublish({ event: "workflow_dispatch", verifyOnly: true }), false);
assert.equal(canPublish(), true);
assert.equal(canPublish({ outcome: "failure" }), false);
assert.equal(canPublish({ outcome: "cancelled" }), false);
assert.equal(canPublish({ source: "pull_request" }), false);
assert.equal(canPublish({ headRepository: "attacker/signature-primitives" }), false);
assert.equal(canPublish({ repository: "attacker/signature-primitives" }), false);
assert.deepEqual(workflow.on.workflow_run.branches, ["main"]);
assert.equal(publish.environment, "release");
assert.equal(publish.permissions["id-token"], "write");
console.log("PASS: only a successful CI push from the repository can publish; manual, failed and fork paths refuse.");

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
