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
  const expr = new Parser(tokens, ["github", "inputs", "needs", "steps"], []).parse();
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

// A new crate cannot mint an OIDC token before its first publication. Its
// narrowly scoped API token must never replace existing-package authentication;
// packages depending on it return to OIDC once it is in the registry.
const selection = publish.steps.find(step => step.id === "bootstrap");
const firstLtv = publish.steps.find(step => step.name === "Publish the first LTV version");
const dependents = publish.steps.find(step => step.name === "Publish packages depending on LTV");
assert.ok(selection && firstLtv && dependents);
assert.ok(gate < publish.steps.indexOf(selection));
assert.ok(publish.steps.indexOf(selection) < publish.steps.indexOf(release));
assert.ok(publish.steps.indexOf(release) < publish.steps.indexOf(firstLtv));
assert.ok(publish.steps.indexOf(firstLtv) < publish.steps.indexOf(dependents));
assert.equal(release.env.CARGO_REGISTRY_TOKEN, undefined);
assert.equal(dependents.env.CARGO_REGISTRY_TOKEN, undefined);
assert.equal(firstLtv.env.CARGO_REGISTRY_TOKEN, "${{ secrets.LTV_BOOTSTRAP_TOKEN }}");
assert.equal(firstLtv.with.config, ".github/release-ltv.toml");
assert.equal(dependents.with.config, ".github/release-dependents.toml");
for (const step of [firstLtv, dependents]) {
  assert.equal(step.with.command, "release");
  assert.equal(step.with.version, release.with.version);
}
for (const enabled of ["true", "false"]) {
  const values = { steps: { bootstrap: { outputs: { enabled, cades: "false" } } } };
  assert.equal(evaluate(firstLtv.if, values), enabled === "true");
  assert.equal(evaluate(dependents.if, values), enabled === "true");
  const expression = release.with.config.slice(3, -2).trim();
  const parsed = new Parser(new Lexer(expression).lex().tokens, ["steps"], []).parse();
  const selected = new Evaluator(parsed, context(values)).evaluate();
  assert.equal(selected.coerceString(), enabled === "true" ? ".github/release-core.toml" : "release-plz.toml");
}
const modeOutput = mkdtempSync(join(tmpdir(), "primitives-publish-mode-"));
try {
  for (const token of ["", "synthetic-bootstrap-credential"]) {
    const output = join(modeOutput, token ? "present" : "absent");
    execFileSync("bash", ["-eu", "-c", selection.run], {
      env: { ...process.env, LTV_BOOTSTRAP_TOKEN: token, CADES_BOOTSTRAP_TOKEN: "", GITHUB_OUTPUT: output }, stdio: "pipe",
    });
    assert.equal(readFileSync(output, "utf8"), `enabled=${token ? "true" : "false"}\ncades=false\n`);
  }
} finally {
  rmSync(modeOutput, { recursive: true, force: true });
}
console.log("PASS: first LTV publication uses its own token between OIDC steps; absent token selects normal OIDC.");

// CAdES is the sixth coordinated package, not an excuse to hand the new-crate
// credential to the existing five. Removing the secret restores ordinary OIDC.
const firstCades = publish.steps.find(step => step.id === "first-cades");
const cadesResolution = publish.steps.find(step => step.name === "Wait until CAdES dependencies resolve");
assert.ok(firstCades && cadesResolution);
assert.ok(publish.steps.indexOf(dependents) < publish.steps.indexOf(cadesResolution));
assert.ok(publish.steps.indexOf(cadesResolution) < publish.steps.indexOf(firstCades));
assert.equal(firstCades.env.CARGO_REGISTRY_TOKEN, "${{ secrets.CADES_BOOTSTRAP_TOKEN }}");
assert.equal(firstCades.with.config, ".github/release-cades.toml");
assert.equal(firstCades.with.version, release.with.version);
assert.equal(cadesResolution.run, "bash scripts/wait-registry-resolution.sh structured-ltv");
for (const cades of ["true", "false"]) {
  const values = { steps: { bootstrap: { outputs: { enabled: "false", cades } } } };
  assert.equal(evaluate(firstCades.if, values), cades === "true");
  assert.equal(evaluate(cadesResolution.if, values), cades === "true");
  const expression = release.with.config.slice(3, -2).trim();
  const parsed = new Parser(new Lexer(expression).lex().tokens, ["steps"], []).parse();
  assert.equal(new Evaluator(parsed, context(values)).evaluate().coerceString(),
    cades === "true" ? ".github/release-before-cades.toml" : "release-plz.toml");
}
const cadesModeOutput = mkdtempSync(join(tmpdir(), "primitives-cades-mode-"));
try {
  const output = join(cadesModeOutput, "selected");
  execFileSync("bash", ["-eu", "-c", selection.run], {
    env: { ...process.env, LTV_BOOTSTRAP_TOKEN: "", CADES_BOOTSTRAP_TOKEN: "synthetic-new-crate-credential", GITHUB_OUTPUT: output }, stdio: "pipe",
  });
  assert.equal(readFileSync(output, "utf8"), "enabled=false\ncades=true\n");
  assert.throws(() => execFileSync("bash", ["-eu", "-c", selection.run], {
    env: { ...process.env, LTV_BOOTSTRAP_TOKEN: "synthetic-ltv", CADES_BOOTSTRAP_TOKEN: "synthetic-cades", GITHUB_OUTPUT: join(cadesModeOutput, "conflict") }, stdio: "pipe",
  }), "conflicting initial-publication credentials refuse before authentication");
} finally {
  rmSync(cadesModeOutput, { recursive: true, force: true });
}
console.log("PASS: CAdES bootstrap is isolated, dependency-ordered and returns to OIDC without the secret.");

// release-plz's own readiness check can pass before a dependent's cargo publish
// resolves the new version (release-plz#2946). The dependents step must wait
// for actual resolution of a freshly published LTV, and only then.
const resolution = publish.steps.find(step => step.name === "Wait until LTV resolves for dependents");
assert.ok(resolution, "a resolver wait must separate LTV from its dependents");
assert.ok(publish.steps.indexOf(firstLtv) < publish.steps.indexOf(resolution));
assert.ok(publish.steps.indexOf(resolution) < publish.steps.indexOf(dependents));
assert.equal(resolution.run, "bash scripts/wait-registry-resolution.sh structured-ltv");
for (const created of ["true", "false", ""]) {
  const values = { steps: { "first-ltv": { outputs: { releases_created: created } } } };
  assert.equal(evaluate(resolution.if, values), created === "true");
}
console.log("PASS: dependents publish only after a newly published LTV version resolves.");

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

// Registry qualification reads what crates.io serves for this revision, so it
// follows an actual publication by any publishing step and nothing else.
const registry = workflow.jobs.registry;
assert.equal(registry.needs, "publish");
assert.equal(registry.steps.find(step => step.uses?.startsWith("actions/checkout@")).with.ref, "${{ github.sha }}");
assert.equal(registry.steps.find(step => step.uses?.startsWith("actions/checkout@")).with["fetch-depth"], 0);
assert.ok(registry.steps.some(step => step.run === "bash scripts/qualify-registry.sh"));
assert.equal(publish.steps.find(step => step.id === "release"), release);
assert.equal(publish.steps.find(step => step.id === "first-ltv"), firstLtv);
assert.equal(publish.steps.find(step => step.id === "dependents"), dependents);
const released = publish.outputs.released.slice(3, -2).trim();
for (const [core, ltv, dependent, cades] of [
  ["true", "", "", ""], ["false", "true", "", ""], ["false", "false", "true", ""], ["true", "true", "true", "true"],
  ["false", "false", "false", "true"], ["false", "false", "false", "false"], ["false", "", "", ""], ["", "", "", ""],
]) {
  const created = core === "true" || ltv === "true" || dependent === "true" || cades === "true";
  const steps = {
    release: { outputs: { releases_created: core } },
    "first-ltv": { outputs: { releases_created: ltv } },
    dependents: { outputs: { releases_created: dependent } },
    "first-cades": { outputs: { releases_created: cades } },
  };
  assert.equal(evaluate(released, { steps }), created);
  assert.equal(evaluate(registry.if, { needs: { publish: { outputs: { released: String(created) } } } }), created);
}
console.log("PASS: registry qualification follows a publication of this revision and is skipped otherwise.");

const ci = parse(readFileSync(new URL("../workflows/ci.yml", import.meta.url), "utf8"));
// Registry and pull-request MSRV checks run the same exact compiler release.
const msrvInstall = steps => steps.find(step => /^rustup toolchain install \d+\.\d+\.\d+ /.test(step.run ?? ""))?.run.split(" ")[3];
assert.ok(msrvInstall(ci.jobs.msrv.steps));
assert.equal(msrvInstall(registry.steps), msrvInstall(ci.jobs.msrv.steps));
console.log("PASS: registry qualification installs the pull-request MSRV compiler.");
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

// Finished CI wakes trusted main automation, which never checks out PR code.
const merge = parse(readFileSync(new URL("../workflows/dependabot-merge.yml", import.meta.url), "utf8"));
assert.ok(merge.on.workflow_run.workflows.includes(ci.name));
assert.equal(merge.jobs.merge.steps[0].with.ref, "${{ github.event.repository.default_branch }}");
console.log("PASS: finished CI wakes trusted default-branch merge automation.");
