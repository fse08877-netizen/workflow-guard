import test from "node:test";
import assert from "node:assert/strict";
import { scanWorkflowText } from "../src/index.js";

test("detects unsafe workflow issues", () => {
  const workflow = `
on: pull_request_target

permissions: write-all

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo \${{ github.event.pull_request.title }}
`;

  const findings = scanWorkflowText(workflow, ".github/workflows/bad.yml");
  const rules = findings.map((f) => f.ruleId);

  assert.ok(rules.includes("unpinned-action"));
  assert.ok(rules.includes("dangerous-pull-request-target"));
  assert.ok(rules.includes("excessive-permissions"));
  assert.ok(rules.includes("script-injection"));
  assert.ok(rules.includes("missing-timeout"));
});

test("passes a hardened workflow", () => {
  const workflow = `
on: push

permissions:
  contents: read

timeout-minutes: 10

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3
      - run: echo hello
`;

  const findings = scanWorkflowText(workflow, ".github/workflows/good.yml");
  assert.deepEqual(findings, []);
});

test("allows configured unpinned actions", () => {
  const workflow = `
on: push

permissions:
  contents: read

timeout-minutes: 10

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`;

  const findings = scanWorkflowText(workflow, ".github/workflows/allowed.yml", {
    rules: {
      "unpinned-action": {
        enabled: true,
        allowed: ["actions/checkout@v4"]
      }
    }
  });

  const unpinned = findings.filter((f) => f.ruleId === "unpinned-action");
  assert.equal(unpinned.length, 0);
});

test("detects secret echo patterns", () => {
  const workflow = `
on: push

permissions:
  contents: read

timeout-minutes: 10

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.TOKEN }}
`;

  const findings = scanWorkflowText(workflow, ".github/workflows/secret.yml");
  const rules = findings.map((f) => f.ruleId);
  assert.ok(rules.includes("secret-echo"));
});
