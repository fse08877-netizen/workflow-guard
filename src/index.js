import fs from "node:fs/promises";
import path from "node:path";
import yaml from "js-yaml";

export function defaultConfig() {
  return {
    version: 1,
    failOn: "error",
    rules: {
      "parse-error": { enabled: true },
      "unpinned-action": { enabled: true, allowed: [] },
      "missing-permissions": { enabled: true },
      "excessive-permissions": { enabled: true },
      "dangerous-pull-request-target": { enabled: true },
      "script-injection": { enabled: true },
      "secret-echo": { enabled: true },
      "missing-timeout": { enabled: true }
    }
  };
}

export function mergeConfig(userConfig = {}) {
  const base = defaultConfig();

  return {
    ...base,
    ...userConfig,
    rules: {
      ...base.rules,
      ...(userConfig.rules || {})
    }
  };
}

function ruleEnabled(config, ruleId) {
  return config?.rules?.[ruleId]?.enabled !== false;
}

function lineFromIndex(text, index) {
  return text.slice(0, index).split("\n").length;
}

function columnFromIndex(text, index) {
  const lastNewline = text.lastIndexOf("\n", index - 1);
  return index - lastNewline;
}

function makeFinding(ruleId, level, message, filePath, line = 1, column = 1) {
  return { ruleId, level, message, filePath, line, column };
}

function checkUnpinnedActions(text, filePath, config) {
  if (!ruleEnabled(config, "unpinned-action")) return [];

  const findings = [];
  const allowed = config?.rules?.["unpinned-action"]?.allowed || [];
  const usesRegex = /^\s*uses:\s*['"]?([^'"\s#]+)['"]?/gm;

  let match;

  while ((match = usesRegex.exec(text)) !== null) {
    const rawUses = match[1];

    if (rawUses.startsWith("./") || rawUses.startsWith("docker://")) continue;

    const atIndex = rawUses.lastIndexOf("@");

    if (atIndex <= 0) continue;

    const action = rawUses.slice(0, atIndex);
    const ref = rawUses.slice(atIndex + 1);
    const pinnedBySha = /^[0-9a-f]{40}$/i.test(ref);

    if (pinnedBySha) continue;

    const exact = `${action}@${ref}`;

    if (allowed.includes(exact) || allowed.includes(action)) continue;

    findings.push(
      makeFinding(
        "unpinned-action",
        "warning",
        `${exact} is not pinned by a full commit SHA. Pin actions to a full commit SHA or add it to the allowlist.`,
        filePath,
        lineFromIndex(text, match.index),
        columnFromIndex(text, match.index)
      )
    );
  }

  return findings;
}

function getTriggers(doc) {
  const on = doc.on;
  if (!on) return [];
  if (typeof on === "string") return [on];
  if (Array.isArray(on)) return on.map((v) => String(v));
  if (typeof on === "object") return Object.keys(on);
  return [];
}

function checkPermissions(doc, filePath, config) {
  const findings = [];

  if (ruleEnabled(config, "missing-permissions") && doc.permissions === undefined) {
    findings.push(
      makeFinding(
        "missing-permissions",
        "warning",
        "Workflow has no top-level permissions block. Define least-privilege permissions.",
        filePath
      )
    );
  }

  if (ruleEnabled(config, "excessive-permissions") && doc.permissions === "write-all") {
    findings.push(
      makeFinding(
        "excessive-permissions",
        "error",
        "Workflow uses permissions: write-all. Replace with scoped permissions.",
        filePath
      )
    );
  }

  return findings;
}

function checkPullRequestTarget(doc, filePath, config) {
  if (!ruleEnabled(config, "dangerous-pull-request-target")) return [];

  const triggers = getTriggers(doc);

  if (!triggers.includes("pull_request_target")) return [];

  return [
    makeFinding(
      "dangerous-pull-request-target",
      "warning",
      "pull_request_target can be dangerous when combined with checkout of PR head code. Review it carefully.",
      filePath
    )
  ];
}

function checkScriptInjection(text, filePath, config) {
  if (!ruleEnabled(config, "script-injection")) return [];

  const findings = [];
  const injectionRegex = /\$\{\{\s*github\.(event|head_ref)[^}]*\}\}/g;

  let match;

  while ((match = injectionRegex.exec(text)) !== null) {
    findings.push(
      makeFinding(
        "script-injection",
        "error",
        "Untrusted GitHub event context is interpolated in this workflow. Move it to an env variable and validate before use.",
        filePath,
        lineFromIndex(text, match.index),
        columnFromIndex(text, match.index)
      )
    );
  }

  return findings;
}

function checkSecretEcho(text, filePath, config) {
  if (!ruleEnabled(config, "secret-echo")) return [];

  const findings = [];
  const secretRegex = /\b(echo|printf)\b[^\n]*\$\{\{\s*secrets\.[^}]+\}\}/gi;

  let match;

  while ((match = secretRegex.exec(text)) !== null) {
    findings.push(
      makeFinding(
        "secret-echo",
        "warning",
        "A secret may be printed to logs. Avoid echoing secrets.",
        filePath,
        lineFromIndex(text, match.index),
        columnFromIndex(text, match.index)
      )
    );
  }

  return findings;
}

function checkMissingTimeout(doc, filePath, config) {
  if (!ruleEnabled(config, "missing-timeout")) return [];

  if (typeof doc["timeout-minutes"] === "number") return [];

  const jobs = doc.jobs || {};
  const hasJobTimeout = Object.values(jobs).some(
    (job) => typeof job?.["timeout-minutes"] === "number"
  );

  if (hasJobTimeout) return [];

  return [
    makeFinding(
      "missing-timeout",
      "warning",
      "Workflow has no timeout-minutes. Add a timeout to limit runaway jobs.",
      filePath
    )
  ];
}

export function scanWorkflowText(text, filePath, config = defaultConfig()) {
  const mergedConfig = mergeConfig(config);

  let doc;

  try {
    doc = yaml.load(text);
  } catch (error) {
    if (!ruleEnabled(mergedConfig, "parse-error")) return [];
    return [makeFinding("parse-error", "error", `YAML parse error: ${error.message}`, filePath)];
  }

  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    return [makeFinding("parse-error", "error", "Workflow file is not a YAML object.", filePath)];
  }

  const findings = [
    ...checkUnpinnedActions(text, filePath, mergedConfig),
    ...checkPermissions(doc, filePath, mergedConfig),
    ...checkPullRequestTarget(doc, filePath, mergedConfig),
    ...checkScriptInjection(text, filePath, mergedConfig),
    ...checkSecretEcho(text, filePath, mergedConfig),
    ...checkMissingTimeout(doc, filePath, mergedConfig)
  ];

  return findings.sort((a, b) => a.line - b.line || a.column - b.column);
}

export async function scanWorkflowFile(filePath, config = defaultConfig()) {
  const text = await fs.readFile(filePath, "utf8");
  return scanWorkflowText(text, filePath, config);
}

async function findWorkflowFiles(rootPath) {
  const stat = await fs.stat(rootPath);

  if (stat.isFile()) return [rootPath];

  const workflowsDir = path.join(rootPath, ".github", "workflows");
  const files = [];

  try {
    const entries = await fs.readdir(workflowsDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isFile()) continue;
      if (!entry.name.endsWith(".yml") && !entry.name.endsWith(".yaml")) continue;
      files.push(path.join(workflowsDir, entry.name));
    }
  } catch {
    // No workflows directory.
  }

  return files;
}

export async function scanDirectory(rootPath, config = defaultConfig()) {
  const files = await findWorkflowFiles(rootPath);
  const findings = [];

  for (const file of files) {
    findings.push(...(await scanWorkflowFile(file, config)));
  }

  return findings;
}

export function formatPretty(findings) {
  if (findings.length === 0) return "workflow-guard: no issues found.\n";

  const byFile = new Map();

  for (const finding of findings) {
    if (!byFile.has(finding.filePath)) byFile.set(finding.filePath, []);
    byFile.get(finding.filePath).push(finding);
  }

  let output = "";

  for (const [filePath, fileFindings] of byFile) {
    output += `${filePath}\n`;
    for (const finding of fileFindings) {
      output += `  ${finding.line}:${finding.column}  ${finding.level.padEnd(7)} ${finding.ruleId}  ${finding.message}\n`;
    }
    output += "\n";
  }

  return output;
}

export function toSarif(findings) {
  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "workflow-guard",
            informationUri: "https://github.com/fse08877-netizen/workflow-guard",
            rules: []
          }
        },
        results: findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: finding.level === "note" ? "note" : finding.level,
          message: { text: finding.message },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.filePath.replace(/\\/g, "/") },
                region: { startLine: finding.line || 1, startColumn: finding.column || 1 }
              }
            }
          ]
        }))
      }
    ]
  };
}
