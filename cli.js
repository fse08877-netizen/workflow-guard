#!/usr/bin/env node

import { parseArgs } from "node:util";
import fs from "node:fs/promises";
import yaml from "js-yaml";
import {
  scanDirectory,
  scanWorkflowFile,
  formatPretty,
  toSarif,
  mergeConfig,
  defaultConfig
} from "./index.js";

async function loadConfig(configPath) {
  if (!configPath) return defaultConfig();

  const raw = await fs.readFile(configPath, "utf8");
  const parsed = configPath.endsWith(".json") ? JSON.parse(raw) : yaml.load(raw);

  return mergeConfig(parsed || {});
}

function shouldFail(findings, failOn) {
  if (failOn === "none") return false;

  if (failOn === "warning") {
    return findings.some(
      (finding) => finding.level === "warning" || finding.level === "error"
    );
  }

  return findings.some((finding) => finding.level === "error");
}

async function main() {
  const command = process.argv[2];

  if (command !== "scan") {
    console.log(
      "Usage: workflow-guard scan [path] [--config file] [--format pretty|sarif] [--fail-on error|warning|none] [--output file]"
    );
    process.exit(command ? 1 : 0);
  }

  const { values, positionals } = parseArgs({
    args: process.argv.slice(3),
    options: {
      config: { type: "string" },
      format: { type: "string" },
      "fail-on": { type: "string" },
      output: { type: "string" }
    },
    allowPositionals: true
  });

  const target = positionals[0] || ".";
  const config = await loadConfig(values.config);
  const failOn = values["fail-on"] || config.failOn || "error";
  const format = values.format || "pretty";

  let findings;
  const stat = await fs.stat(target);

  if (stat.isFile()) {
    findings = await scanWorkflowFile(target, config);
  } else {
    findings = await scanDirectory(target, config);
  }

  const output =
    format === "sarif"
      ? JSON.stringify(toSarif(findings), null, 2)
      : formatPretty(findings);

  if (values.output) {
    await fs.writeFile(values.output, output);
  } else {
    process.stdout.write(output);
  }

  process.exit(shouldFail(findings, failOn) ? 1 : 0);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
