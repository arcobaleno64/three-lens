#!/usr/bin/env node
// Adapted from arcobaleno64/agy-plugin-cc (scripts/bump-version.mjs, itself from
// openai/codex-plugin-cc, Apache-2.0) for this plugin's layout. Keeps every
// manifest and the one hardcoded source constant in lockstep.
//
// plugin.json carries no version field (confirmed against Antigravity's own
// documented example, which omits it) — AGY's plugin manifest is not one of the
// targets here, unlike Claude Code's.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";

const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const TOOL_VERSION_FILE = "skills/3lens/scripts/finalize-scan.mjs";
const TOOL_VERSION_PATTERN = /^export const TOOL_VERSION = '[^']*';$/m;

const JSON_TARGETS = [
  {
    file: "package.json",
    values: [{ label: "version", get: (json) => json.version, set: (json, version) => { json.version = version; } }]
  },
  {
    file: "plugin.json",
    values: [{ label: "version", get: (json) => json.version, set: (json, version) => { json.version = version; } }]
  },
  {
    file: "skills/3lens/tool-integrity-manifest.json",
    values: [{ label: "toolVersion", get: (json) => json.toolVersion, set: (json, version) => { json.toolVersion = version; } }]
  },
  {
    file: "recommended-security-audit-permissions.json",
    values: [{ label: "version", get: (json) => json.version, set: (json, version) => { json.version = version; } }]
  },
  {
    file: "evals/evidence-matrix.json",
    values: [{ label: "version", get: (json) => json.version, set: (json, version) => { json.version = version; } }]
  }
];

const DOC_TARGETS = [
  {
    file: "skills/3lens/SKILL.md",
    pattern: /^# Three-Lens Security Skill \(\/3lens v[^\s)]+\)(?=\r?$)/m,
    replacement: (v) => `# Three-Lens Security Skill (/3lens v${v})`
  },
  {
    file: "README.md",
    pattern: /^# Three-Lens \(3lens\) v[^\s]+/m,
    replacement: (v) => `# Three-Lens (3lens) v${v}`
  },
  {
    file: "README.md",
    pattern: /^├── package\.json\s+# npm test, test:evals, test:semantic, test:discovery, test:stability, check:release \([^)]*\)/m,
    replacement: (v) => `├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (${v})`
  },
  {
    file: "README.zh-TW.md",
    pattern: /^# Three-Lens \(3lens\) v[^\s]+/m,
    replacement: (v) => `# Three-Lens (3lens) v${v}`
  },
  {
    file: "README.zh-TW.md",
    pattern: /^├── package\.json\s+# npm test, test:evals, test:semantic, test:discovery, test:stability, check:release \([^)]*\)/m,
    replacement: (v) => `├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (${v})`
  },
  {
    file: "SECURITY.md",
    pattern: /^## 2\. Hardening & Guardrails \(v[^\s]+ \/ Production\)/m,
    replacement: (v) => `## 2. Hardening & Guardrails (v${v} / Production)`
  },
  {
    file: "docs/reproduction/README.md",
    pattern: /^> \*\*Frozen Baseline\*\*: `agy-security-audit v[^`]+`/m,
    replacement: (v) => `> **Frozen Baseline**: \`agy-security-audit v${v}\``
  }
];

function usage() {
  return [
    "Usage:",
    "  node scripts/bump-version.mjs <version>",
    "  node scripts/bump-version.mjs --check [version]",
    "",
    "Options:",
    "  --check       Verify version metadata is in lockstep. Uses package.json when version is omitted.",
    "  --list-targets Print every file this script can rewrite, one per line.",
    "  --root <dir>  Run against a different repository root.",
    "  --help        Print this help."
  ].join("\n");
}

function parseArgs(argv) {
  const options = { check: false, root: process.cwd(), version: null };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--check") {
      options.check = true;
    } else if (arg === "--list-targets") {
      options.listTargets = true;
    } else if (arg === "--root") {
      const root = argv[i + 1];
      if (!root) {
        throw new Error("--root requires a directory.");
      }
      options.root = root;
      i += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (options.version) {
      throw new Error(`Unexpected extra argument: ${arg}`);
    } else {
      options.version = arg;
    }
  }

  options.root = path.resolve(options.root);
  return options;
}

function validateVersion(version) {
  if (!VERSION_PATTERN.test(version)) {
    throw new Error(`Expected a semver-like version such as 1.0.3, got: ${version}`);
  }
}

function readJson(root, file) {
  return JSON.parse(fs.readFileSync(path.join(root, file), "utf8"));
}

function writeJson(root, file, json) {
  fs.writeFileSync(path.join(root, file), `${JSON.stringify(json, null, 2)}\n`);
}

function readPackageVersion(root) {
  const packageJson = readJson(root, "package.json");
  if (typeof packageJson.version !== "string") {
    throw new Error("package.json version must be a string.");
  }
  validateVersion(packageJson.version);
  return packageJson.version;
}

function readToolVersionConstant(root) {
  const filePath = path.join(root, TOOL_VERSION_FILE);
  const content = fs.readFileSync(filePath, "utf8");
  const match = content.match(TOOL_VERSION_PATTERN);
  if (!match) {
    throw new Error(`${TOOL_VERSION_FILE}: could not find an 'export const TOOL_VERSION = ...' declaration.`);
  }
  return match[0].match(/'([^']*)'/)[1];
}

function writeToolVersionConstant(root, version) {
  const filePath = path.join(root, TOOL_VERSION_FILE);
  const content = fs.readFileSync(filePath, "utf8");
  if (!TOOL_VERSION_PATTERN.test(content)) {
    throw new Error(`${TOOL_VERSION_FILE}: could not find an 'export const TOOL_VERSION = ...' declaration to rewrite.`);
  }
  const updated = content.replace(TOOL_VERSION_PATTERN, `export const TOOL_VERSION = '${version}';`);
  if (updated === content) return false;
  fs.writeFileSync(filePath, updated);
  return true;
}

function checkVersions(root, expectedVersion) {
  const mismatches = [];
  for (const target of JSON_TARGETS) {
    const json = readJson(root, target.file);
    for (const value of target.values) {
      const actual = value.get(json);
      if (actual !== expectedVersion) {
        mismatches.push(`${target.file} ${value.label}: expected ${expectedVersion}, found ${actual ?? "<missing>"}`);
      }
    }
  }
  const toolVersion = readToolVersionConstant(root);
  if (toolVersion !== expectedVersion) {
    mismatches.push(`${TOOL_VERSION_FILE} TOOL_VERSION: expected ${expectedVersion}, found ${toolVersion}`);
  }
  for (const doc of DOC_TARGETS) {
    const fullPath = path.join(root, doc.file);
    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath, "utf8");
      const match = content.match(doc.pattern);
      if (!match) {
        mismatches.push(`${doc.file}: version heading pattern not found`);
      } else {
        const expectedHeading = doc.replacement(expectedVersion);
        if (match[0] !== expectedHeading) {
          mismatches.push(`${doc.file}: expected '${expectedHeading}', found '${match[0]}'`);
        }
      }
    }
  }
  return mismatches;
}

// A release whose manifests agree but whose changelog says nothing about the
// version is the one artifact that tells a user what changed, so the gate is
// worth keeping — but only enforced once the file exists. There is no
// CHANGELOG.md yet; the first bump that adds one starts the discipline.
function checkChangelogEntry(root, expectedVersion) {
  const file = path.join(root, "CHANGELOG.md");
  if (!fs.existsSync(file)) return null;
  const headings = fs.readFileSync(file, "utf8").split(/\r?\n/).filter((line) => line.startsWith("## "));
  const found = headings.some((line) => {
    const token = line.split(/\s+/)[1]?.replace(/^\[/, '').replace(/\]$/, '');
    return token === expectedVersion || token === `v${expectedVersion}`;
  });
  if (found) return null;
  return `CHANGELOG.md: no \`## ${expectedVersion}\` entry. The manifests agree, so nothing else would have caught this.`;
}

function bumpVersion(root, version) {
  const changedFiles = [];
  for (const target of JSON_TARGETS) {
    const json = readJson(root, target.file);
    const before = JSON.stringify(json);
    for (const value of target.values) {
      value.set(json, version);
    }
    if (JSON.stringify(json) !== before) {
      writeJson(root, target.file, json);
      changedFiles.push(target.file);
    }
  }
  if (writeToolVersionConstant(root, version)) {
    changedFiles.push(TOOL_VERSION_FILE);
  }
  for (const doc of DOC_TARGETS) {
    const fullPath = path.join(root, doc.file);
    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath, "utf8");
      if (doc.pattern.test(content)) {
        const updated = content.replace(doc.pattern, doc.replacement(version));
        if (updated !== content) {
          fs.writeFileSync(fullPath, updated, "utf8");
          changedFiles.push(doc.file);
        }
      }
    }
  }
  return changedFiles;
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }

  if (options.listTargets) {
    for (const target of JSON_TARGETS) {
      console.log(target.file);
    }
    console.log(TOOL_VERSION_FILE);
    for (const doc of DOC_TARGETS) {
      console.log(doc.file);
    }
    return;
  }

  const version = options.version ?? (options.check ? readPackageVersion(options.root) : null);
  if (!version) {
    throw new Error(`Missing version.\n\n${usage()}`);
  }
  validateVersion(version);

  if (options.check) {
    const mismatches = checkVersions(options.root, version);
    if (mismatches.length > 0) {
      throw new Error(`Version metadata is out of sync:\n${mismatches.join("\n")}`);
    }
    const missingEntry = checkChangelogEntry(options.root, version);
    if (missingEntry) {
      throw new Error(missingEntry);
    }
    console.log(`All version metadata matches ${version}.`);
    return;
  }

  // Regenerating tool-integrity-manifest.json's script hashes is a separate,
  // deliberate step (scripts/regen-integrity-manifest.mjs) run after a bump
  // touches finalize-scan.mjs's TOOL_VERSION line — not folded in here, so a
  // caller cannot accidentally pin a manifest against files mid-edit.
  const changedFiles = bumpVersion(options.root, version);
  const touched = changedFiles.length > 0 ? changedFiles.join(", ") : "no files changed";
  console.log(`Set version metadata to ${version}: ${touched}.`);
  console.log("Next: run 'node scripts/regen-integrity-manifest.mjs' to re-pin script hashes, then the full test suite.");
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}
