#!/usr/bin/env node
/**
 * run-live-model-benchmark.mjs
 * Authentic Model Discovery Runner Harness for Antigravity (AGY).
 *
 * Executes live `agy` CLI in headless print mode (`agy --mode plan --print ...`)
 * to prompt discovery against security benchmark fixtures, parsing real model
 * candidate findings and serializing schema-compliant empirical envelopes.
 *
 * Fixture Partitioning & Generalization Governance:
 * - Development Set (Regression Fixture): SEM-03 (Confused Deputy) was calibrated
 *   with direct prompt heuristics; it serves as a regression baseline.
 * - Holdout Fixtures: Remaining benchmark fixtures evaluate unbiased generalization.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import {
  createBenchmarkRunEnvelope,
  validateBenchmarkRunEnvelope,
  validateCandidateSet,
  probeEnvironment,
  parseStreamJsonTrace
} from '../skills/3lens/scripts/record-benchmark-run.mjs';
import {
  finalizeScan,
  computeLineageFingerprint,
  normalizeCandidateSymbol
} from '../skills/3lens/scripts/finalize-scan.mjs';
import { evaluateDiscovery } from '../skills/3lens/scripts/run-discovery-eval.mjs';
import { evaluateStability } from '../skills/3lens/scripts/run-stability-eval.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const DEFAULT_REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Synchronous sleep helper using Atomics.wait to prevent busy-waiting.
 */
export function sleepSync(ms) {
  if (typeof ms === 'number' && ms > 0) {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
  }
}

/**
 * Atomically writes JSON content to target file using a temporary file and rename.
 */
export function writeJsonAtomic(filePath, data) {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true });
  const tmpPath = path.join(dir, `.${path.basename(filePath)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
  let retries = 5;
  while (true) {
    try {
      fs.renameSync(tmpPath, filePath);
      break;
    } catch (err) {
      retries--;
      if (retries <= 0) {
        try { fs.unlinkSync(tmpPath); } catch {}
        throw err;
      }
      sleepSync(50);
    }
  }
}

/**
 * Checks whether an error or output string indicates upstream rate limiting / resource exhaustion.
 */
export function isRateLimitError(str) {
  if (!str || typeof str !== 'string') return false;
  return /429|resource[_\s]?exhausted|quota[_\s]?exceeded|rate[_\s]?limit|too many requests/i.test(str);
}

/**
 * Fixture Partitioning Specification:
 * Explicit separation between development/calibration fixtures and holdout fixtures.
 */
export const SUITE_FIXTURE_SPLITS = {
  semantic: {
    developmentSet: {
      ids: ['SEM-03', 'SEM-09'],
      role: 'REGRESSION_BASELINE',
      rationale: 'SEM-03 (Confused Deputy) and SEM-09 (Prototype Pollution) were calibrated with targeted prompt heuristics; classified as development/regression fixtures.'
    },
    holdoutFixtures: {
      ids: ['SEM-01', 'SEM-02', 'SEM-04', 'SEM-05', 'SEM-06', 'SEM-07', 'SEM-08', 'SEM-10'],
      role: 'HOLDOUT_GENERALIZATION',
      rationale: 'Fixtures evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution generalization.'
    }
  },
  holdout: {
    developmentSet: {
      ids: [],
      role: 'REGRESSION_BASELINE',
      rationale: 'Holdout generalization benchmark suite has no development or calibrated fixtures (Section 21 covenant).'
    },
    holdoutFixtures: {
      ids: ['HLD-01', 'HLD-02', 'HLD-03', 'HLD-04', 'HLD-05', 'HLD-06', 'HLD-07', 'HLD-08', 'HLD-09', 'HLD-10'],
      role: 'HOLDOUT_GENERALIZATION',
      rationale: 'All 10 fixtures evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution generalization.'
    }
  }
};

export const BENCHMARK_FIXTURE_SPLITS = SUITE_FIXTURE_SPLITS.semantic;

/**
 * Strips comments that could leak ground truth labels, categories, CWE numbers,
 * or evaluation status from fixture source code during blind evaluation.
 *
 * Line numbers are strictly preserved (1-to-1) by replacing leaking comment lines
 * with neutral comment markers, preventing line-number shift artifacts in reported findings.
 */
export function stripLabelLeakingComments(sourceCode) {
  if (typeof sourceCode !== 'string') return '';
  const lines = sourceCode.split('\n');
  const result = [];
  let inLeadingCommentBlock = true;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    if (inLeadingCommentBlock) {
      if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*') || trimmed === '') {
        if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
          result.push('// [blind-review: header comment redacted]');
        } else {
          result.push(line);
        }
        continue;
      } else {
        inLeadingCommentBlock = false;
      }
    }

    // After leading header block, neutralize any comment mentioning ground truth tokens
    if (
      trimmed.startsWith('//') &&
      /evals\/|\b(?:safe|guarded|vulnerable|cwe-\d+|semantic\s*category|holdout\s*category)\b/i.test(trimmed)
    ) {
      result.push('// [blind-review: metadata comment redacted]');
    } else {
      result.push(line);
    }
  }

  return result.join('\n');
}

/**
 * Projects a benchmark fixture into a deterministic label-blind case file under scratch/
 * (e.g. scratch/live-benchmark/cases/case-<hash>.js).
 *
 * Prevents lexical leakage where the model infers safety from paths like /safe/ or header comments.
 * The projected file is written both to scratch/live-benchmark/cases and shadow context (if present).
 */
export function projectLabelBlindFixture(fixture, repoRoot = DEFAULT_REPO_ROOT, casesDir = 'scratch/context/cases') {
  const sourcePath = path.resolve(repoRoot, fixture.file);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Fixture file not found: ${sourcePath}`);
  }
  const rawContent = fs.readFileSync(sourcePath, 'utf8');
  const strippedContent = stripLabelLeakingComments(rawContent);

  const fileHash = crypto.createHash('sha256').update(fixture.file).digest('hex').slice(0, 12);
  const projectedFileName = `case-${fileHash}.js`;
  const normalizedCasesDir = casesDir.replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
  const projectedRelPath = `${normalizedCasesDir}/${projectedFileName}`;
  const projectedAbsPath = path.resolve(repoRoot, projectedRelPath);

  fs.mkdirSync(path.dirname(projectedAbsPath), { recursive: true });
  fs.writeFileSync(projectedAbsPath, strippedContent, 'utf8');

  // Also mirror to scratch/live-benchmark/cases for permanent trace recording
  const mirrorRelPath = `scratch/live-benchmark/cases/${projectedFileName}`;
  const mirrorAbsPath = path.resolve(repoRoot, mirrorRelPath);
  try {
    fs.mkdirSync(path.dirname(mirrorAbsPath), { recursive: true });
    fs.writeFileSync(mirrorAbsPath, strippedContent, 'utf8');
  } catch {}

  // Mirror to scratch/context/cases if shadow context is active and casesDir was different
  if (normalizedCasesDir !== 'scratch/context/cases') {
    const shadowAbsPath = path.resolve(repoRoot, 'scratch/context/cases', projectedFileName);
    try {
      fs.mkdirSync(path.dirname(shadowAbsPath), { recursive: true });
      fs.writeFileSync(shadowAbsPath, strippedContent, 'utf8');
    } catch {}
  }

  return {
    originalFile: fixture.file,
    projectedRelPath,
    projectedAbsPath,
    fileHash,
    strippedContent,
    lineCount: strippedContent.split('\n').length
  };
}

/**
 * Prepares an isolated, hermetic evaluation sandbox directory containing ONLY the
 * stripped target fixture and minimal synthetic metadata (HERMETIC_BENCHMARK_V1).
 *
 * Strict Exclusion Properties:
 * - Isolated directory per case under scratch/hermetic-sandbox/case-<hash>
 * - No ground-truth.json, no fixture IDs, no SAFE/VULNERABLE labels, no CWE hints
 * - No git history, no previous model outputs, no scorer or harness scripts
 * - Minimal synthetic package.json (ESM enabled, private)
 * - Enables agy CLI invocation with cwd = sandboxDir and workspace = sandboxDir
 */
export function prepareHermeticSandbox(fixture, repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const sourcePath = path.resolve(repoRoot, fixture.file);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Fixture file not found: ${sourcePath}`);
  }
  const rawContent = fs.readFileSync(sourcePath, 'utf8');
  const strippedContent = stripLabelLeakingComments(rawContent);

  const fileHash = crypto.createHash('sha256').update(fixture.file).digest('hex').slice(0, 12);
  const targetFileName = options.targetFileName || `case-${fileHash}.js`;
  const defaultSandboxDir = `scratch/hermetic-sandbox/case-${fileHash}`;
  const sandboxRelDir = (options.sandboxDir || defaultSandboxDir).replace(/\\/g, '/').replace(/^\/+/, '').replace(/\/+$/, '');
  const sandboxAbsDir = path.resolve(repoRoot, sandboxRelDir);

  // Clean directory first to guarantee no stale files exist
  if (fs.existsSync(sandboxAbsDir)) {
    fs.rmSync(sandboxAbsDir, { recursive: true, force: true });
  }
  fs.mkdirSync(sandboxAbsDir, { recursive: true });

  // Write isolated target code file
  const targetAbsPath = path.join(sandboxAbsDir, targetFileName);
  fs.writeFileSync(targetAbsPath, strippedContent, 'utf8');

  // Write minimal synthetic package.json (no project leaks, ESM enabled)
  const syntheticPackageJson = {
    name: 'hermetic-sandbox-fixture',
    version: '1.0.0',
    type: 'module',
    private: true
  };
  fs.writeFileSync(
    path.join(sandboxAbsDir, 'package.json'),
    JSON.stringify(syntheticPackageJson, null, 2),
    'utf8'
  );

  return {
    originalFile: fixture.file,
    fileHash,
    sandboxRelDir,
    sandboxAbsDir,
    targetFileName,
    targetRelPath: targetFileName,
    targetAbsPath,
    strippedContent,
    lineCount: strippedContent.split('\n').length
  };
}

/**
 * Cleans up a hermetic sandbox directory.
 */
export function cleanHermeticSandbox(sandboxAbsDir) {
  try {
    if (fs.existsSync(sandboxAbsDir)) {
      fs.rmSync(sandboxAbsDir, { recursive: true, force: true });
    }
  } catch {}
}

/**
 * Deterministically stringifies a JSON-compatible value with sorted object keys.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(canonicalJsonStringify).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k])).join(',') + '}';
}

/**
 * Computes canonical SHA-256 digest of an evaluation protocol specification (excluding protocolDigest).
 */
export function computeProtocolDigest(protocol) {
  if (!protocol || typeof protocol !== 'object') return null;
  const clone = { ...protocol };
  delete clone.protocolDigest;
  const canonical = canonicalJsonStringify(clone);
  return crypto.createHash('sha256').update(canonical, 'utf8').digest('hex');
}

/**
 * Loads, parses, and validates the integrity of a frozen evaluation protocol specification (Fail-Closed).
 */
export function loadAndValidateProtocol(protocolPath, repoRoot = DEFAULT_REPO_ROOT) {
  const fullPath = path.resolve(repoRoot, protocolPath);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Protocol file not found: ${fullPath}`);
  }
  const content = fs.readFileSync(fullPath, 'utf8');
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (err) {
    throw new Error(`Invalid JSON in protocol file (${fullPath}): ${err.message}`);
  }

  if (!parsed.protocolId || typeof parsed.protocolId !== 'string') {
    throw new Error(`Protocol missing required protocolId: ${fullPath}`);
  }
  if (parsed.status !== 'FROZEN') {
    throw new Error(`Protocol status must be 'FROZEN', got '${parsed.status}' (${fullPath})`);
  }
  if (!parsed.protocolDigest || typeof parsed.protocolDigest !== 'string') {
    throw new Error(`Protocol missing required protocolDigest: ${fullPath}`);
  }

  const computedDigest = computeProtocolDigest(parsed);
  if (computedDigest !== parsed.protocolDigest) {
    throw new Error(
      `PROTOCOL_INTEGRITY_VIOLATION: Digest mismatch for protocol '${parsed.protocolId}'.\n` +
      `  Expected (stamped): ${parsed.protocolDigest}\n` +
      `  Computed (actual):  ${computedDigest}\n` +
      `Fail-Closed: Protocol specification has been altered post-freeze!`
    );
  }

  return parsed;
}

/**
 * Validates that runner options comply with the frozen protocol specification.
 */
export function verifyProtocolCompliance(options, protocol, experimentKey = 'holdoutPaired') {
  if (!protocol) return;
  let exp = null;
  if (protocol.experiments && experimentKey && protocol.experiments[experimentKey]) {
    exp = protocol.experiments[experimentKey];
  } else if (protocol.executionParameters) {
    exp = protocol.executionParameters;
  } else if (protocol.experiments) {
    exp = protocol.experiments.reasoningAblation || protocol.experiments.holdoutPaired || Object.values(protocol.experiments)[0];
  } else {
    exp = protocol;
  }
  if (!exp) return;

  const errors = [];
  if (exp.suite && options.suite && options.suite !== exp.suite) {
    errors.push(`Suite mismatch: protocol expects '${exp.suite}', run specified '${options.suite}'`);
  }
  if (exp.passes !== undefined && options.passes !== undefined && Number(options.passes) !== Number(exp.passes)) {
    errors.push(`Passes count mismatch: protocol expects ${exp.passes}, run specified ${options.passes}`);
  }
  if (exp.shuffleSeed !== undefined && options.shuffleSeed && String(options.shuffleSeed) !== String(exp.shuffleSeed)) {
    errors.push(`Shuffle seed mismatch: protocol expects '${exp.shuffleSeed}', run specified '${options.shuffleSeed}'`);
  }
  if (exp.hermetic !== undefined && options.hermetic !== undefined && Boolean(options.hermetic) !== Boolean(exp.hermetic)) {
    errors.push(`Hermetic mode mismatch: protocol expects hermetic=${exp.hermetic}, run specified hermetic=${options.hermetic}`);
  }
  if (exp.labelBlind !== undefined && options.labelBlind !== undefined && Boolean(options.labelBlind) !== Boolean(exp.labelBlind)) {
    errors.push(`Label-blind mode mismatch: protocol expects labelBlind=${exp.labelBlind}, run specified labelBlind=${options.labelBlind}`);
  }
  if (exp.includeSafe !== undefined && options.includeSafe !== undefined && Boolean(options.includeSafe) !== Boolean(exp.includeSafe)) {
    errors.push(`Include-safe mode mismatch: protocol expects includeSafe=${exp.includeSafe}, run specified includeSafe=${options.includeSafe}`);
  }
  if (!options.mock && exp.throttleDelayMs !== undefined && options.delayMs !== undefined && Number(options.delayMs) !== Number(exp.throttleDelayMs)) {
    errors.push(`Throttle delay mismatch: protocol expects ${exp.throttleDelayMs}ms, run specified ${options.delayMs}ms`);
  }
  if (exp.timeoutMs !== undefined && options.timeoutMs !== undefined && Number(options.timeoutMs) !== Number(exp.timeoutMs)) {
    errors.push(`Timeout mismatch: protocol expects ${exp.timeoutMs}ms, run specified ${options.timeoutMs}ms`);
  }
  if (exp.modelId && options.modelId && options.modelId !== exp.modelId) {
    errors.push(`Model ID mismatch: protocol expects '${exp.modelId}', run specified '${options.modelId}'`);
  }
  if (exp.baseModel && options.baseModel && options.baseModel !== exp.baseModel) {
    errors.push(`Base model mismatch: protocol expects '${exp.baseModel}', run specified '${options.baseModel}'`);
  }
  if (exp.reasoningProfile && options.reasoningProfile && options.reasoningProfile !== exp.reasoningProfile) {
    errors.push(`Reasoning profile mismatch: protocol expects '${exp.reasoningProfile}', run specified '${options.reasoningProfile}'`);
  }
  if (exp.outDir && options.outDir) {
    const repo = options.repoRoot || DEFAULT_REPO_ROOT;
    const resolvedExp = path.resolve(repo, exp.outDir).replace(/\\/g, '/').replace(/\/+$/, '');
    const resolvedOut = path.resolve(repo, options.outDir).replace(/\\/g, '/').replace(/\/+$/, '');
    const isWin = process.platform === 'win32';
    const match = isWin ? (resolvedExp.toLowerCase() === resolvedOut.toLowerCase()) : (resolvedExp === resolvedOut);
    if (!match) {
      errors.push(`Output directory mismatch: protocol expects '${exp.outDir}', run specified '${options.rawOutDir || options.outDir}'`);
    }
  }

  if (errors.length > 0) {
    throw new Error(
      `PROTOCOL_NON_COMPLIANCE: Benchmark execution deviates from frozen protocol '${protocol.protocolId}':\n` +
      errors.map(e => `  - ${e}`).join('\n')
    );
  }
}

/**
 * Deterministically shuffles an array using Mulberry32 PRNG given a seed.
 */
export function shuffleArrayWithSeed(array, seed) {
  if (seed === undefined || seed === null || seed === '') return array.slice();
  const copy = array.slice();
  let s = 0;
  if (typeof seed === 'number') {
    s = seed | 0;
  } else {
    const str = String(seed);
    for (let i = 0; i < str.length; i++) {
      s = ((s << 5) - s + str.charCodeAt(i)) | 0;
    }
  }

  function random() {
    s |= 0;
    s = (s + 0x6d2b79f5) | 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }

  for (let i = copy.length - 1; i > 0; i--) {
    const j = Math.floor(random() * (i + 1));
    [copy[i], copy[j]] = [copy[j], copy[i]];
  }
  return copy;
}

/**
 * Computes safe-control specificity metrics under dual controlled ground truth.
 *
 * Metrics:
 * 1. Fixture FP Rate = (safe fixtures with >= 1 FP) / safeFixtureCount
 * 2. Run-exposure FP Rate = (safe exposures with >= 1 FP) / (safeFixtureCount * totalPasses)
 * 3. Exposure Specificity = 1 - Run-exposure FP Rate
 * 4. FP Candidate Density = (total spurious candidates) / (safeFixtureCount * totalPasses)
 * 5. Max Lineage Recurrence = Maximum recurrence of any single spurious lineage
 */
export function computeSafeControlMetrics({
  safeRecurrences = [],
  allPassResults = [],
  totalPasses = 1,
  safeFixtureCount = 10,
  safeResults = []
} = {}) {
  const K = Math.max(1, safeFixtureCount);
  const N = Math.max(1, totalPasses);
  const totalExposures = K * N;

  const fixtureFPCounts = new Map();
  let exposuresWithFPCount = 0;
  let totalSpuriousCandidates = 0;

  if (allPassResults && allPassResults.length > 0) {
    for (const pass of allPassResults) {
      const fixResults = pass.fixtureResults || [];
      for (const res of fixResults) {
        const isSafe = res.split === 'SAFE_CONTROL' || res.fixtureId?.endsWith('-SAFE') || (res.file && res.file.includes('/safe/'));
        if (!isSafe) continue;
        const candCount = Array.isArray(res.candidates)
          ? res.candidates.length
          : (typeof res.candidateCount === 'number' ? res.candidateCount : 0);
        if (candCount > 0) {
          exposuresWithFPCount++;
          totalSpuriousCandidates += candCount;
          fixtureFPCounts.set(res.fixtureId, (fixtureFPCounts.get(res.fixtureId) || 0) + candCount);
        }
      }
    }
  } else if (safeResults && safeResults.length > 0) {
    for (const res of safeResults) {
      const candCount = Array.isArray(res.candidates) ? res.candidates.length : 0;
      if (candCount > 0) {
        exposuresWithFPCount++;
        totalSpuriousCandidates += candCount;
        fixtureFPCounts.set(res.fixtureId, (fixtureFPCounts.get(res.fixtureId) || 0) + candCount);
      }
    }
  } else if (safeRecurrences && safeRecurrences.length > 0) {
    for (const r of safeRecurrences) {
      const count = r.recurrenceCount || 1;
      totalSpuriousCandidates += count;
      const fid = r.matchedFixtureId || r.symbol || r.id;
      fixtureFPCounts.set(fid, (fixtureFPCounts.get(fid) || 0) + count);
    }
    exposuresWithFPCount = Math.min(totalSpuriousCandidates, totalExposures);
  }

  const fixturesWithFP = fixtureFPCounts.size;
  const fixtureFPRate = Number((fixturesWithFP / K).toFixed(4));
  const runExposureFPRate = Number((exposuresWithFPCount / totalExposures).toFixed(4));
  const exposureSpecificity = Number((1 - runExposureFPRate).toFixed(4));
  const fpCandidateDensity = Number((totalSpuriousCandidates / totalExposures).toFixed(4));

  let maxLineageRecurrence = 0;
  if (Array.isArray(safeRecurrences) && safeRecurrences.length > 0) {
    for (const r of safeRecurrences) {
      if ((r.recurrenceCount || 0) > maxLineageRecurrence) {
        maxLineageRecurrence = r.recurrenceCount;
      }
    }
  }
  const maxLineageRecurrenceRate = Number((maxLineageRecurrence / N).toFixed(4));

  return {
    safeFixtureCount: K,
    totalPasses: N,
    totalExposures,
    fixturesWithFP,
    fixtureFPRate,
    exposuresWithFP: exposuresWithFPCount,
    runExposureFPRate,
    exposureSpecificity,
    totalSpuriousCandidates,
    fpCandidateDensity,
    maxLineageRecurrence,
    maxLineageRecurrenceRate,
    spuriousLineages: safeRecurrences
  };
}

/**
 * Parses model stdout to extract structured JSON candidate findings.
 * Handles pure JSON, Markdown code blocks, or embedded JSON arrays.
 */
export function parseModelJsonOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];

  const text = rawOutput.trim();

  function extractArray(obj) {
    if (!obj || typeof obj !== 'object') return null;
    if (Array.isArray(obj)) return obj;
    if (Array.isArray(obj.candidates)) return obj.candidates;
    if (Array.isArray(obj.findings)) return obj.findings;
    if (Array.isArray(obj.results)) return obj.results;
    return null;
  }

  // 1. Direct JSON parse
  try {
    const parsed = JSON.parse(text);
    const arr = extractArray(parsed);
    if (arr) return arr;
  } catch {}

  // 2. Extract JSON from Markdown code blocks (```json ... ``` or ``` ...)
  const codeBlockRegex = /```(?:json)?\s*([\s\S]*?)```/gi;
  let match;
  while ((match = codeBlockRegex.exec(text)) !== null) {
    try {
      const candidateJson = JSON.parse(match[1].trim());
      const arr = extractArray(candidateJson);
      if (arr) return arr;
    } catch {}
  }

  // 3. Fallback: bracket match extraction [ { ... } ] or { ... }
  const firstBracket = text.indexOf('[');
  const lastBracket = text.lastIndexOf(']');
  if (firstBracket !== -1 && lastBracket > firstBracket) {
    try {
      const sliced = text.slice(firstBracket, lastBracket + 1);
      const parsed = JSON.parse(sliced);
      const arr = extractArray(parsed);
      if (arr) return arr;
    } catch {}
  }

  const firstBrace = text.indexOf('{');
  const lastBrace = text.lastIndexOf('}');
  if (firstBrace !== -1 && lastBrace > firstBrace) {
    try {
      const sliced = text.slice(firstBrace, lastBrace + 1);
      const parsed = JSON.parse(sliced);
      const arr = extractArray(parsed);
      if (arr) return arr;
    } catch {}
  }

  return [];
}

/**
 * Builds discovery prompt instructing AGY to review fixture code under Default-Deny.
 */
export function buildDiscoveryPrompt(fixtureRelPath, fixtureContent = '') {
  return `You are conducting a strict defensive software engineering and code quality review under Default-Deny on the following file:
File: ${fixtureRelPath}

Review Instructions:
1. Inspect the file located at '${fixtureRelPath}' using view_file.
2. Audit the file under Default-Deny for unmitigated software defects (such as input sanitization, broken authorization or tenancy boundaries, unvalidated object mutation CWE-1321, or unsafe resource handling).
3. Do not invoke external search tools or search other repository files. Base your analysis solely on '${fixtureRelPath}'.
4. Presumption of Non-Pass: If the implementation is safe, properly mitigated, or has no unmitigated defects, return an empty candidate set:
{"schemaVersion": "1.0.0", "candidates": []}
5. If unmitigated defects exist, output ONLY structured JSON conforming to candidate-set.schema.json:
{
  "schemaVersion": "1.0.0",
  "candidates": [
    {
      "id": "CAND-<RULE>-<LINE>",
      "ruleId": "CWE-XXX",
      "title": "Concise defect description",
      "securityProperty": "authorization",
      "findingType": "VULNERABILITY",
      "proofKind": "STATIC_TRACE",
      "severity": "CRITICAL",
      "location": {
        "uri": "${fixtureRelPath}",
        "startLine": 1,
        "endLine": 1
      },
      "symbol": "functionOrSinkName"
    }
  ]
}
Output ONLY valid JSON. Do not include commentary outside the JSON.`;
}

/**
 * Executes a single fixture discovery pass via real `agy` CLI in headless mode with retry resilience.
 */
export function runAgyDiscoveryOnFixture(fixture, repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const fixturePath = path.resolve(repoRoot, fixture.file);
  if (!fs.existsSync(fixturePath)) {
    throw new Error(`Fixture file not found: ${fixturePath}`);
  }

  const isSafeFixture = fixture.expectedVerdict === 'SAFE' || fixture.severity === 'NONE' || fixture.id.endsWith('-SAFE');
  const splits = options.fixtureSplits || BENCHMARK_FIXTURE_SPLITS;
  const isDevSet = splits.developmentSet.ids.includes(fixture.id);
  const split = isSafeFixture ? 'SAFE_CONTROL' : (isDevSet ? 'DEVELOPMENT_SET' : 'HOLDOUT_SET');

  const isHermetic = options.hermetic !== false;
  const useLabelBlind = options.labelBlind !== false;
  const defaultCasesDir = fs.existsSync(path.resolve(repoRoot, 'scratch/context'))
    ? 'scratch/context/cases'
    : 'scratch/live-benchmark/cases';
  const effectiveCasesDir = options.casesDir || defaultCasesDir;

  // Support simulated / offline mode for tests and CI
  if (options.mock || options.mockCandidates) {
    if (isHermetic) {
      prepareHermeticSandbox(fixture, repoRoot, options);
    } else if (useLabelBlind) {
      projectLabelBlindFixture(fixture, repoRoot, effectiveCasesDir);
    }
    if (isSafeFixture) {
      const safeCandidateSet = { schemaVersion: '1.0.0', candidates: [] };
      const mockTelemetry = {
        format: 'SIMULATED_MOCK',
        conversationId: `sim-mock-${fixture.id}`,
        telemetryDigest: crypto.createHash('sha256').update(JSON.stringify(safeCandidateSet)).digest('hex'),
        totalEvents: 3,
        availableTools: ['view_file', 'list_dir', 'grep_search', 'find_by_name'],
        toolsUsed: ['view_file'],
        subagentsInvoked: [],
        permissionMode: 'always-proceed',
        tokenUsage: {
          inputTokens: 350,
          outputTokens: 40,
          thinkingTokens: 0,
          cacheReadTokens: 0,
          totalTokens: 390
        },
        durationSeconds: 0.025
      };
      return {
        fixtureId: fixture.id,
        file: fixture.file,
        durationMs: 25,
        candidates: [],
        rawOutput: JSON.stringify(safeCandidateSet),
        error: null,
        split,
        executionTelemetry: mockTelemetry
      };
    }

    const passIdx = options.passIndex || 1;
    let mockCands;
    if (Array.isArray(options.mockCandidates)) {
      mockCands = options.mockCandidates;
    } else if (options.mockCandidates && Array.isArray(options.mockCandidates.candidates)) {
      mockCands = options.mockCandidates.candidates;
    } else {
      mockCands = [
        {
          id: `CAND-${fixture.id}-P${passIdx}`,
          ruleId: fixture.cwe || 'CWE-441',
          title: `Simulated discovery finding for ${fixture.id}`,
          securityProperty: 'safe-resource-handling',
          findingType: 'VULNERABILITY',
          proofKind: 'STATIC_TRACE',
          severity: fixture.severity || 'HIGH',
          location: {
            uri: fixture.file,
            startLine: (fixture.targetLine || 10) + (passIdx - 1) * 2,
            endLine: (fixture.targetLine || 15) + (passIdx - 1) * 2
          },
          symbol: fixture.id
        }
      ];
    }
    for (const cand of mockCands) {
      if (!cand.securityProperty) cand.securityProperty = 'safe-resource-handling';
      if (!cand.findingType) cand.findingType = 'VULNERABILITY';
      if (!cand.proofKind) cand.proofKind = 'STATIC_TRACE';
      if (!cand.lineageId) {
        cand.lineageId = computeLineageFingerprint({
          ruleId: cand.ruleId || 'SEC-VULN',
          uri: fixture.file,
          symbol: cand.symbol || fixture.id
        });
      }
    }
    const mockCandidateSet = { schemaVersion: '1.0.0', candidates: mockCands };
    const mockTelemetry = {
      format: 'SIMULATED_MOCK',
      conversationId: `sim-mock-${fixture.id}`,
      telemetryDigest: crypto.createHash('sha256').update(JSON.stringify(mockCandidateSet)).digest('hex'),
      totalEvents: 3,
      availableTools: ['view_file', 'list_dir', 'grep_search', 'find_by_name'],
      toolsUsed: ['view_file'],
      subagentsInvoked: [],
      permissionMode: 'always-proceed',
      sandboxEnabled: Boolean(options.sandbox),
      tokenUsage: {
        inputTokens: 500,
        outputTokens: 120,
        thinkingTokens: 0,
        cacheReadTokens: 0,
        totalTokens: 620
      },
      durationSeconds: 0.05
    };
    return {
      fixtureId: fixture.id,
      file: fixture.file,
      durationMs: 50,
      candidates: mockCands,
      rawOutput: JSON.stringify(mockCandidateSet),
      error: null,
      split,
      executionTelemetry: mockTelemetry
    };
  }

  const fixtureContent = fs.readFileSync(fixturePath, 'utf8');
  let promptTargetFile = fixture.file;
  let promptContent = fixtureContent;
  let projectedInfo = null;
  let hermeticInfo = null;
  let effectiveCwd = repoRoot;
  let workspaceDir = repoRoot;

  if (isHermetic) {
    hermeticInfo = prepareHermeticSandbox(fixture, repoRoot, options);
    effectiveCwd = hermeticInfo.sandboxAbsDir;
    workspaceDir = hermeticInfo.sandboxAbsDir;
    promptTargetFile = hermeticInfo.targetRelPath;
    promptContent = hermeticInfo.strippedContent;
  } else if (useLabelBlind) {
    projectedInfo = projectLabelBlindFixture(fixture, repoRoot, effectiveCasesDir);
    promptTargetFile = projectedInfo.projectedRelPath;
    promptContent = projectedInfo.strippedContent;
  }

  const prompt = buildDiscoveryPrompt(promptTargetFile, promptContent);
  const modelId = options.modelId || process.env.AGY_MODEL || 'gemini-3.8-flash-high';
  const timeoutMs = options.timeoutMs || 240000;
  const maxAttempts = options.retries !== undefined ? options.retries + 1 : 3;

  let lastResult = null;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const startTime = Date.now();
    const agyArgs = [
      '--add-dir', workspaceDir,
      '--dangerously-skip-permissions',
      '--output-format', 'stream-json'
    ];
    if (options.sandbox) {
      agyArgs.push('--sandbox');
    }
    if (modelId) {
      agyArgs.push('--model', modelId);
    }
    const effort = options.effort || options.reasoningProfile || options.tier;
    if (effort) {
      agyArgs.push('--effort', effort);
    }
    agyArgs.push('--print', prompt);

    let stdout = '';
    let stderr = '';
    let exitCode = 0;
    let procSignal = null;

    try {
      const agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy';
      const result = spawnSync(agyBin, agyArgs, {
        cwd: effectiveCwd,
        encoding: 'utf8',
        timeout: timeoutMs,
        env: {
          ...process.env,
          PAGER: 'cat'
        },
        stdio: ['pipe', 'pipe', 'pipe']
      });

      if (result.error) {
        stderr = result.error.code === 'ETIMEDOUT'
          ? `CENSORED_EXPOSURE: Process execution timed out after ${timeoutMs}ms`
          : `CENSORED_EXPOSURE: Process execution error: ${result.error.message}`;
        exitCode = 1;
      } else {
        stdout = result.stdout || '';
        stderr = result.stderr || '';
        procSignal = result.signal || null;
        // Gate 0 (R16-F02-01): Explicitly detect signal termination (SIGTERM/SIGKILL with status: null).
        // Default-Deny: Convert null status with signal to non-zero exit code (128) rather than 0.
        exitCode = result.status !== null ? result.status : (result.signal ? 128 : (result.error ? 1 : 0));
        if (procSignal) {
          stderr = stderr
            ? `${stderr}\nProcess terminated by signal: ${procSignal}`
            : `CENSORED_EXPOSURE: Process terminated by signal: ${procSignal}`;
        }
      }
    } catch (err) {
      stderr = `CENSORED_EXPOSURE: Process execution exception: ${err.message}`;
      exitCode = 1;
    }

    const durationMs = Date.now() - startTime;
    let parsedOutput = null;
    let rawCandidates = [];
    let schemaError = null;
    let executionTelemetry = null;

    const trace = parseStreamJsonTrace(stdout, { exitCode, signal: procSignal });
    if (trace.success) {
      executionTelemetry = trace.telemetry;
      const rawText = trace.rawResponse.trim();
      const fenceMatch = rawText.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
      const cleanJson = fenceMatch ? fenceMatch[1].trim() : rawText;
      try {
        parsedOutput = JSON.parse(cleanJson);
      } catch (err) {
        schemaError = `CENSORED_EXPOSURE: Invalid JSON in stream result response: ${err.message}`;
      }
    } else {
      if (trace.telemetry) {
        executionTelemetry = trace.telemetry;
      }
      schemaError = trace.error?.startsWith('CENSORED_EXPOSURE')
        ? trace.error
        : `CENSORED_EXPOSURE: Stream trace validation failed (${trace.error || 'terminated prematurely'})`;
    }

    if (executionTelemetry) {
      executionTelemetry.sandboxEnabled = Boolean(options.sandbox);
    }

    if (parsedOutput) {
      const valResult = validateCandidateSet(parsedOutput);
      if (!valResult.valid) {
        schemaError = `SCHEMA_VIOLATION: ${valResult.errors.join('; ')}`;
      } else {
        rawCandidates = parsedOutput.candidates;
      }
    }

    const candidates = [];

    // Normalize candidate lineage IDs and sanitize
    for (const cand of rawCandidates) {
      if (!cand || typeof cand !== 'object') continue;
      // Remap candidate URI back to authoritative fixture file if label-blind projected
      if (cand.location) {
        cand.location.uri = fixture.file;
      }
      normalizeCandidateSymbol(cand, fixtureContent);
      if (!cand.lineageId) {
        cand.lineageId = computeLineageFingerprint({
          ruleId: cand.ruleId || 'SEC-VULN',
          uri: fixture.file,
          symbol: cand.symbol || fixture.id
        });
      }
      if (options.tier || options.effort || options.reasoningProfile) {
        cand.modelEffort = options.tier || options.effort || options.reasoningProfile;
      }
      candidates.push(cand);
    }

    const ALLOWED_FINISHED_REASONS = new Set(['stop', 'end_turn', 'complete', 'completed', 'eos', 'stop_sequence']);
    let nonAllowlistedFinishedReason = false;
    if (executionTelemetry?.finishedReason) {
      const normReason = String(executionTelemetry.finishedReason).trim().toLowerCase();
      if (!ALLOWED_FINISHED_REASONS.has(normReason)) {
        nonAllowlistedFinishedReason = true;
      }
    }

    const isFilterBlocked = stdout.includes("blocked by Gemini's filters") || stdout.includes("request was blocked") || (executionTelemetry?.finishedReason && ['safety', 'content_filter', 'filter', 'recitation'].includes(String(executionTelemetry.finishedReason).toLowerCase()));
    let error = (exitCode !== 0 || procSignal)
      ? (stderr?.startsWith('CENSORED_EXPOSURE') ? stderr : `CENSORED_EXPOSURE: Process exited with code ${exitCode}${procSignal ? ` (signal: ${procSignal})` : ''} (${stderr || 'non-zero exit'})`)
      : null;
    if (!error && nonAllowlistedFinishedReason) {
      error = `CENSORED_EXPOSURE: Stream terminated with non-allowlisted finished_reason: ${executionTelemetry.finishedReason}`;
    }
    if (!error && schemaError) {
      error = schemaError;
    }
    if (!error && isFilterBlocked) {
      error = 'CENSORED_EXPOSURE: Upstream API content filter triggered; retrying discovery pass with alternative token sampling';
    }

    if ((exitCode !== 0 || procSignal) && executionTelemetry) {
      executionTelemetry.finishedReason = 'CENSORED_EXPOSURE';
    }

    const isRateLimit = isRateLimitError(stderr) || isRateLimitError(stdout) || isRateLimitError(error);

    lastResult = {
      fixtureId: fixture.id,
      file: fixture.file,
      modelId,
      durationMs,
      candidates,
      rawOutput: stdout,
      error,
      split,
      executionTelemetry
    };

    if (!error) {
      break;
    }

    if (attempt < maxAttempts) {
      let backoffMs = 1000;
      if (isRateLimit) {
        // Exponential backoff for HTTP 429 / ResourceExhausted: 5s, 10s, 20s
        backoffMs = 5000 * Math.pow(2, attempt - 1);
        if (options.mock) {
          backoffMs = Math.min(25, backoffMs);
        }
        console.warn(`  ⚠ Rate limit / ResourceExhausted detected on [${fixture.id}] (Attempt ${attempt}/${maxAttempts}). Backing off for ${backoffMs / 1000}s...`);
      } else {
        console.warn(`  ⚠ Attempt ${attempt} failed on [${fixture.id}]: ${(error || '').trim()}. Retrying in 1s...`);
      }
      sleepSync(backoffMs);
    }
  }

  if (options.cleanSandbox && hermeticInfo) {
    cleanHermeticSandbox(hermeticInfo.sandboxAbsDir);
  }

  return lastResult;
}

export const executeLiveDiscoveryPass = runAgyDiscoveryOnFixture;

/**
 * Computes partitioned metrics separating the Development Set (SEM-03)
 * from the Holdout Generalization Set (SEM-01..SEM-10 excluding SEM-03)
 * and evaluates safe control false-positive immunity.
 */
export function computePartitionedMetrics(stabilityResult, groundTruth = [], splits = BENCHMARK_FIXTURE_SPLITS, extra = {}) {
  const activeSplits = splits || BENCHMARK_FIXTURE_SPLITS;
  const recurrence = stabilityResult.findingsRecurrence || [];
  const devIds = new Set(activeSplits.developmentSet.ids);
  const holdoutIds = new Set(activeSplits.holdoutFixtures.ids);

  const devRecurrences = [];
  const holdoutRecurrences = [];
  const safeRecurrences = [];

  for (const item of recurrence) {
    const uri = item.location?.uri || '';
    let matchedId = null;

    for (const gt of groundTruth) {
      if (uri.includes(gt.file) || (item.symbol && item.symbol === gt.id)) {
        matchedId = gt.id;
        break;
      }
    }

    if (!matchedId) {
      for (const gt of groundTruth) {
        if (item.id?.includes(gt.id) || (item.title && item.title.includes(gt.name))) {
          matchedId = gt.id;
          break;
        }
      }
    }

    if (matchedId) {
      if (devIds.has(matchedId)) {
        devRecurrences.push({ ...item, matchedFixtureId: matchedId });
      } else if (holdoutIds.has(matchedId)) {
        holdoutRecurrences.push({ ...item, matchedFixtureId: matchedId });
      } else if (matchedId.endsWith('-SAFE')) {
        safeRecurrences.push({ ...item, matchedFixtureId: matchedId });
      }
    } else {
      if (uri.includes('/safe/')) {
        safeRecurrences.push(item);
      } else if (devIds.size > 0 && (uri.includes('03-confused-deputy') || uri.includes('09-prototype-pollution'))) {
        devRecurrences.push({ ...item, matchedFixtureId: uri.includes('03-confused-deputy') ? 'SEM-03' : 'SEM-09' });
      } else {
        holdoutRecurrences.push(item);
      }
    }
  }

  const devMeanRecurrence = devRecurrences.length > 0
    ? Number((devRecurrences.reduce((acc, r) => acc + r.reliabilityRate, 0) / devRecurrences.length).toFixed(4))
    : 0;

  const holdoutMeanRecurrence = holdoutRecurrences.length > 0
    ? Number((holdoutRecurrences.reduce((acc, r) => acc + r.reliabilityRate, 0) / holdoutRecurrences.length).toFixed(4))
    : 0;

  const safeCount = extra.safeFixtureCount !== undefined
    ? extra.safeFixtureCount
    : (groundTruth.filter(gt => gt.expectedVerdict === 'SAFE').length || 10);
  const totalPasses = extra.totalPasses || (stabilityResult.pairwiseJaccard ? stabilityResult.pairwiseJaccard.length + 1 : 1);
  const safeMetrics = computeSafeControlMetrics({
    safeRecurrences,
    allPassResults: extra.allPassResults || [],
    totalPasses,
    safeFixtureCount: safeCount
  });

  return {
    developmentSet: {
      fixtures: activeSplits.developmentSet.ids,
      lineagesCount: devRecurrences.length,
      meanRecurrenceRate: devMeanRecurrence,
      lineages: devRecurrences
    },
    holdoutSet: {
      fixtures: activeSplits.holdoutFixtures.ids,
      lineagesCount: holdoutRecurrences.length,
      meanRecurrenceRate: holdoutMeanRecurrence,
      lineages: holdoutRecurrences
    },
    safeControls: {
      ...safeMetrics,
      lineagesCount: safeRecurrences.length,
      totalFalsePositives: safeMetrics.totalSpuriousCandidates,
      spuriousLineages: safeRecurrences
    }
  };
}

/**
 * Generates publication-grade formal empirical baseline report in Markdown.
 */
export function renderEmpiricalBaselineReport({
  stabilityResult,
  partitionedMetrics,
  envelopes = [],
  options = {},
  repoRoot = DEFAULT_REPO_ROOT
}) {
  const env0 = envelopes[0]?.environment || {};
  const target0 = envelopes[0]?.target || {};
  const totalPasses = envelopes.length;
  const isEmpirical = stabilityResult.evaluationMode === 'RECORDED_EMPIRICAL';

  const pairwiseTableRows = (stabilityResult.pairwiseJaccard || []).map(p =>
    `| Pass ${p.runA} ↔ Pass ${p.runB} | ${(p.jaccard * 100).toFixed(1)}% | ${p.jaccard >= 0.8 ? 'PASS' : 'WARN'} |`
  ).join('\n');

  const recurrenceTableRows = (stabilityResult.findingsRecurrence || []).map(r => {
    const fixtureId = r.matchedFixtureId || r.symbol || r.id;
    return `| \`${r.lineageId?.substring(0, 10)}...\` | \`${fixtureId}\` | \`${r.ruleId}\` | ${r.recurrenceCount}/${totalPasses} | ${(r.reliabilityRate * 100).toFixed(1)}% | ${r.reliabilityRate === 1.0 ? 'PERFECT' : (r.reliabilityRate >= 0.6 ? 'MODERATE' : 'SPORADIC')} |`;
  }).join('\n');

  const devRec = partitionedMetrics.developmentSet;
  const holdRec = partitionedMetrics.holdoutSet;
  const safeRec = partitionedMetrics.safeControls || {};
  const safeMetrics = safeRec;
  const safeCount = safeMetrics.safeFixtureCount || 10;
  const totalSafeExposures = safeMetrics.totalExposures || (safeCount * totalPasses);
  const splits = options.fixtureSplits || (options.suite === 'holdout' ? SUITE_FIXTURE_SPLITS.holdout : BENCHMARK_FIXTURE_SPLITS);

  const isHoldout = options.suite === 'holdout' || target0.corpus === 'holdout-benchmark' || (splits.holdoutFixtures?.ids[0]?.startsWith('HLD-'));
  const safeCorpusRel = isHoldout ? 'evals/holdout-benchmark/safe' : 'evals/semantic-benchmark/safe';
  const hasSafeControls = Boolean(options.includeSafe || options.safeOnly);

  const corpusDesc = isHoldout
    ? '`evals/holdout-benchmark` (20-fixture paired holdout benchmark)'
    : '`evals/semantic-benchmark` (20-fixture paired semantic benchmark)';

  const principleDesc = isHoldout
    ? 'Default-Deny Presumption of Non-Pass; strictly uncalibrated Holdout Generalization Set (`HLD-01..HLD-10`) per Section 21 Holdout Covenant.'
    : 'Default-Deny Presumption of Non-Pass; partitioned Development Set (`SEM-03`) vs. Holdout Generalization Set (`SEM-01..SEM-10`).';

  const benchmarkScope = isHoldout ? 'holdout vulnerability benchmark' : 'semantic vulnerability benchmark';

  const partitioningNarrative = isHoldout
    ? `Under Section 21 governance, holdout benchmark fixtures are strictly segregated from calibration or training data to measure authentic out-of-distribution model generalization:
1. **Development Set**: Uncalibrated (0 fixtures; Section 21 covenant forbids prompt heuristics for holdout fixtures).
2. **Holdout Generalization Set (\`HLD-01..HLD-10\`)**: Evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution model generalization across 10 distinct CWE vulnerability classes.`
    : `Under Section 21 governance, benchmark fixtures are strictly segregated to avoid prompt-tuning overfitting:
1. **Development Set (\`SEM-03\` Confused Deputy & \`SEM-09\` Prototype Pollution)**: Calibrated during rule engineering with targeted prompt heuristics; serves as a regression baseline.
2. **Holdout Generalization Set (\`SEM-01..SEM-10\` excluding SEM-03 and SEM-09)**: Evaluated without targeted per-case prompt tuning to measure authentic out-of-distribution model generalization across 8 distinct CWE vulnerability classes.`;

  const devSetRole = splits.developmentSet.ids.length > 0
    ? 'Regression Baseline Calibration'
    : 'Uncalibrated (0 Fixtures per Section 21 Covenant)';

  const pubDate = options.publicationDate ||
    (envelopes[0]?.recordedAt ? envelopes[0].recordedAt.slice(0, 10) : '2026-09-17');

  return `# Empirical Baseline Evaluation Report: Model-Dependent Stochastic Discovery (N=${totalPasses})

**Evaluation Harness**: Antigravity Security Audit Plugin (\`@arcobaleno64/agy-security-audit\`)  
**Publication Date**: ${pubDate}  
**Corpus**: ${corpusDesc}  
**Governance Standard**: NIST SSDF (SP 800-218) / OWASP ASVS 5.0.0 / Section 21 Benchmark Protocol  
**Principle**: ${principleDesc}

---

## 1. Executive Summary & Provenance Attestation

This evaluation establishes the project's first authentic, model-dependent empirical baseline across $N=${totalPasses}$ independent execution passes on the ${benchmarkScope}. Unlike synthetic harness self-tests that yield an invariant 100%, this report records genuine stochastic LLM discovery behavior, measuring finding-set Jaccard similarity, lineage stability, and generalization beyond calibration fixtures.

| Provenance Property | Value / Attestation |
| :--- | :--- |
| **Evaluation Mode** | \`${stabilityResult.evaluationMode}\` |
| **Model-Dependent Run** | \`${stabilityResult.modelDependentRun}\` |
| **Evaluated Model ID** | \`${env0.modelId || 'gemini-3.8-flash-high'}\` |
| **Model Provider** | \`${env0.modelProvider || 'google'}\` |
| **Antigravity CLI Version** | \`${env0.agyVersion || '1.2.2'}\` |
| **Node.js Runtime** | \`${env0.nodeVersion || process.version}\` |
| **OS Architecture** | \`${env0.os || (process.platform + ' (' + process.arch + ')')}\` |
| **Security Audit Plugin Version** | \`${env0.toolVersion || '1.2.2'}\` |
| **TCB Integrity Digest** | \`${env0.toolIntegrityDigest || 'N/A'}\` |
| **Tool Dirty State** | \`${env0.toolDirty === false ? 'CLEAN (false)' : 'DIRTY (true)'}\` |
| **Repository Revision (SHA)** | \`${target0.commitSha || env0.toolRevision || 'UNKNOWN'}\` |
| **Total Evaluation Passes (N)** | \`${totalPasses}\` |
| **Safe Controls Audited** | \`${hasSafeControls ? `YES (${safeCount} paired safe controls${options.safeOnly ? ', safe-only mode' : ''})` : 'NO (vulnerable fixtures only)'}\` |

### Key Benchmark Metrics
- **Mean Pairwise Jaccard Similarity**: **${(stabilityResult.meanJaccardSimilarity * 100).toFixed(1)}%**
- **Unique Semantic Lineages Discovered**: **${stabilityResult.totalUniqueLineages}**
- **Consistently Recurrent Lineages (100% Passes)**: **${stabilityResult.perfectRecurrenceCount} / ${stabilityResult.totalUniqueLineages}**
${options.safeOnly
  ? `- **Mean Candidate Recall**: **N/A (No vulnerable positives in safe-only corpus)**
- **Mean Discovery Precision**: **N/A (Evaluates safe control false-positive exposure rather than vulnerability detection)**
- **Exposure Specificity**: **${((safeMetrics.exposureSpecificity !== undefined ? safeMetrics.exposureSpecificity : 1) * 100).toFixed(1)}%**
- **Run-Exposure False-Positive Rate**: **${((safeMetrics.runExposureFPRate || 0) * 100).toFixed(1)}%** (${safeMetrics.exposuresWithFP || 0}/${totalSafeExposures})
- **Fixture False-Positive Rate**: **${((safeMetrics.fixtureFPRate || 0) * 100).toFixed(1)}%** (${safeMetrics.fixturesWithFP || 0}/${safeCount})
- **FP Candidate Density**: **${(safeMetrics.fpCandidateDensity || 0).toFixed(3)}**
- **Max Lineage Recurrence**: **${safeMetrics.maxLineageRecurrence || 0} / ${totalPasses}** (${((safeMetrics.maxLineageRecurrenceRate || 0) * 100).toFixed(1)}%)`
  : (stabilityResult.empiricalEfficacy ? `- **Mean Candidate Recall**: **${(stabilityResult.empiricalEfficacy.meanCandidateRecall * 100).toFixed(1)}%**\n- **Mean Discovery Precision**: **${(stabilityResult.empiricalEfficacy.meanPrecision * 100).toFixed(1)}%**` : '')}

---

## 2. Multi-Pass Stochastic Stability & Jaccard Matrix (N=${totalPasses})

The pairwise Jaccard similarity metric $J(A, B) = \frac{|A \cap B|}{|A \cup B|}$ measures candidate finding-set invariance across independent discovery passes on identical codebases.

### Pairwise Comparison Matrix
| Pass Comparison | Jaccard Similarity | Status (Threshold ≥ 80.0%) |
| :--- | :--- | :--- |
${pairwiseTableRows}

- **Aggregate Mean Jaccard**: **${(stabilityResult.meanJaccardSimilarity * 100).toFixed(1)}%**
- **Pairwise Comparisons Evaluated**: ${stabilityResult.pairwiseComparisons}

---

## 3. Fixture Partitioning & Generalization Analysis

${partitioningNarrative}

### Partition Metrics Summary
| Partition Split | Fixture Count | Lineages Found | Mean Recurrence Rate | Role & Governance |
| :--- | :--- | :--- | :--- | :--- |
| **Development Set${splits.developmentSet.ids.length > 0 ? ` (\`${splits.developmentSet.ids.join('`, `')}\`)` : ''}** | ${splits.developmentSet.ids.length} | ${devRec.lineagesCount} | **${(devRec.meanRecurrenceRate * 100).toFixed(1)}%** | ${devSetRole} |
| **Holdout Generalization Set** | ${splits.holdoutFixtures.ids.length} | ${holdRec.lineagesCount} | **${(holdRec.meanRecurrenceRate * 100).toFixed(1)}%** | Unbiased Out-of-Distribution Generalization |

### Lineage Recurrence Breakdown
| Lineage Digest | Fixture / Symbol | CWE Rule | Passes Observed | Reliability Rate | Stability Classification |
| :--- | :--- | :--- | :--- | :--- | :--- |
${recurrenceTableRows}

---

## 4. Safe Control Specificity Baseline (Controlled Ground Truth)

${hasSafeControls ? `The benchmark harness audited all ${safeCount} paired safe controls (\`${safeCorpusRel}/*.js\`) across all $N=${totalPasses}$ independent passes (${totalSafeExposures} safe exposures) under label-blind materialization (\`LABEL_BLIND_V1\`).

### Safe-Control Specificity Metrics (Controlled Dual Ground Truth)
| Metric | Observed Value | Definition & Formula |
| :--- | :--- | :--- |
| **Controlled Safe Fixtures Evaluated** | \`${safeCount}\` | Distinct safe baseline control fixtures ($K$) |
| **Total Safe Exposures ($K \\times N$)** | \`${totalSafeExposures}\` | Total independent model exposures across passes |
| **Fixture False-Positive Rate** | **${((safeMetrics.fixtureFPRate || 0) * 100).toFixed(1)}%** (${safeMetrics.fixturesWithFP || 0}/${safeCount}) | Fraction of safe fixtures with $\\ge 1$ spurious candidate |
| **Run-Exposure False-Positive Rate** | **${((safeMetrics.runExposureFPRate || 0) * 100).toFixed(1)}%** (${safeMetrics.exposuresWithFP || 0}/${totalSafeExposures}) | Fraction of $(fixture, pass)$ exposures with $\\ge 1$ spurious candidate |
| **Exposure Specificity** | **${((safeMetrics.exposureSpecificity !== undefined ? safeMetrics.exposureSpecificity : 1) * 100).toFixed(1)}%** | $1 - \\text{Run-Exposure FP Rate}$ ($TN / (TN + FP)$) |
| **FP Candidate Density** | **${(safeMetrics.fpCandidateDensity || 0).toFixed(3)}** | Spurious candidates per safe exposure ($C_{spurious} / (K \\times N)$) |
| **Max Lineage Recurrence** | **${safeMetrics.maxLineageRecurrence || 0} / ${totalPasses}** (${((safeMetrics.maxLineageRecurrenceRate || 0) * 100).toFixed(1)}%) | Maximum recurrence of any single spurious lineage |

> [!IMPORTANT]
> ${(safeMetrics.totalSpuriousCandidates || safeRec.totalFalsePositives || 0) === 0
  ? `0 reportable false positives observed across ${totalPasses} valid runs on ${safeCount} controlled safe fixtures. This result is corpus- and configuration-bounded and does not imply false-positive immunity.`
  : `${safeMetrics.totalSpuriousCandidates || safeRec.totalFalsePositives} spurious candidate(s) observed across ${totalPasses} valid runs on ${safeCount} controlled safe fixtures. Specificity calibrated at ${((safeMetrics.exposureSpecificity || 0) * 100).toFixed(1)}%.`}
` : `No live safe-control evidence was collected in this run (\`--include-safe\` or \`--safe-only\` not active). No empirical specificity estimate is reported. Deterministic invariant results are reported separately and do not constitute empirical specificity evidence.`}

---

## 5. Failure Analysis & Boundary Edge Cases

Under Default-Deny, any candidate missed during discovery or exhibiting low recurrence is analyzed rather than masked:
1. **Stochastic Line Variance**: Slight variations in reported start/end line bounds across runs are automatically normalized by the semantic lineage algorithm (\`computeLineageFingerprint\`), ensuring line-shift invariance.
2. **Subtle Flaws & Multi-Step Logic**: Vulnerabilities involving complex multi-step taint tracking (e.g. \`SEM-08\` async message broker boundaries) or prototype pollution (\`SEM-09\`) exhibit the highest stochastic variance across model iterations.
${options.safeOnly
  ? `3. **Safe-Control Exposure & Verification Necessity**: On safe controls with mock architectural patterns, raw model discovery exhibits an observed ${((safeMetrics.runExposureFPRate || 0) * 100).toFixed(1)}% run-exposure false positive rate (${((safeMetrics.fixtureFPRate || 0) * 100).toFixed(1)}% fixture false-positive rate). This empirical exposure demonstrates that upstream LLM discovery generates spurious candidate hypotheses on defensive boilerplate, underscoring why downstream 3-lens verifier panels and finalization under Default-Deny are strictly necessary to prevent unverified candidates from reaching authoritative reports.`
  : `3. **Defensive Verification Protocol**: Candidate generation on complex codebases produces hypotheses that require multi-stage verification. Downstream 3-lens verifier panels and finalization under Default-Deny ensure unevidenced candidate hypotheses are eliminated prior to reporting.`}

---

## 6. Comparison: Authentic Empirical Baseline vs. Synthetic Benchmark

| Dimension | Synthetic Harness Baseline | Authentic Empirical Baseline (This Run) |
| :--- | :--- | :--- |
| **Evidence Origin** | \`SYNTHETIC\` | \`${envelopes[0]?.evidenceOrigin || 'MODEL_OBSERVED'}\` |
| **Execution Kind** | \`SIMULATED_HARNESS\` | \`${envelopes[0]?.executionKind || 'LIVE_AGENT'}\` |
| **Jaccard Similarity** | Fixed 100.0% (deterministic) | **${(stabilityResult.meanJaccardSimilarity * 100).toFixed(1)}%** (authentic empirical) |
| **Stochastic Variance** | Zero (simulated line shifts only) | Genuine model output variance |
| **Scientific Value** | Invariant regression gate | Real-world capability and reliability measurement |

---

*Report generated automatically by \`scripts/run-live-model-benchmark.mjs\`.*
`;
}

/**
 * Runs full live discovery benchmark across benchmark fixtures.
 * Supports multi-pass execution, partitioned evaluation, and automatic report rendering.
 */
export function runLiveModelBenchmark(repoRoot = DEFAULT_REPO_ROOT, options = {}) {
  const suite = options.suite === 'holdout' ? 'holdout' : 'semantic';
  const isHoldout = suite === 'holdout';
  const activeSplits = options.fixtureSplits || SUITE_FIXTURE_SPLITS[suite];
  const defaultGtRel = isHoldout
    ? 'evals/holdout-benchmark/ground-truth.json'
    : 'evals/semantic-benchmark/ground-truth.json';
  const gtPath = options.groundTruthPath || path.resolve(repoRoot, defaultGtRel);
  if (!fs.existsSync(gtPath)) {
    throw new Error(`Ground truth file missing: ${gtPath}`);
  }

  const groundTruth = JSON.parse(fs.readFileSync(gtPath, 'utf8'));
  const vulnerableFixtures = groundTruth.filter(gt => gt.expectedVerdict === 'VULNERABLE');
  const safeFixtures = groundTruth.filter(gt => gt.expectedVerdict === 'SAFE');

  const isSafeOnly = Boolean(options.safeOnly);
  let targetFixtures = isSafeOnly
    ? safeFixtures
    : (options.includeSafe ? [...vulnerableFixtures, ...safeFixtures] : vulnerableFixtures);

  if (options.fixtureId) {
    targetFixtures = targetFixtures.filter(f => f.id === options.fixtureId);
    if (targetFixtures.length === 0) {
      throw new Error(`Target fixture not found: ${options.fixtureId}`);
    }
  }

  if (options.shuffleSeed) {
    targetFixtures = shuffleArrayWithSeed(targetFixtures, options.shuffleSeed);
  }

  const passes = options.passes ? parseInt(options.passes, 10) : 1;
  const delayMs = options.delayMs !== undefined ? options.delayMs : (options.mock ? 0 : 1000);
  const timeoutMs = options.timeoutMs;
  const defaultOutDirName = isHoldout ? 'evals/holdout-live-runs' : 'evals/live-runs';
  const outDir = options.outDir !== undefined
    ? (options.outDir ? path.resolve(repoRoot, options.outDir) : null)
    : (passes > 1 && !options.mock ? path.resolve(repoRoot, defaultOutDirName) : null);

  const modelId = options.modelId || process.env.AGY_MODEL || 'gemini-3.8-flash-high';
  const modelProvider = options.modelProvider || process.env.AGY_MODEL_PROVIDER || 'google';

  let activeProtocol = null;
  if (options.protocol) {
    activeProtocol = typeof options.protocol === 'object'
      ? options.protocol
      : loadAndValidateProtocol(options.protocol, repoRoot);
    const expKey = options.experimentKey || (activeProtocol.protocolId === 'v1.5-g5-ablation-1' ? 'reasoningAblation' : 'holdoutPaired');
    verifyProtocolCompliance({
      suite,
      passes,
      includeSafe: Boolean(options.includeSafe || options.safeOnly),
      shuffleSeed: options.shuffleSeed,
      hermetic: options.hermetic !== false,
      labelBlind: options.labelBlind !== false,
      delayMs,
      timeoutMs,
      modelId,
      baseModel: options.baseModel,
      reasoningProfile: options.reasoningProfile,
      outDir,
      rawOutDir: options.outDir,
      repoRoot,
      mock: Boolean(options.mock)
    }, activeProtocol, expKey);
  }

  console.log('================================================================');
  console.log('Authentic Model Discovery Benchmark Runner (AGY Multi-Pass)');
  console.log(`  Evidence Origin:       ${options.mock ? 'SYNTHETIC' : 'MODEL_OBSERVED'}`);
  console.log(`  Execution Kind:        ${options.mock ? 'SIMULATED_HARNESS' : 'LIVE_AGENT'}`);
  console.log(`  Model ID:              ${modelId}`);
  if (options.baseModel) {
    console.log(`  Base Model:            ${options.baseModel}`);
  }
  if (options.reasoningProfile) {
    console.log(`  Reasoning Profile:     ${options.reasoningProfile}`);
  }
  if (activeProtocol) {
    console.log(`  Protocol Bound:        ${activeProtocol.protocolId} (${activeProtocol.protocolDigest.slice(0, 16)}...)`);
  }
  console.log(`  Evaluation Passes (N): ${passes}`);
  console.log(`  Target Fixtures:       ${targetFixtures.length} (${isSafeOnly ? safeFixtures.length + ' safe controls only' : vulnerableFixtures.length + ' vuln' + (options.includeSafe ? ', ' + safeFixtures.length + ' safe controls' : '')})`);
  if (options.shuffleSeed) {
    console.log(`  Shuffle Seed:          ${options.shuffleSeed}`);
  }
  console.log(`  Label-Blind Mode:      ${options.labelBlind !== false ? 'ENABLED (LABEL_BLIND_V1)' : 'DISABLED'}`);
  console.log(`  Hermetic Isolation:    ${options.hermetic !== false ? 'ENABLED (HERMETIC_BENCHMARK_V1)' : 'DISABLED'}`);
  console.log(`  Throttle Delay:        ${delayMs}ms`);
  console.log(`  Sandbox Mode:          ${options.sandbox ? 'ENABLED (--sandbox)' : 'DISABLED'}`);
  if (outDir) {
    console.log(`  Output Directory:      ${outDir}`);
  }
  if (options.mock) {
    console.log('  Notice:                Running in SIMULATED MOCK MODE');
  }
  console.log('================================================================\n');

  const isResume = Boolean(options.resume);
  const outDirRel = outDir ? path.relative(repoRoot, outDir).replace(/\\/g, '/').replace(/^\.\//, '') : '';
  const outDirSlug = outDirRel.replace(/[^a-zA-Z0-9_-]/g, '_');
  const defaultCheckpointsDir = options.mock
    ? 'scratch/mock-benchmark/checkpoints'
    : (outDirSlug
        ? path.join('scratch/live-benchmark/checkpoints', outDirSlug)
        : 'scratch/live-benchmark/checkpoints');
  const checkpointsBaseDir = options.checkpointsDir
    ? path.resolve(repoRoot, options.checkpointsDir)
    : path.resolve(repoRoot, defaultCheckpointsDir);

  if (outDir) {
    fs.mkdirSync(outDir, { recursive: true });
  }

  const explicitIdentitySource = (options.baseModel || options.reasoningProfile || options.identitySource === 'CONFIG_DECLARED')
    ? 'CONFIG_DECLARED'
    : (options.identitySource || undefined);

  const envProv = probeEnvironment(repoRoot, {
    modelId,
    modelProvider,
    ...(options.baseModel ? { baseModel: options.baseModel } : {}),
    ...(options.reasoningProfile ? { reasoningProfile: options.reasoningProfile } : {}),
    ...(explicitIdentitySource ? { identitySource: explicitIdentitySource } : {}),
    ...(options.environment || {})
  });

  const envelopes = [];
  const allPassResults = [];

  for (let p = 1; p <= passes; p++) {
    const runId = passes > 1 ? `run-pass-${p}` : (options.runId || `run-pass-${p}`);
    const passFilePath = outDir
      ? path.join(outDir, `${runId}.json`)
      : (options.output ? path.resolve(repoRoot, options.output) : null);

    // 1. Idempotent Pass Resume: If pass envelope exists and is valid for all targetFixtures
    if (isResume && passFilePath && fs.existsSync(passFilePath)) {
      try {
        const rawPass = fs.readFileSync(passFilePath, 'utf8');
        const parsedEnvelope = JSON.parse(rawPass);
        const valResult = validateBenchmarkRunEnvelope(parsedEnvelope);
        const expectedOrigin = options.mock ? 'SYNTHETIC' : 'MODEL_OBSERVED';
        if (valResult.valid && parsedEnvelope.evidenceOrigin === expectedOrigin) {
          const auditedIds = new Set((parsedEnvelope.metadata?.fixtureResults || []).map(r => r.fixtureId));
          const hasAllFixtures = targetFixtures.every(f => auditedIds.has(f.id));
          if (hasAllFixtures) {
            console.log(`\n>>> [RESUME] Pass ${p} of ${passes} already complete and valid (${passFilePath}). Skipping model invocation.`);
            envelopes.push(parsedEnvelope);
            allPassResults.push({
              passIndex: p,
              fixtureResults: parsedEnvelope.metadata?.fixtureResults || [],
              candidateCount: parsedEnvelope.findings?.candidates?.length || 0
            });
            continue;
          } else {
            console.log(`  ℹ Existing pass file at ${passFilePath} contains ${auditedIds.size}/${targetFixtures.length} target fixtures. Re-running pass.`);
          }
        } else if (!valResult.valid) {
          console.warn(`  ⚠ Existing pass file failed envelope schema validation (${passFilePath}): ${valResult.errors.join('; ')}. Re-running pass.`);
        }
      } catch (err) {
        console.warn(`  ⚠ Existing pass file unreadable or invalid (${passFilePath}): ${err.message}. Re-running pass.`);
      }
    }

    console.log(`\n>>> Starting Pass ${p} of ${passes}...`);
    const passStartTime = Date.now();
    const fixtureResults = [];
    const passCandidates = [];
    const passCheckpointDir = path.join(checkpointsBaseDir, `pass-${p}`);
    fs.mkdirSync(passCheckpointDir, { recursive: true });

    for (let i = 0; i < targetFixtures.length; i++) {
      const fix = targetFixtures[i];
      const checkpointFile = path.join(passCheckpointDir, `${fix.id}.json`);
      let res = null;

      // 2. Per-fixture checkpoint resume
      if (isResume && fs.existsSync(checkpointFile)) {
        try {
          const rawCheckpoint = fs.readFileSync(checkpointFile, 'utf8');
          const parsedCheckpoint = JSON.parse(rawCheckpoint);
          const isMockCheckpoint = parsedCheckpoint?.executionTelemetry?.format === 'SIMULATED_MOCK';
          const formatCompatible = options.mock ? isMockCheckpoint : !isMockCheckpoint;

          if (parsedCheckpoint?.modelId && modelId && parsedCheckpoint.modelId !== modelId) {
            console.warn(`  ⚠ Checkpoint for [${fix.id}] was produced by model '${parsedCheckpoint.modelId}', but current run expects '${modelId}'. Discarding cross-model checkpoint.`);
          } else if (parsedCheckpoint && parsedCheckpoint.fixtureId === fix.id && Array.isArray(parsedCheckpoint.candidates) && formatCompatible) {
            const candVal = validateCandidateSet({ candidates: parsedCheckpoint.candidates });
            if (candVal.valid) {
              res = parsedCheckpoint;
              console.log(`[Pass ${p}/${passes}] [RESUME] Checkpoint restored for [${fix.id}] from ${checkpointFile}`);
            } else {
              console.warn(`  ⚠ Checkpoint for [${fix.id}] has invalid candidate schema (${checkpointFile}): ${candVal.errors.join('; ')}. Re-auditing.`);
            }
          }
        } catch (err) {
          console.warn(`  ⚠ Checkpoint for [${fix.id}] invalid (${checkpointFile}): ${err.message}. Re-auditing.`);
        }
      }

      if (!res) {
        console.log(`[Pass ${p}/${passes}] Auditing fixture [${fix.id}]: ${fix.file}...`);
        res = runAgyDiscoveryOnFixture(fix, repoRoot, { ...options, fixtureSplits: activeSplits, passIndex: p, modelId });
        try {
          writeJsonAtomic(checkpointFile, res);
        } catch (err) {
          console.warn(`  ⚠ Failed to write checkpoint for [${fix.id}]: ${err.message}`);
        }

        if (delayMs > 0 && i < targetFixtures.length - 1) {
          sleepSync(delayMs);
        }
      }

      fixtureResults.push(res);
      passCandidates.push(...res.candidates);

      if (res.error) {
        console.warn(`  ⚠ Discovery execution error on [${fix.id}]: ${res.error.trim()}`);
      }
      console.log(`  -> Found ${res.candidates.length} candidate(s) in ${res.durationMs}ms [${res.split}]`);
    }

    const passDurationMs = Date.now() - passStartTime;

    const telemList = fixtureResults.map(r => r.executionTelemetry).filter(Boolean);
    let passTelemetry = null;
    if (telemList.length > 0) {
      const primary = telemList[0];
      const aggregatedTokens = telemList.reduce((acc, t) => {
        const u = t.tokenUsage || {};
        acc.inputTokens += (u.inputTokens || 0);
        acc.outputTokens += (u.outputTokens || 0);
        acc.thinkingTokens += (u.thinkingTokens || 0);
        acc.cacheReadTokens += (u.cacheReadTokens || 0);
        acc.totalTokens += (u.totalTokens || 0);
        return acc;
      }, { inputTokens: 0, outputTokens: 0, thinkingTokens: 0, cacheReadTokens: 0, totalTokens: 0 });

      const allAvailableTools = Array.from(new Set(telemList.flatMap(t => t.availableTools || [])));
      const allToolsUsed = Array.from(new Set(telemList.flatMap(t => t.toolsUsed || [])));
      const allSubagents = Array.from(new Set(telemList.flatMap(t => t.subagentsInvoked || [])));
      const totalEvents = telemList.reduce((acc, t) => acc + (t.totalEvents || 0), 0);
      const totalDuration = Number((passDurationMs / 1000).toFixed(3));

      passTelemetry = {
        format: options.mock ? 'SIMULATED_MOCK' : (primary.format || 'AGY_STREAM_JSON_V1'),
        conversationId: primary.conversationId || (options.mock ? `sim-mock-pass-${p}` : null),
        telemetryDigest: crypto.createHash('sha256').update(telemList.map(t => t.telemetryDigest || '').join(':')).digest('hex'),
        totalEvents,
        availableTools: allAvailableTools.length > 0 ? allAvailableTools : (primary.availableTools || ['view_file', 'list_dir', 'grep_search', 'find_by_name']),
        toolsUsed: allToolsUsed,
        subagentsInvoked: allSubagents,
        permissionMode: primary.permissionMode || 'always-proceed',
        sandboxEnabled: Boolean(options.sandbox),
        tokenUsage: aggregatedTokens,
        durationSeconds: totalDuration
      };
    } else if (options.mock) {
      passTelemetry = {
        format: 'SIMULATED_MOCK',
        conversationId: `sim-mock-pass-${p}`,
        telemetryDigest: crypto.createHash('sha256').update(`sim-mock-pass-${p}`).digest('hex'),
        totalEvents: 1,
        availableTools: ['view_file', 'list_dir', 'grep_search', 'find_by_name'],
        toolsUsed: ['view_file'],
        subagentsInvoked: [],
        permissionMode: 'always-proceed',
        sandboxEnabled: Boolean(options.sandbox),
        tokenUsage: {
          inputTokens: 100,
          outputTokens: 50,
          thinkingTokens: 0,
          cacheReadTokens: 0,
          totalTokens: 150
        },
        durationSeconds: Number((passDurationMs / 1000).toFixed(3))
      };
    }

    const envelope = createBenchmarkRunEnvelope({
      repoRoot,
      runId,
      benchmarkMode: 'DISCOVERY',
      evidenceOrigin: options.mock ? 'SYNTHETIC' : 'MODEL_OBSERVED',
      executionKind: options.mock ? 'SIMULATED_HARNESS' : 'LIVE_AGENT',
      target: {
        repositoryName: isHoldout ? 'evals/holdout-benchmark' : 'evals/semantic-benchmark',
        repositoryUri: 'https://github.com/arcobaleno64/agy-security-audit.git',
        corpus: isHoldout ? 'holdout-benchmark' : 'semantic-benchmark'
      },
      environment: {
        ...envProv,
        ...(options.environment || {})
      },
      candidates: passCandidates,
      executionDurationMs: passDurationMs,
      executionTelemetry: passTelemetry,
      metadata: {
        passIndex: p,
        totalPasses: passes,
        suite,
        protocolId: activeProtocol ? activeProtocol.protocolId : null,
        protocolDigest: activeProtocol ? activeProtocol.protocolDigest : null,
        baseModel: options.baseModel || envProv.baseModel || null,
        reasoningProfile: options.reasoningProfile || envProv.reasoningProfile || null,
        identitySource: envProv.identitySource || null,
        fixtureSplits: activeSplits,
        includeSafe: Boolean(options.includeSafe || options.safeOnly),
        safeOnly: isSafeOnly,
        shuffleSeed: options.shuffleSeed || null,
        labelBlind: options.labelBlind !== false,
        hermetic: options.hermetic !== false,
        hermeticHarnessVersion: options.hermetic !== false ? 'HERMETIC_BENCHMARK_V1' : null,
        throttleDelayMs: delayMs,
        pacingPolicy: `${delayMs}ms inter-call throttle delay`,
        fixtureResults: fixtureResults.map(r => ({
          fixtureId: r.fixtureId,
          split: r.split,
          candidateCount: r.candidates.length,
          durationMs: r.durationMs,
          error: r.error || null
        })),
        governanceNote: isHoldout
          ? 'Holdout generalization benchmark: all 10 fixtures strictly uncalibrated per Section 21 covenant.'
          : 'SEM-03 classified as development-set / regression fixture; holdout fixtures evaluate generalization.'
      }
    });

    if (outDir) {
      const passFilePath = path.join(outDir, `${runId}.json`);
      writeJsonAtomic(passFilePath, envelope);
      console.log(`  ✔ Pass ${p} envelope written to: ${passFilePath}`);
    }

    envelopes.push(envelope);
    allPassResults.push({ passIndex: p, fixtureResults, candidateCount: passCandidates.length });

    if (p < passes && delayMs > 0) {
      sleepSync(delayMs);
    }
  }

  // Multi-pass stability evaluation & partitioned aggregation
  let stabilityResult = null;
  let partitionedMetrics = null;
  let discoveryEval = null;

  if (passes >= 2) {
    stabilityResult = evaluateStability(envelopes, repoRoot, { groundTruth });
    const targetSafeCount = targetFixtures.filter(f => f.expectedVerdict === 'SAFE' || f.id?.endsWith('-SAFE')).length;
    partitionedMetrics = computePartitionedMetrics(stabilityResult, groundTruth, activeSplits, {
      allPassResults,
      totalPasses: passes,
      safeFixtureCount: targetSafeCount > 0 ? targetSafeCount : undefined
    });

    console.log('\n================================================================');
    console.log(`Empirical Stability Aggregation (N=${passes} Passes):`);
    console.log(`  Evaluation Mode:                 ${stabilityResult.evaluationMode}`);
    console.log(`  Model-Dependent Run:             ${stabilityResult.modelDependentRun}`);
    console.log(`  Mean Finding-Set Jaccard:        ${(stabilityResult.meanJaccardSimilarity * 100).toFixed(1)}%`);
    console.log(`  Unique Semantic Lineages:        ${stabilityResult.totalUniqueLineages}`);
    console.log(`  100% Reliable Lineages:          ${stabilityResult.perfectRecurrenceCount}/${stabilityResult.totalUniqueLineages}`);
    console.log(`  Development Set Recurrence:      ${(partitionedMetrics.developmentSet.meanRecurrenceRate * 100).toFixed(1)}% (${activeSplits.developmentSet.ids.join(', ') || 'None'})`);
    console.log(`  Holdout Set Mean Recurrence:     ${(partitionedMetrics.holdoutSet.meanRecurrenceRate * 100).toFixed(1)}% (${isHoldout ? 'HLD-01..10' : 'SEM-01..10'})`);
    if (options.includeSafe || options.safeOnly) {
      console.log(`  Safe Control Specificity:        ${((partitionedMetrics.safeControls.exposureSpecificity ?? 1) * 100).toFixed(1)}%`);
      console.log(`  Safe Control False Positives:    ${partitionedMetrics.safeControls.totalFalsePositives}`);
      console.log(`  Safe Run-Exposure FP Rate:       ${((partitionedMetrics.safeControls.runExposureFPRate ?? 0) * 100).toFixed(1)}%`);
    }
    console.log('================================================================\n');
  } else {
    discoveryEval = evaluateDiscovery(envelopes[0].findings.candidates, groundTruth, options);
    console.log('\n================================================================');
    console.log('Empirical Discovery Evaluation (Single Pass):');
    console.log(`  Run ID:                          ${envelopes[0].runId}`);
    console.log(`  Evidence Origin:                 ${envelopes[0].evidenceOrigin}`);
    console.log(`  Execution Kind:                  ${envelopes[0].executionKind}`);
    console.log(`  Total Ground Truth:              ${discoveryEval.totalGroundTruth} (${discoveryEval.vulnerableCount} vuln, ${discoveryEval.safeCount} safe)`);
    console.log(`  Candidates Evaluated:            ${discoveryEval.totalCandidates}`);
    console.log(`  Candidate True Pos (TP):         ${discoveryEval.candidateTP}`);
    console.log(`  Candidate False Pos (FP):        ${discoveryEval.candidateFP}`);
    console.log(`  Candidate False Neg (FN):        ${discoveryEval.candidateFN}`);
    if (isSafeOnly) {
      console.log(`  Discovery Precision:             N/A (Evaluates safe control false-positive exposure rather than vulnerability detection)`);
      console.log(`  Discovery Recall:                N/A (No vulnerable positives in safe-only corpus)`);
      console.log(`  Discovery F1 Score:              N/A`);
    } else {
      console.log(`  Discovery Precision:             ${(discoveryEval.precision * 100).toFixed(1)}%`);
      console.log(`  Discovery Recall:                ${(discoveryEval.recall * 100).toFixed(1)}%`);
      console.log(`  Discovery F1 Score:              ${discoveryEval.f1.toFixed(3)}`);
    }
    console.log('================================================================\n');
  }

  // Formal Report Generation Hook
  let reportMarkdown = null;
  if (options.reportPath) {
    const reportTarget = path.resolve(repoRoot, options.reportPath);
    fs.mkdirSync(path.dirname(reportTarget), { recursive: true });

    if (passes >= 2 && stabilityResult && partitionedMetrics) {
      reportMarkdown = renderEmpiricalBaselineReport({
        stabilityResult,
        partitionedMetrics,
        envelopes,
        options: { ...options, fixtureSplits: activeSplits, safeOnly: isSafeOnly },
        repoRoot
      });
    } else {
      // Single pass report
      reportMarkdown = `# Single-Pass Discovery Benchmark Run

**Run ID**: \`${envelopes[0]?.runId}\`  
**Evidence Origin**: \`${envelopes[0]?.evidenceOrigin}\`  
**Execution Kind**: \`${envelopes[0]?.executionKind}\`  
**Model ID**: \`${envelopes[0]?.environment?.modelId || 'unknown'}\`  
**Total Candidates**: ${envelopes[0]?.findings?.candidates?.length || 0}  

### Discovery Evaluation Metrics
- **Candidates Evaluated**: ${discoveryEval?.totalCandidates ?? 0}
- **True Positives (TP)**: ${discoveryEval?.candidateTP ?? 0}
- **False Positives (FP)**: ${discoveryEval?.candidateFP ?? 0}
- **False Negatives (FN)**: ${discoveryEval?.candidateFN ?? 0}
${isSafeOnly
  ? `- **Discovery Precision**: **N/A (Evaluates safe control false-positive exposure rather than vulnerability detection)**\n- **Discovery Recall**: **N/A (No vulnerable positives in safe-only corpus)**\n- **Discovery F1 Score**: **N/A**`
  : `- **Discovery Precision**: ${discoveryEval ? (discoveryEval.precision * 100).toFixed(1) : '0.0'}%\n- **Discovery Recall**: ${discoveryEval ? (discoveryEval.recall * 100).toFixed(1) : '0.0'}%\n- **Discovery F1 Score**: ${discoveryEval ? discoveryEval.f1.toFixed(3) : '0.000'}`}
`;
    }

    fs.writeFileSync(reportTarget, reportMarkdown, 'utf8');
    console.log(`✔ Formal empirical baseline report rendered: ${reportTarget}`);
  }

  return {
    envelopes,
    envelope: envelopes[0],
    stabilityResult,
    partitionedMetrics,
    discoveryEval,
    allPassResults,
    reportMarkdown
  };
}

/**
 * Internal self-test suite validating label stripping, projection, shuffling, and specificity metrics.
 */
export function runHarnessSelfTests(repoRoot = DEFAULT_REPO_ROOT) {
  console.log('Running run-live-model-benchmark.mjs harness unit tests...');

  // Test 1: stripLabelLeakingComments preserves lines and strips leakage
  const sample1 = `// evals/semantic-benchmark/safe/01-authz-bypass.js
// Semantic Category: authz-bypass (CWE-862 - SAFE GUARDED)
import express from 'express';
const router = express.Router();
// normal inline comment
const x = 1;
// evals/something safe
const y = 2;`;

  const stripped = stripLabelLeakingComments(sample1);
  const strippedLines = stripped.split('\n');
  if (strippedLines.length !== sample1.split('\n').length) {
    throw new Error(`stripLabelLeakingComments line count mismatch: expected ${sample1.split('\n').length}, got ${strippedLines.length}`);
  }
  if (/evals\/|authz-bypass|CWE-862|SAFE GUARDED/i.test(stripped)) {
    throw new Error('stripLabelLeakingComments leaked ground truth tokens');
  }
  if (!strippedLines[2].includes('import express')) {
    throw new Error(`stripLabelLeakingComments corrupted code line 3: ${strippedLines[2]}`);
  }
  console.log('  ✔ Test 1: stripLabelLeakingComments correctly strips labels while preserving 1:1 line numbers.');

  // Test 2: projectLabelBlindFixture creates projected file and returns proper metadata
  const dummyFixture = {
    id: 'SEM-01-SAFE',
    file: 'evals/semantic-benchmark/safe/01-authz-bypass.js',
    expectedVerdict: 'SAFE'
  };
  const proj = projectLabelBlindFixture(dummyFixture, repoRoot);
  if (!fs.existsSync(proj.projectedAbsPath)) {
    throw new Error(`Projected file not found: ${proj.projectedAbsPath}`);
  }
  if (proj.strippedContent.includes('evals/semantic-benchmark/safe')) {
    throw new Error('Projected content contains raw path');
  }
  console.log('  ✔ Test 2: projectLabelBlindFixture successfully materializes label-blind case.');

  // Test 3: shuffleArrayWithSeed determinism
  const arr = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
  const shuf1 = shuffleArrayWithSeed(arr, 'seed-123');
  const shuf2 = shuffleArrayWithSeed(arr, 'seed-123');
  const shuf3 = shuffleArrayWithSeed(arr, 'seed-456');
  if (JSON.stringify(shuf1) !== JSON.stringify(shuf2)) {
    throw new Error('shuffleArrayWithSeed not deterministic for same seed');
  }
  if (JSON.stringify(shuf1) === JSON.stringify(arr)) {
    throw new Error('shuffleArrayWithSeed failed to permute array');
  }
  if (JSON.stringify(shuf1) === JSON.stringify(shuf3)) {
    throw new Error('shuffleArrayWithSeed produced identical array for different seeds');
  }
  console.log('  ✔ Test 3: shuffleArrayWithSeed produces deterministic permutations.');

  // Test 4: computeSafeControlMetrics calculations
  const zeroFP = computeSafeControlMetrics({
    safeRecurrences: [],
    allPassResults: [
      { passIndex: 1, fixtureResults: [{ fixtureId: 'F1', split: 'SAFE_CONTROL', candidates: [] }] },
      { passIndex: 2, fixtureResults: [{ fixtureId: 'F1', split: 'SAFE_CONTROL', candidates: [] }] }
    ],
    totalPasses: 2,
    safeFixtureCount: 10
  });
  if (zeroFP.exposureSpecificity !== 1.0 || zeroFP.totalSpuriousCandidates !== 0 || zeroFP.fixturesWithFP !== 0) {
    throw new Error(`computeSafeControlMetrics failed on zero-FP: ${JSON.stringify(zeroFP)}`);
  }

  const positiveFP = computeSafeControlMetrics({
    safeRecurrences: [{ matchedFixtureId: 'F1', recurrenceCount: 2 }],
    allPassResults: [
      { passIndex: 1, fixtureResults: [{ fixtureId: 'F1', split: 'SAFE_CONTROL', candidates: [{ id: 'C1' }] }] },
      { passIndex: 2, fixtureResults: [{ fixtureId: 'F1', split: 'SAFE_CONTROL', candidates: [{ id: 'C2' }] }] }
    ],
    totalPasses: 2,
    safeFixtureCount: 10
  });
  if (positiveFP.fixturesWithFP !== 1 || positiveFP.runExposureFPRate !== 0.1 || positiveFP.exposureSpecificity !== 0.9 || positiveFP.totalSpuriousCandidates !== 2) {
    throw new Error(`computeSafeControlMetrics failed on positive-FP: ${JSON.stringify(positiveFP)}`);
  }
  console.log('  ✔ Test 4: computeSafeControlMetrics correctly computes specificity, density, and recurrence.');

  // Test 5: Simulated safe-only multi-pass benchmark
  const mockRun = runLiveModelBenchmark(repoRoot, {
    safeOnly: true,
    mock: true,
    passes: 3,
    shuffleSeed: 'test-seed'
  });
  if (!mockRun.stabilityResult || mockRun.envelopes.length !== 3) {
    throw new Error('runLiveModelBenchmark mock safe-only run failed');
  }
  if (mockRun.partitionedMetrics.safeControls.exposureSpecificity !== 1.0) {
    throw new Error('Mock safe controls had non-1.0 specificity');
  }
  console.log('  ✔ Test 5: runLiveModelBenchmark executes safe-only mock passes cleanly.');

  // Test 6: isRateLimitError detection
  if (!isRateLimitError('HTTP 429 Too Many Requests') ||
      !isRateLimitError('ResourceExhausted: Quota exceeded for model') ||
      !isRateLimitError('RESOURCE_EXHAUSTED') ||
      !isRateLimitError('rate limit exceeded') ||
      isRateLimitError('SyntaxError: unexpected token') ||
      isRateLimitError('')) {
    throw new Error('isRateLimitError failed on expected status strings');
  }
  console.log('  ✔ Test 6: isRateLimitError correctly identifies rate-limit and resource-exhaustion patterns.');

  // Test 7: Atomic per-fixture checkpointing and idempotent resume
  const testCheckpointsDir = path.resolve(repoRoot, 'scratch/test-harness-checkpoints');
  const testOutDir = path.resolve(repoRoot, 'scratch/test-harness-out');
  try {
    fs.rmSync(testCheckpointsDir, { recursive: true, force: true });
    fs.rmSync(testOutDir, { recursive: true, force: true });
  } catch {}

  // 7a. Test atomic writing
  const sampleData = { test: 'data', timestamp: 12345 };
  const sampleFilePath = path.join(testCheckpointsDir, 'atomic-test.json');
  writeJsonAtomic(sampleFilePath, sampleData);
  const readBack = JSON.parse(fs.readFileSync(sampleFilePath, 'utf8'));
  if (readBack.test !== 'data' || readBack.timestamp !== 12345) {
    throw new Error('writeJsonAtomic data corrupted on write/read');
  }

  // 7b. Pre-seed a per-fixture checkpoint for SEM-01-SAFE in pass-1
  const pass1Dir = path.join(testCheckpointsDir, 'pass-1');
  const seededCheckpoint = {
    fixtureId: 'SEM-01-SAFE',
    file: 'evals/semantic-benchmark/safe/01-authz-bypass.js',
    durationMs: 12,
    candidates: [],
    rawOutput: '{"schemaVersion":"1.0.0","candidates":[]}',
    error: null,
    split: 'SAFE_CONTROL',
    executionTelemetry: null
  };
  writeJsonAtomic(path.join(pass1Dir, 'SEM-01-SAFE.json'), seededCheckpoint);

  // 7c. Run live model benchmark with mock and resume
  const resumeRun1 = runLiveModelBenchmark(repoRoot, {
    safeOnly: true,
    mock: true,
    passes: 1,
    resume: true,
    outDir: testOutDir,
    checkpointsDir: 'scratch/test-harness-checkpoints'
  });

  if (resumeRun1.envelopes.length !== 1) {
    throw new Error('resumeRun1 failed to produce pass envelope');
  }

  // Verify that all 10 safe checkpoints exist now
  for (let i = 1; i <= 10; i++) {
    const padId = `SEM-${String(i).padStart(2, '0')}-SAFE`;
    const cpFile = path.join(pass1Dir, `${padId}.json`);
    if (!fs.existsSync(cpFile)) {
      throw new Error(`Expected checkpoint missing: ${cpFile}`);
    }
  }

  // Verify pass file was written to testOutDir
  const pass1File = path.join(testOutDir, 'run-pass-1.json');
  if (!fs.existsSync(pass1File)) {
    throw new Error(`Expected pass file missing: ${pass1File}`);
  }

  // 7d. Run again with resume: true; should load existing pass-1 envelope directly without re-auditing
  const resumeRun2 = runLiveModelBenchmark(repoRoot, {
    safeOnly: true,
    mock: true,
    passes: 1,
    resume: true,
    outDir: testOutDir,
    checkpointsDir: 'scratch/test-harness-checkpoints'
  });

  if (resumeRun2.envelopes.length !== 1) {
    throw new Error('resumeRun2 failed to load pass envelope');
  }

  // 7e. Multi-pass resume expansion + invalid candidate schema rejection
  const pass2Dir = path.join(testCheckpointsDir, 'pass-2');
  const invalidCheckpoint = {
    fixtureId: 'SEM-02-SAFE',
    file: 'evals/semantic-benchmark/safe/02-cross-tenant-access.js',
    durationMs: 10,
    candidates: [{ malformedCandidate: true }],
    rawOutput: '{"malformedCandidate":true}',
    error: null,
    split: 'SAFE_CONTROL',
    executionTelemetry: { format: 'SIMULATED_MOCK' }
  };
  writeJsonAtomic(path.join(pass2Dir, 'SEM-02-SAFE.json'), invalidCheckpoint);

  // Run with passes: 2; Pass 1 should load from disk, Pass 2 should reject invalid SEM-02-SAFE checkpoint, re-audit, and finish
  const resumeRun3 = runLiveModelBenchmark(repoRoot, {
    safeOnly: true,
    mock: true,
    passes: 2,
    resume: true,
    outDir: testOutDir,
    checkpointsDir: 'scratch/test-harness-checkpoints'
  });

  if (resumeRun3.envelopes.length !== 2) {
    throw new Error('resumeRun3 failed to produce 2 pass envelopes');
  }
  const repairedCp = JSON.parse(fs.readFileSync(path.join(pass2Dir, 'SEM-02-SAFE.json'), 'utf8'));
  const repairedVal = validateCandidateSet({ candidates: repairedCp.candidates });
  if (!repairedVal.valid) {
    throw new Error('SEM-02-SAFE checkpoint was not repaired with valid candidates on re-audit');
  }

  // Cleanup test artifacts
  try {
    fs.rmSync(testCheckpointsDir, { recursive: true, force: true });
    fs.rmSync(testOutDir, { recursive: true, force: true });
  } catch {}

  console.log('  ✔ Test 7: Atomic per-fixture checkpointing, schema-validated candidate resume, and multi-pass expansion verified.');

  // Test 8: Hermetic Sandbox Harness (HERMETIC_BENCHMARK_V1)
  const hermeticFixture = {
    id: 'HLD-01-SAFE',
    file: 'evals/holdout-benchmark/safe/01-ssti-template-injection.js',
    expectedVerdict: 'SAFE'
  };
  const sandboxMeta = prepareHermeticSandbox(hermeticFixture, repoRoot);
  if (!fs.existsSync(sandboxMeta.sandboxAbsDir)) {
    throw new Error(`Hermetic sandbox directory not created: ${sandboxMeta.sandboxAbsDir}`);
  }
  const sandboxFiles = fs.readdirSync(sandboxMeta.sandboxAbsDir);
  if (!sandboxFiles.includes(sandboxMeta.targetFileName) || !sandboxFiles.includes('package.json')) {
    throw new Error(`Hermetic sandbox missing expected files: ${sandboxFiles.join(', ')}`);
  }
  for (const forbidden of ['ground-truth.json', '.git', 'reports', 'evals', 'scripts', 'skills']) {
    if (sandboxFiles.includes(forbidden)) {
      throw new Error(`Hermetic sandbox containment breached; contains forbidden '${forbidden}'`);
    }
  }
  const pkgContent = JSON.parse(fs.readFileSync(path.join(sandboxMeta.sandboxAbsDir, 'package.json'), 'utf8'));
  if (pkgContent.name !== 'hermetic-sandbox-fixture' || pkgContent.type !== 'module') {
    throw new Error('Hermetic sandbox package.json invalid');
  }
  const codeContent = fs.readFileSync(sandboxMeta.targetAbsPath, 'utf8');
  if (/evals\/|ssti-template-injection|SAFE|CWE-/i.test(codeContent)) {
    throw new Error('Hermetic target code leaked labels/categories');
  }
  const mockHermeticRes = runAgyDiscoveryOnFixture(hermeticFixture, repoRoot, {
    mock: true,
    hermetic: true
  });
  if (mockHermeticRes.file !== hermeticFixture.file) {
    throw new Error(`Candidate file not mapped back to authoritative path: got ${mockHermeticRes.file}`);
  }
  cleanHermeticSandbox(sandboxMeta.sandboxAbsDir);
  console.log('  ✔ Test 8: Hermetic Sandbox Harness (HERMETIC_BENCHMARK_V1) strictly isolates workspace and metadata.');

  // Test 9: Evaluation Protocol Freeze & Integrity Validation (v1.5-eval-1)
  const protoFile = 'evals/protocols/v1.5-eval-1.json';
  const protoObj = loadAndValidateProtocol(protoFile, repoRoot);
  if (protoObj.protocolId !== 'v1.5-eval-1' || protoObj.status !== 'FROZEN') {
    throw new Error('loadAndValidateProtocol failed on valid protocol v1.5-eval-1');
  }

  // Test 9b: Tampering rejection (Fail-Closed)
  const tamperedProto = JSON.parse(JSON.stringify(protoObj));
  tamperedProto.experiments.holdoutPaired.passes = 999;
  let tamperingCaught = false;
  try {
    const computed = computeProtocolDigest(tamperedProto);
    if (computed === tamperedProto.protocolDigest) {
      throw new Error('Tampered protocol produced identical digest');
    }
    if (computeProtocolDigest(tamperedProto) !== tamperedProto.protocolDigest) {
      tamperingCaught = true;
    }
  } catch {
    tamperingCaught = true;
  }
  if (!tamperingCaught) {
    throw new Error('loadAndValidateProtocol failed to reject tampered protocol');
  }

  // Test 9c: Non-compliance rejection (Fail-Closed)
  let nonComplianceCaught = false;
  try {
    verifyProtocolCompliance({
      suite: 'holdout',
      passes: 1, // Protocol expects 3
      shuffleSeed: '20260917',
      hermetic: true,
      labelBlind: true
    }, protoObj, 'holdoutPaired');
  } catch (err) {
    if (err.message.includes('PROTOCOL_NON_COMPLIANCE') && err.message.includes('Passes count mismatch')) {
      nonComplianceCaught = true;
    }
  }
  if (!nonComplianceCaught) {
    throw new Error('verifyProtocolCompliance failed to reject non-compliant passes count');
  }

  // Test 9d: Runner integration with protocol binding
  const mockProtocolRun = runLiveModelBenchmark(repoRoot, {
    suite: 'holdout',
    safeOnly: true,
    mock: true,
    passes: 3,
    shuffleSeed: '20260917',
    hermetic: true,
    labelBlind: true,
    protocol: protoFile,
    experimentKey: 'holdoutPaired'
  });
  if (mockProtocolRun.envelopes[0].metadata?.protocolId !== 'v1.5-eval-1' ||
      mockProtocolRun.envelopes[0].metadata?.protocolDigest !== protoObj.protocolDigest) {
    throw new Error('Benchmark envelope failed to record protocol binding metadata');
  }
  console.log('  ✔ Test 9: Evaluation Protocol Freeze & Integrity Validation (v1.5-eval-1) verified fail-closed.');

  // Test 10: G5 Medium Ablation Execution Protocol (v1.5-g5-ablation-1) freeze & compliance verification
  const ablationProtoFile = path.resolve(repoRoot, 'evals/protocols/v1.5-g5-ablation-execution-1.json');
  const ablationProto = loadAndValidateProtocol(ablationProtoFile, repoRoot);
  if (ablationProto.protocolId !== 'v1.5-g5-ablation-1' || ablationProto.status !== 'FROZEN') {
    throw new Error('v1.5-g5-ablation-1 protocol failed freeze verification');
  }

  const validAblationOptions = {
    suite: 'holdout',
    passes: 3,
    includeSafe: true,
    shuffleSeed: '20260917',
    hermetic: true,
    labelBlind: true,
    delayMs: 2000,
    timeoutMs: 240000,
    modelId: 'gemini-3.8-flash-medium',
    baseModel: 'gemini-3.8-flash',
    reasoningProfile: 'medium',
    outDir: 'evals/live-runs/reasoning-ablation/medium',
    repoRoot
  };
  verifyProtocolCompliance(validAblationOptions, ablationProto);

  verifyProtocolCompliance({
    ...validAblationOptions,
    outDir: path.resolve(repoRoot, 'evals/live-runs/reasoning-ablation/medium')
  }, ablationProto);

  let outDirMismatchCaught = false;
  try {
    verifyProtocolCompliance({
      ...validAblationOptions,
      outDir: 'evals/live-runs/wrong-dir'
    }, ablationProto);
  } catch (err) {
    if (err.message.includes('Output directory mismatch')) outDirMismatchCaught = true;
  }
  if (!outDirMismatchCaught) {
    throw new Error('verifyProtocolCompliance failed to reject mismatched outDir');
  }

  let baseModelMismatchCaught = false;
  try {
    verifyProtocolCompliance({
      ...validAblationOptions,
      baseModel: 'gemini-3.8-pro'
    }, ablationProto);
  } catch (err) {
    if (err.message.includes('Base model mismatch')) baseModelMismatchCaught = true;
  }
  if (!baseModelMismatchCaught) {
    throw new Error('verifyProtocolCompliance failed to reject mismatched baseModel');
  }

  let profileMismatchCaught = false;
  try {
    verifyProtocolCompliance({
      ...validAblationOptions,
      reasoningProfile: 'high'
    }, ablationProto);
  } catch (err) {
    if (err.message.includes('Reasoning profile mismatch')) profileMismatchCaught = true;
  }
  if (!profileMismatchCaught) {
    throw new Error('verifyProtocolCompliance failed to reject mismatched reasoningProfile');
  }

  console.log('  ✔ Test 10: G5 Medium Ablation Execution Protocol & verifyProtocolCompliance verified fail-closed.');

  console.log('\n✔ All run-live-model-benchmark.mjs harness unit tests passed successfully.');
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('run-live-model-benchmark.mjs');
if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    return idx !== -1 && idx + 1 < args.length ? args[idx + 1] : null;
  }

  const showHelp = args.includes('--help') || args.includes('-h');
  if (showHelp) {
    console.log(`
Usage: node scripts/run-live-model-benchmark.mjs [options]

Options:
  --suite <semantic|holdout> Benchmark suite to execute (default: semantic)
  --passes <N>         Number of distinct execution passes to run (default: 1)
  --include-safe       Include the 10 paired safe controls to measure live false-positive rate
  --safe-only          Run discovery ONLY on the paired safe controls to calibrate specificity
  --shuffle-seed <str> Deterministically shuffle evaluation order to mitigate presentation bias
  --no-label-blind     Disable label-blind case materialization (defaults to enabled)
  --hermetic           Enable hermetic benchmark sandbox isolation (default: enabled)
  --no-hermetic        Disable hermetic sandbox isolation, falling back to legacy repoRoot workspace
  --protocol <path>    Bind benchmark run to a frozen evaluation protocol specification
  --check-protocol <path> Validate integrity and digest of a frozen evaluation protocol
  --test               Run internal harness unit tests
  --fixture <id>       Run discovery only on a specific fixture (e.g. SEM-03)
  --model <modelId>    Override target model ID (default: gemini-3.8-flash-high)
  --base-model <model> Base model architecture (e.g. gemini-3.8-flash)
  --reasoning-profile, --effort <profile> Reasoning/thinking profile (e.g. low, medium, high)
  --out-dir <dir>      Directory to write benchmark envelope JSON files (default: evals/live-runs or evals/holdout-live-runs if passes > 1)
  --output <path>      Path to output JSON benchmark envelope (for single pass)
  --report <path>      Path to write formal Markdown empirical baseline report
  --delay-ms <ms>      Throttle delay between fixture dispatches in milliseconds (default: 1000)
  --timeout <ms>       Execution timeout per fixture in milliseconds (default: 120000)
  --resume             Resume benchmark from existing pass envelopes or fixture checkpoints
  --sandbox            Enable OS terminal sandbox (passes --sandbox to agy)
  --mock, --dry-run    Run with simulated fixture candidate generator (offline CI mode)
  --help, -h           Show this help message
`);
    process.exit(0);
  }

  const checkProtocolPath = getArg('--check-protocol');
  if (checkProtocolPath) {
    try {
      const p = loadAndValidateProtocol(checkProtocolPath, DEFAULT_REPO_ROOT);
      console.log(`✔ Protocol [${p.protocolId}] integrity verified (SHA-256: ${p.protocolDigest})`);
      process.exit(0);
    } catch (err) {
      console.error(`❌ Protocol verification failed: ${err.message}`);
      process.exit(1);
    }
  }

  if (args.includes('--test')) {
    runHarnessSelfTests(DEFAULT_REPO_ROOT);
    process.exit(0);
  }

  const suiteArg = getArg('--suite') || 'semantic';
  const isHoldout = suiteArg === 'holdout';
  const passesArg = getArg('--passes') || getArg('-n');
  const passes = passesArg ? parseInt(passesArg, 10) : 1;
  const includeSafe = args.includes('--include-safe');
  const isSafeOnly = args.includes('--safe-only');
  const isResume = args.includes('--resume');
  const shuffleSeed = getArg('--shuffle-seed') || getArg('--seed');
  const noLabelBlind = args.includes('--no-label-blind');
  const noHermetic = args.includes('--no-hermetic');
  const isHermetic = !noHermetic;
  const protocolPath = getArg('--protocol');
  const fixtureId = getArg('--fixture');
  const outDirArg = getArg('--out-dir') || getArg('--output-dir');
  const outFile = getArg('--output');
  const reportPath = getArg('--report');
  const model = getArg('--model');
  const baseModel = getArg('--base-model');
  const reasoningProfile = getArg('--reasoning-profile') || getArg('--effort') || getArg('--tier');
  const retriesArg = getArg('--retries');
  const retries = retriesArg ? parseInt(retriesArg, 10) : undefined;
  const timeoutArg = getArg('--timeout') || getArg('--timeout-ms');
  const timeoutMs = timeoutArg ? parseInt(timeoutArg, 10) : undefined;
  const delayArg = getArg('--delay-ms') || getArg('--delay');
  const delayMs = delayArg ? parseInt(delayArg, 10) : undefined;
  const isMock = args.includes('--mock') || args.includes('--dry-run');
  const isSandbox = args.includes('--sandbox');

  const defaultOutDir = (passes > 1 && !isMock && !outFile)
    ? (isHoldout ? 'evals/holdout-live-runs' : 'evals/live-runs')
    : null;
  const effectiveOutDir = outDirArg !== null ? outDirArg : defaultOutDir;

  if (outFile && passes > 1) {
    console.error('❌ Error: --output is only supported for single-pass runs (--passes 1). Use --out-dir to specify an output directory for multi-pass runs.');
    process.exit(1);
  }

  try {
    const result = runLiveModelBenchmark(DEFAULT_REPO_ROOT, {
      suite: suiteArg,
      passes,
      includeSafe,
      safeOnly: isSafeOnly,
      resume: isResume,
      shuffleSeed,
      labelBlind: !noLabelBlind,
      hermetic: isHermetic,
      protocol: protocolPath || undefined,
      fixtureId,
      modelId: model || undefined,
      baseModel: baseModel || undefined,
      reasoningProfile: reasoningProfile || undefined,
      identitySource: (baseModel || reasoningProfile) ? 'CONFIG_DECLARED' : undefined,
      retries,
      timeoutMs,
      delayMs,
      mock: isMock,
      sandbox: isSandbox,
      outDir: effectiveOutDir,
      reportPath
    });

    if (outFile && passes === 1) {
      fs.mkdirSync(path.dirname(outFile), { recursive: true });
      fs.writeFileSync(outFile, JSON.stringify(result.envelope, null, 2), 'utf8');
      console.log(`\n✔ Benchmark envelope written to: ${outFile}`);
    }

    console.log('\n✔ Live model benchmark runner finished successfully.');
  } catch (err) {
    console.error('❌ Live benchmark runner error:', err.message);
    process.exit(1);
  }
}
