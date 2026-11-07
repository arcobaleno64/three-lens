#!/usr/bin/env node
/**
 * scripts/validate-v2-corpus.mjs
 * Milestone 5.4 Phase 2 (RFC 0005 Workstream 2):
 * Authoritative Validator for V2.0 Layer 2 External Validity Corpus.
 *
 * Enforces all normative requirements from:
 * - evals/protocols/v2.0-three-layer-evaluation-framework.md
 * - evals/protocols/v2.0-acceptance-criteria.json
 *
 * Requirements verified:
 * 1. Total Case Bounds: 12 <= totalCases <= 16
 * 2. Vulnerable Case Bounds: 6 <= vulnerableCases <= 8
 * 3. Fixed Counterpart Bounds: 3 <= fixedCounterparts <= 4
 * 4. Clean Control Bounds: 3 <= cleanControls <= 4
 * 5. Minimum 7 distinct CWE vulnerability families
 * 6. Physical verification: targetFile exists on disk and is non-empty
 * 7. Immutable Ground Truth Bundle: commitSha, upstreamRepo, technicalProof, humanOracle
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

export function validateV2Corpus(corpusPath = path.join(REPO_ROOT, 'evals/v2-corpus/layer2-external-validity-corpus.json')) {
  const criteriaPath = path.join(REPO_ROOT, 'evals/protocols/v2.0-acceptance-criteria.json');

  if (!fs.existsSync(criteriaPath)) {
    throw new Error(`Missing acceptance criteria file: ${criteriaPath}`);
  }
  if (!fs.existsSync(corpusPath)) {
    throw new Error(`Missing Layer 2 corpus file: ${corpusPath}`);
  }

  const criteria = JSON.parse(fs.readFileSync(criteriaPath, 'utf8'));
  const corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));

  const l2Criteria = criteria.sampleSizeRequirements.layer2;
  const errors = [];
  const warnings = [];

  const cases = corpus.cases || [];
  const total = cases.length;

  // R03-B07 & R04-B06: Validate frozenAt timestamp consistency against git commit time
  if (corpus.frozenAt) {
    const frozenTime = new Date(corpus.frozenAt).getTime();
    if (isNaN(frozenTime) || frozenTime > Date.now()) {
      errors.push(`frozenAt timestamp '${corpus.frozenAt}' is invalid or from the future`);
    } else {
      const representativeCommit = cases[0]?.commitSha;
      if (representativeCommit) {
        try {
          const commitDateStr = execFileSync('git', ['log', '-1', '--format=%cI', representativeCommit], {
            cwd: REPO_ROOT,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'pipe']
          }).trim();
          if (commitDateStr) {
            const commitTime = new Date(commitDateStr).getTime();
            if (!isNaN(commitTime) && frozenTime < commitTime - 120000) {
              errors.push(`frozenAt (${corpus.frozenAt}) predates commitSha date (${commitDateStr})`);
            }
          }
        } catch {}
      }
    }
  } else {
    errors.push('Missing required frozenAt timestamp in corpus');
  }

  if (total < l2Criteria.minTotalCases || total > l2Criteria.maxTotalCases) {
    errors.push(`Total cases count (${total}) outside allowed range [${l2Criteria.minTotalCases}, ${l2Criteria.maxTotalCases}]`);
  }

  const vulnerable = cases.filter(c => c.role === 'VULNERABLE');
  const fixed = cases.filter(c => c.role === 'FIXED_COUNTERPART');
  const clean = cases.filter(c => c.role === 'CLEAN_CONTROL');

  if (vulnerable.length < l2Criteria.minVulnerableCases || vulnerable.length > l2Criteria.maxVulnerableCases) {
    errors.push(`Vulnerable cases count (${vulnerable.length}) outside allowed range [${l2Criteria.minVulnerableCases}, ${l2Criteria.maxVulnerableCases}]`);
  }

  if (fixed.length < l2Criteria.minFixedCounterparts || fixed.length > l2Criteria.maxFixedCounterparts) {
    errors.push(`Fixed counterparts count (${fixed.length}) outside allowed range [${l2Criteria.minFixedCounterparts}, ${l2Criteria.maxFixedCounterparts}]`);
  }

  if (clean.length < l2Criteria.minCleanControls || clean.length > l2Criteria.maxCleanControls) {
    errors.push(`Clean controls count (${clean.length}) outside allowed range [${l2Criteria.minCleanControls}, ${l2Criteria.maxCleanControls}]`);
  }

  const families = new Set(cases.map(c => c.family));
  if (families.size < l2Criteria.minVulnerabilityFamilies) {
    errors.push(`Distinct vulnerability families (${families.size}) < required (${l2Criteria.minVulnerabilityFamilies})`);
  }

  const requiredFields = [
    'caseId',
    'provenanceType',
    'family',
    'role',
    'cwe',
    'title',
    'upstreamRepo',
    'commitSha',
    'targetFile',
    'targetSink',
    'expectedDisposition',
    'expectedSeverity',
    'technicalProof',
    'humanOracle'
  ];

  const seenIds = new Set();
  const validProvenanceTypes = new Set(['SYNTHETIC_REGRESSION', 'SYNTHETIC_CLEAN_CONTROL', 'UPSTREAM_VERIFIED_OSS']);

  for (let i = 0; i < cases.length; i++) {
    const c = cases[i];
    const prefix = `Case #${i + 1} [${c.caseId || 'UNKNOWN'}]`;

    if (seenIds.has(c.caseId)) {
      errors.push(`${prefix}: Duplicate caseId '${c.caseId}'`);
    }
    seenIds.add(c.caseId);

    for (const f of requiredFields) {
      if (c[f] === undefined || c[f] === null || c[f] === '') {
        errors.push(`${prefix}: Missing required field '${f}'`);
      }
    }

    if (c.provenanceType && !validProvenanceTypes.has(c.provenanceType)) {
      errors.push(`${prefix}: Invalid provenanceType '${c.provenanceType}'`);
    }

    if (c.commitSha && !/^[0-9a-f]{40}$/i.test(c.commitSha)) {
      errors.push(`${prefix}: commitSha must be a 40-character git commit hash, found '${c.commitSha}'`);
    }

    if (c.provenanceType === 'SYNTHETIC_CLEAN_CONTROL' && c.role !== 'CLEAN_CONTROL') {
      errors.push(`${prefix}: SYNTHETIC_CLEAN_CONTROL must have role CLEAN_CONTROL`);
    }

    if (c.provenanceType === 'SYNTHETIC_REGRESSION' && !['VULNERABLE', 'FIXED_COUNTERPART'].includes(c.role)) {
      errors.push(`${prefix}: SYNTHETIC_REGRESSION must have role VULNERABLE or FIXED_COUNTERPART`);
    }

    if (!['VULNERABLE', 'FIXED_COUNTERPART', 'CLEAN_CONTROL'].includes(c.role)) {
      errors.push(`${prefix}: Invalid role '${c.role}'`);
    }

    if (c.role === 'VULNERABLE' && c.expectedDisposition !== 'REPORTABLE') {
      errors.push(`${prefix}: Vulnerable role must have expectedDisposition 'REPORTABLE', found '${c.expectedDisposition}'`);
    }

    if ((c.role === 'FIXED_COUNTERPART' || c.role === 'CLEAN_CONTROL') && c.expectedDisposition !== 'SUPPRESSED') {
      errors.push(`${prefix}: Non-vulnerable role must have expectedDisposition 'SUPPRESSED', found '${c.expectedDisposition}'`);
    }

    // Physical verification (R04-B06: Disk existence + Git commit tree existence)
    if (c.targetFile) {
      const diskPath = path.resolve(REPO_ROOT, c.targetFile);
      if (!fs.existsSync(diskPath)) {
        errors.push(`${prefix}: Target file missing on disk: ${c.targetFile}`);
      } else {
        const stats = fs.statSync(diskPath);
        if (stats.size === 0) {
          errors.push(`${prefix}: Target file is empty: ${c.targetFile}`);
        }
      }

      if (c.blobSha256) {
        const fileContent = fs.readFileSync(diskPath);
        const actualSha = crypto.createHash('sha256').update(fileContent).digest('hex');
        if (actualSha !== c.blobSha256) {
          errors.push(`${prefix}: Target file SHA-256 '${actualSha}' does not match declared blobSha256 '${c.blobSha256}' (Round 07 F-05)`);
        }
      }

      if (c.commitSha) {
        try {
          const gitBlob = execFileSync('git', ['cat-file', '-p', `${c.commitSha}:${c.targetFile}`], {
            cwd: REPO_ROOT,
            stdio: ['ignore', 'pipe', 'pipe']
          });
          if (c.blobSha256) {
            const gitSha = crypto.createHash('sha256').update(gitBlob).digest('hex');
            if (gitSha !== c.blobSha256) {
              errors.push(`${prefix}: Target file in git commit '${c.commitSha}' has SHA-256 '${gitSha}', which diverges from declared blobSha256 '${c.blobSha256}' (Round 07 F-05)`);
            }
          }
        } catch {
          errors.push(`${prefix}: Target file '${c.targetFile}' does not exist in git commit object '${c.commitSha}' (R04-B06)`);
        }
      }
    }

    if (c.humanOracle) {
      if (!c.humanOracle.status || !c.humanOracle.adjudicatedBy || !c.humanOracle.rationale) {
        errors.push(`${prefix}: Incomplete humanOracle block`);
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    summary: {
      totalCases: total,
      vulnerable: vulnerable.length,
      fixed: fixed.length,
      clean: clean.length,
      familiesCount: families.size,
      families: Array.from(families)
    }
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  console.log('Validating V2.0 Layer 2 External Validity Corpus against Acceptance Criteria...');
  try {
    const result = validateV2Corpus();
    if (!result.valid) {
      console.error('❌ Validation FAILED with errors:');
      for (const err of result.errors) {
        console.error(`  - ${err}`);
      }
      process.exit(1);
    }

    console.log('✔ V2.0 Layer 2 External Validity Corpus PASSED:');
    console.log(`  - Total Cases: ${result.summary.totalCases} (Target: 12-16)`);
    console.log(`  - Vulnerable Cases: ${result.summary.vulnerable} (Target: 6-8)`);
    console.log(`  - Fixed Counterparts: ${result.summary.fixed} (Target: 3-4)`);
    console.log(`  - Clean Negative Controls: ${result.summary.clean} (Target: 3-4)`);
    console.log(`  - Vulnerability Families: ${result.summary.familiesCount} (Target: >= 7)`);
    console.log('  - Physical File Integrity: 100% Verified on Disk');
    process.exit(0);
  } catch (err) {
    console.error(`Validation execution error: ${err.message}`);
    process.exit(1);
  }
}
