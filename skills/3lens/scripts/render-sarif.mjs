#!/usr/bin/env node
/**
 * render-sarif.mjs
 * Generates SARIF 2.1.0 and Markdown reports for the AGY Security Audit Skill.
 * Implements objective Evidence Sufficiency calculation, CVSS v4.0 verification,
 * Git provenance hashing, and double-blind swarm consensus summaries.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import os from 'node:os';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getHardenedGitProvenance, readGitFileAtRevision, resolveGitCommitRef } from './safe-git.mjs';
import { buildDirectoryManifest, extractChangedFiles, buildScanManifest, categorizeDirectory, classifyFile } from './build-inventory.mjs';
import { buildThreatModel, generateDiscoveryMatrix, detectRepositoryInventory } from './build-threat-model.mjs';

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
} from './finalize-scan.mjs';

import { validateAttackPath, detectProofGaps } from './validate-attack-path.mjs';
import { validatePatchSyntax, detectStalePatch, verifyRemediation } from './validate-patch.mjs';
import { evaluateDiscovery, generateSimulatedCandidates, runDiscoveryEval } from './run-discovery-eval.mjs';
import { evaluateStability, computeJaccardSimilarity, generateSimulatedRuns, evaluateCorpusStability, runStabilityEval } from './run-stability-eval.mjs';
import { runSemanticEval, runHoldoutEval } from './run-semantic-eval.mjs';
import { isRealPathContained, safeReadFileContained, assertContainedPath } from './path-containment.mjs';
import { createBenchmarkRunEnvelope, validateBenchmarkRunEnvelope, probeEnvironment, validateCandidateSet, parseStreamJsonTrace, validatePermissionsProfile, AGY_COMMAND_EXECUTION_POLICIES, parseAgentFrontmatter, validateAgentContract, validateAllAgentContracts } from './record-benchmark-run.mjs';




export {
  CVSS_V4_REGEX,
  normalizeUri,
  calculateRigor,
  validateDirectoryManifest,
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
  renderSarifFromCanonical,
  renderMarkdownFromCanonical,
  buildDirectoryManifest,
  extractChangedFiles,
  buildScanManifest
};

/**
 * Escapes characters that could trigger markdown/HTML injection in reports.
 * Maintained for backward compatibility; delegates to sanitizeInlineText.
 */
export function escapeMarkdown(str) {
  return sanitizeInlineText(str);
}

/**
 * Extracts Git VCS Provenance using safe hardened environment.
 */
export function getGitProvenance(repoRoot) {
  return getHardenedGitProvenance(repoRoot);
}



/**
 * Builds standard SARIF 2.1.0 document.
 * Centralized through finalizeScan to enforce default-deny and canonical contract.
 */
export function renderSarif({ findings = [], manifest = null, provenance = null, repoRoot = process.cwd(), votes = [], auditIntent = 'DISCOVERY', nonce = null, scanRunId = null }) {
  const finalization = finalizeScan({
    candidates: findings,
    manifest,
    repoRoot,
    provenance,
    votes,
    auditIntent,
    nonce,
    scanRunId
  });
  return renderSarifFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus,
    provenance: finalization.provenance,
    repoRoot,
    auditIntent: finalization.auditIntent
  });
}

/**
 * Builds Human-Readable Markdown Audit Report with strict entity escaping and default-deny.
 * Centralized through finalizeScan to guarantee 100% parity with SARIF and JSON.
 */
export function renderMarkdown({ findings = [], manifest = null, provenance = null, repoRoot = process.cwd(), votes = [], auditIntent = 'DISCOVERY', nonce = null, scanRunId = null }) {
  const finalization = finalizeScan({
    candidates: findings,
    manifest,
    repoRoot,
    provenance,
    votes,
    auditIntent,
    nonce,
    scanRunId
  });
  return renderMarkdownFromCanonical({
    canonicalFindings: finalization.canonicalFindings,
    manifest: finalization.manifest,
    coverageStatus: finalization.coverageStatus,
    provenance: finalization.provenance,
    repoRoot,
    auditIntent: finalization.auditIntent
  });
}



// -----------------------------------------------------------------------------
// CLI Dispatch & Automated Test Runner Delegation
// -----------------------------------------------------------------------------
if (process.argv.includes('--test')) {
  try {
    const __dirname = path.dirname(fileURLToPath(import.meta.url));
    const testScriptPath = path.resolve(__dirname, '../../../tests/test-render-sarif.mjs');
    execFileSync(process.execPath, [testScriptPath], { stdio: 'inherit' });
    process.exit(0);
  } catch (err) {
    process.exit(err.status ?? 1);
  }
}

// If invoked with parameters:
const args = process.argv.slice(2);
function getArg(name) {
  const idx = args.indexOf(name);
  if (idx !== -1 && idx + 1 < args.length) {
    return args[idx + 1];
  }
  return null;
}

const canonicalPath = getArg('--canonical');
const inputPath = getArg('--input') || getArg('--candidates');
const votesPath = getArg('--votes');
const manifestPath = getArg('--manifest');
const repoRootArg = getArg('--repo-root') || process.cwd();
const intentArg = getArg('--intent') || getArg('--audit-intent') || 'DISCOVERY';
const nonceArg = getArg('--nonce') || getArg('--task-correlation-nonce');
const scanRunIdArg = getArg('--scan-run-id') || getArg('--run-id');
const outputSarifPath = getArg('--output-sarif');
const outputMdPath = getArg('--output-md');

if (canonicalPath || inputPath) {
  try {
    const repoRoot = path.resolve(repoRootArg);
    const provenance = getHardenedGitProvenance(repoRoot);

    let manifest = null;
    if (manifestPath && fs.existsSync(manifestPath)) {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    }

    let canonicalFindings = [];
    let coverageStatus = 'COMPLETE';
    let activeIntent = intentArg;

    if (canonicalPath) {
      // Production Canonical Pipeline: renderer formats pre-finalized canonical findings with invariant validation
      const rawCanonical = fs.readFileSync(canonicalPath, 'utf8');
      const parsedCanonical = JSON.parse(rawCanonical);
      canonicalFindings = validateCanonicalFindings(parsedCanonical, repoRoot);
      const covRes = reconcileCoverage(manifest, repoRoot);
      coverageStatus = covRes.status;
    } else {
      // Legacy input pipeline: routes strictly through finalizeScan with votes
      const rawCandidates = fs.readFileSync(inputPath, 'utf8');
      const candidates = JSON.parse(rawCandidates);
      const votes = loadVotes(votesPath);

      if (candidates.length > 0 && votes.length === 0) {
        console.warn('[DEFAULT-DENY] Direct render without --votes. Under Default-Deny, all findings are derived as DEFERRED.');
      }

      const finalization = finalizeScan({
        candidates,
        manifest,
        repoRoot,
        votes,
        auditIntent: intentArg,
        nonce: nonceArg || null,
        scanRunId: scanRunIdArg || null
      });
      canonicalFindings = finalization.canonicalFindings;
      coverageStatus = finalization.coverageStatus;
      activeIntent = finalization.auditIntent;
    }

    if (outputSarifPath) {
      const sarif = renderSarifFromCanonical({
        canonicalFindings,
        manifest,
        coverageStatus,
        provenance,
        repoRoot,
        auditIntent: activeIntent
      });
      fs.mkdirSync(path.dirname(outputSarifPath), { recursive: true });
      fs.writeFileSync(outputSarifPath, JSON.stringify(sarif, null, 2), 'utf8');
      console.log(`✔ Generated SARIF report: ${outputSarifPath}`);
    }

    if (outputMdPath) {
      const md = renderMarkdownFromCanonical({
        canonicalFindings,
        manifest,
        coverageStatus,
        provenance,
        repoRoot,
        auditIntent: activeIntent
      });
      fs.mkdirSync(path.dirname(outputMdPath), { recursive: true });
      fs.writeFileSync(outputMdPath, md, 'utf8');
      console.log(`✔ Generated Markdown report: ${outputMdPath}`);
    }
  } catch (err) {
    console.error('Error processing audit reports:', err.message);
    process.exit(1);
  }
}

