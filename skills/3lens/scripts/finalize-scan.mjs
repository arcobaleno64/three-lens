#!/usr/bin/env node
/**
 * finalize-scan.mjs
 * Deterministic Security Authority for the AGY Security Audit Skill.
 * Enforces canonical scan contracts, default-deny disposition derivation,
 * confidence clamping, secret redaction, output sanitization,
 * and coverage reconciliation.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { getHardenedGitProvenance, runSafeGit } from './safe-git.mjs';
import { validateAttackPath, detectProofGaps } from './validate-attack-path.mjs';
import { buildDirectoryManifest, extractChangedFiles, categorizeDirectory, classifyFile } from './build-inventory.mjs';
import { resolveStandardsMapping, detectDependencyBoundary } from './standards-mapping.mjs';
export { categorizeDirectory, classifyFile, resolveStandardsMapping, detectDependencyBoundary };
import { prepareReviewContext, getPreparedContextFilePath, readPreparedFile } from './prepare-review-context.mjs';
export { prepareReviewContext, getPreparedContextFilePath, readPreparedFile };
import { isPathContained, isRealPathContained, assertContainedPath, safeReadFileContained } from './path-containment.mjs';
export { isPathContained, isRealPathContained, assertContainedPath, safeReadFileContained };

// Single source of truth for the tool release version stamped into attestations,
// baselines, and the TCB manifest. `scripts/bump-version.mjs` rewrites this line
// (and package.json, and tool-integrity-manifest.json) together so a release
// cannot bump one without the others going stale.
export const TOOL_VERSION = '1.13.0';
import {
  loadProjectSecurityContext,
  detectContextDrift,
  computeProjectContextFingerprint,
  computeSecurityPropertiesFingerprint,
  initProjectContext,
  loadBaselineContext,
  persistBaselineContext
} from './project-context.mjs';
import { validateThreatModel } from './build-threat-model.mjs';
import {
  validateCompactedStateEnvelope,
  extractCompactedAuditHeader,
  assertCompactSafe,
  serializeCompactedAuditHeader
} from './compact-guard.mjs';
export {
  loadProjectSecurityContext,
  detectContextDrift,
  computeProjectContextFingerprint,
  computeSecurityPropertiesFingerprint,
  initProjectContext,
  loadBaselineContext,
  persistBaselineContext,
  validateThreatModel,
  validateCompactedStateEnvelope,
  extractCompactedAuditHeader,
  assertCompactSafe,
  serializeCompactedAuditHeader
};



export const CVSS_V4_REGEX = /^CVSS:4\.0\/AV:[NALP]\/AC:[LH]\/AT:[NP]\/PR:[NLH]\/UI:[NPA]\/VC:[HLN]\/VI:[HLN]\/VA:[HLN]\/SC:[HLN]\/SI:[HLN]\/SA:[HLN]$/;


// Common secret patterns for deterministic redaction
export const SECRET_PATTERNS = [
  { type: 'AWS_ACCESS_KEY', regex: /(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/g },
  { type: 'GITHUB_TOKEN', regex: /(?:ghp_[a-zA-Z0-9]{36,40}|github_pat_[a-zA-Z0-9_]{82}|gh[orpus]_[a-zA-Z0-9]{36,40})/g },
  { type: 'BEARER_TOKEN', regex: /bearer\s+[a-zA-Z0-9_\-\.:=_\+\/]{20,}/gi },
  { type: 'PRIVATE_KEY', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'GENERIC_SECRET_KV', regex: /(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret[_-]?key|password|passwd|pwd)\s*[:=]\s*["']?([a-zA-Z0-9_\-\.\+=/]{16,})["']?/gi },
  { type: 'JWT_TOKEN', regex: /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/g }
];

/**
 * Strips ANSI escapes, C0/C1 non-printable controls, and Bidi override characters.
 */
export function stripControlAndBidi(str) {
  if (!str) return '';
  return String(str)
    .replace(/\x1B(?:\[[0-?]*[ -/]*[@-~]|[@-Z\\-_])/g, '') // ANSI escape sequences
    .replace(/[\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '') // Bidi overrides
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, ''); // C0 and C1 controls (preserving \t and \n)
}

/**
 * Escapes standard HTML entities.
 */
export function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Sanitizes inline markdown text (anti-HTML + anti-link breakout + strip controls).
 */
export function sanitizeInlineText(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  return escapeHtml(cleaned)
    .replace(/!\[/g, '&#33;&#91;')
    .replace(/\[/g, '&#91;')
    .replace(/\]/g, '&#93;')
    .replace(/\(/g, '&#40;')
    .replace(/\)/g, '&#41;');
}

/**
 * Sanitizes text destined for Markdown table cells (escapes pipes and converts newlines).
 */
export function sanitizeTableCell(str) {
  if (!str) return '';
  return sanitizeInlineText(str)
    .replace(/\|/g, '&#124;')
    .replace(/\r?\n/g, ' ');
}

/**
 * Sanitizes block Markdown text (escapes heading injection and code fence breakout).
 */
export function sanitizeBlockText(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  const escaped = escapeHtml(cleaned)
    .replace(/^(\s*)(#+)/gm, '$1\\$2') // Escape markdown headings
    .replace(/```/g, '\\`\\`\\`'); // Escape code fence breakouts
  return escaped;
}

/**
 * Sanitizes code snippets (escapes code fence breakouts).
 */
export function sanitizeCodeSnippet(str) {
  if (!str) return '';
  const cleaned = stripControlAndBidi(str);
  return cleaned.replace(/```/g, '\\`\\`\\`');
}

/**
 * Deterministically redacts secrets from arbitrary text, returning sanitized text.
 */
export function redactSecrets(text) {
  if (!text) return '';
  let result = String(text);
  for (const { type, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    result = result.replace(regex, (match) => {
      const hash = crypto.createHash('sha256').update(match).digest('hex').substring(0, 8);
      return `[REDACTED_${type}; len=${match.length}; fp=${hash}]`;
    });
  }
  // Also normalize any pre-context tokens in final output text
  result = result.replace(/<SECRET:class=([A-Z0-9_]+):hash=([a-f0-9]+)>/g, '[REDACTED_$1; fp=$2]');
  return result;
}

/**
 * Pre-context secret tokenization (R4-P1-01).
 * Replaces plaintext secrets in source code with structured, length-preserving or line-preserving
 * tokens before passing to LLM inspection contexts, while recording a local resolver map.
 */
export function tokenizeSecretsForContext(sourceText, options = {}) {
  if (!sourceText || typeof sourceText !== 'string') {
    return { tokenizedText: '', secretCount: 0, secretsMap: new Map(), metadata: [] };
  }

  const secretsMap = new Map();
  const metadata = [];
  let tokenizedText = sourceText;

  for (const { type, regex } of SECRET_PATTERNS) {
    regex.lastIndex = 0;
    tokenizedText = tokenizedText.replace(regex, (match, p1) => {
      const targetSecret = (typeof p1 === 'string') ? p1 : String(match);
      const hash = crypto.createHash('sha256').update(targetSecret, 'utf8').digest('hex').substring(0, 12);
      const tokenPlaceholder = `<SECRET:class=${type}:hash=${hash}>`;

      // Preserve newlines if targetSecret spans multiple lines (e.g. PEM private keys)
      const newlineCount = (targetSecret.match(/\r?\n/g) || []).length;
      const paddingNewlines = '\n'.repeat(newlineCount);
      const replacement = tokenPlaceholder + paddingNewlines;

      secretsMap.set(tokenPlaceholder, {
        type,
        hash,
        originalLength: targetSecret.length,
        originalSecret: targetSecret
      });
      metadata.push({
        type,
        hash,
        token: tokenPlaceholder,
        newlineCount
      });

      return replacement;
    });
  }

  return {
    tokenizedText,
    secretCount: metadata.length,
    secretsMap,
    metadata
  };
}

/**
 * Resolves tokenized secrets back to original values in authorized local context (R4-P1-01).
 */
export function detokenizeSecrets(tokenizedText, secretsMap) {
  if (!tokenizedText || !secretsMap || !(secretsMap instanceof Map)) {
    return tokenizedText || '';
  }
  let restored = String(tokenizedText);
  for (const [token, info] of secretsMap.entries()) {
    restored = restored.replaceAll(token, info.originalSecret);
  }
  return restored;
}

/**
 * Authoritative Finding Types (R2-P0-11)
 * Separates genuine security vulnerabilities from proactive hardening and informational notes.
 */
export const VALID_FINDING_TYPES = new Set(['VULNERABILITY', 'HARDENING', 'INFORMATIONAL']);

export function validateFindingType(rawType, fallbackRuleId = '', fallbackTitle = '') {
  if (typeof rawType === 'string' && VALID_FINDING_TYPES.has(rawType.toUpperCase().trim())) {
    return { valid: true, findingType: rawType.toUpperCase().trim() };
  }
  // Derive fallback findingType based on weakness characteristics
  const combined = `${fallbackRuleId} ${fallbackTitle}`.toLowerCase();
  if (/\b(?:hardening|defense-in-depth|rate[_-]?limit|strict[_-]?csp|best[_-]?practice|misuse[_-]?resistance)\b/i.test(combined) &&
      !/\b(?:injection|bypass|flaw|vulnerab|exploit)\b/i.test(combined)) {
    return { valid: true, findingType: 'HARDENING' };
  }
  if (/\b(?:info|informational|verbose|debug|disclosure-low|note)\b/i.test(combined) &&
      !/\b(?:information\s+disclosure|cwe-200|credential\s+disclosure|secret\s+disclosure)\b/i.test(combined)) {
    return { valid: true, findingType: 'INFORMATIONAL' };
  }
  return { valid: true, findingType: 'VULNERABILITY' };
}

/**
 * Authoritative Safe Proof Policy (R2-P0-12)
 * Categorizes evidence verification mechanisms while strictly prohibiting live exploits,
 * credential reuse, persistence, or destructive commands.
 */
export const VALID_PROOF_KINDS = new Set([
  'STATIC_TRACE',
  'UNIT_TEST',
  'BENIGN_REPRODUCTION',
  'CONFIG_EVIDENCE',
  'DEPENDENCY_EVIDENCE',
  'EXTERNAL_SCANNER_EVIDENCE',
  'MANUAL_ATTESTATION'
]);

export const PROHIBITED_PROOF_PATTERNS = [
  /(?:rm\s+-(?:r[fF]|f[rR]|r\s+-f|f\s+-r)\s+[/~*]|format\s+[a-z]:|dd\s+if=|mkfs|shutdown\s+-[hr]|drop\s+database|rd\s+\/s\s+\/q|del\s+\/s\s+\/q|Remove-Item\s+.*-Recurse)/i,
  /(?:curl|wget|fetch)\s+https?:\/\/(?:evil|attacker|exfil|burpcollaborator|oast)/i,
  /(?:nc|ncat)\s+(?:evil|attacker|exfil|burpcollaborator|oast|[0-9a-z.-]+\s+[0-9]{2,5})/i,
  /(?:live[_-]?exploit|credential[_-]?reuse|uncontrolled[_-]?probe)/i
];

export function validateSafeProof(proof, proofKind = 'STATIC_TRACE') {
  const rawKind = typeof proofKind === 'string' ? proofKind.toUpperCase().trim() : 'STATIC_TRACE';
  const safeKind = VALID_PROOF_KINDS.has(rawKind) ? rawKind : 'STATIC_TRACE';

  const proofStr = typeof proof === 'string' ? proof : JSON.stringify(proof || '');
  for (const pattern of PROHIBITED_PROOF_PATTERNS) {
    if (pattern.test(proofStr)) {
      return {
        valid: false,
        safe: false,
        proofKind: safeKind,
        error: 'PROHIBITED_PROOF_VIOLATION: Proof violates defensive safety policy (live exploit, destructive command, or unauthorized probing detected).'
      };
    }
  }

  return { valid: true, safe: true, proofKind: safeKind };
}

/**
 * Failure Taxonomy Reason Codes (R2-P1-10)
 * Replaces generic DEFERRED with granular, actionable causal failure classifications.
 */
export const FAILURE_REASON_CODES = new Set([
  'EVIDENCE_INCOMPLETE',
  'COVERAGE_PARTIAL',
  'VERIFIER_TIMEOUT',
  'ORCHESTRATION_INCOMPLETE',
  'STALE_EVIDENCE',
  'SEVERITY_UNRATED',
  'MODEL_DISAGREEMENT',
  'PROHIBITED_PROOF',
  'UNVERIFIED_CLAIM',
  'AFFIRMATIVELY_VERIFIED',
  'AFFIRMATIVELY_REFUTED',
  'RISK_ACCEPTED'
]);

export function deriveReasonCode(disposition, reason = '', proofSafe = true, coverageStatus = 'COMPLETE') {
  if (disposition === 'REPORTABLE') return 'AFFIRMATIVELY_VERIFIED';
  if (disposition === 'SUPPRESSED') return 'AFFIRMATIVELY_REFUTED';
  if (disposition === 'ACCEPTED_RISK') return 'RISK_ACCEPTED';
  if (!proofSafe || /PROHIBITED_PROOF/i.test(reason)) return 'PROHIBITED_PROOF';
  if (/stale|diverg/i.test(reason)) return 'STALE_EVIDENCE';
  if (/self-assert|fabricated|unvoted|unsupported reportable/i.test(reason)) return 'UNVERIFIED_CLAIM';
  if (/disagree|split/i.test(reason)) return 'MODEL_DISAGREEMENT';
  if (/timeout/i.test(reason)) return 'VERIFIER_TIMEOUT';
  if (/orchestrat|skipped stage/i.test(reason)) return 'ORCHESTRATION_INCOMPLETE';
  if (/unrated|missing severity/i.test(reason)) return 'SEVERITY_UNRATED';
  if (/coverage/i.test(reason) || coverageStatus !== 'COMPLETE') return 'COVERAGE_PARTIAL';
  return 'EVIDENCE_INCOMPLETE';
}

/**
 * Validates formal Risk Acceptance / Waiver records (R4-P2-01).
 */
export function validateRiskAcceptance(waiver, candidateLineageId = '', candidateId = '') {
  if (!waiver || typeof waiver !== 'object') {
    return { valid: false, reason: 'Risk acceptance record is null or not an object.' };
  }
  const { findingLineageId, reason, acceptedBy, expiresAt, compensatingControls } = waiver;
  const matchLineage = Boolean(candidateLineageId && findingLineageId === candidateLineageId);
  const matchId = Boolean(candidateId && findingLineageId === candidateId);
  if (!findingLineageId || ((candidateLineageId || candidateId) && !matchLineage && !matchId)) {
    return { valid: false, reason: 'Risk acceptance findingLineageId missing or does not match target finding.' };
  }
  if (!reason || typeof reason !== 'string' || reason.trim().length === 0) {
    return { valid: false, reason: 'Risk acceptance requires explicit justification reason.' };
  }
  if (!acceptedBy || typeof acceptedBy !== 'string' || acceptedBy.trim().length === 0) {
    return { valid: false, reason: 'Risk acceptance requires explicit acceptedBy authorizer.' };
  }
  if (!expiresAt || isNaN(Date.parse(expiresAt))) {
    return { valid: false, reason: 'Risk acceptance requires valid expiresAt ISO date string.' };
  }
  if (new Date(expiresAt).getTime() <= Date.now()) {
    return { valid: false, reason: `Risk acceptance expired on ${expiresAt}.` };
  }
  if (!compensatingControls || typeof compensatingControls !== 'string' || compensatingControls.trim().length === 0) {
    return { valid: false, reason: 'Risk acceptance requires documented compensatingControls.' };
  }
  return { valid: true, waiver };
}

/**
 * Computes a deterministic evidence snapshot / hash for a file location (R2-P1-04).
 */
export function computeEvidenceSnapshot(repoRoot, relativePath, line = 1) {
  if (!repoRoot || !relativePath) {
    return { blobHash: null, lineHash: null, exists: false };
  }
  const rootResolved = path.resolve(repoRoot);
  const resolved = path.resolve(repoRoot, relativePath);
  if (!isPathContained(rootResolved, resolved)) {
    return { blobHash: null, lineHash: null, exists: false, error: 'Path traversal outside repository root' };
  }
  const readResult = safeReadFileContained(rootResolved, resolved, { allowSymlinks: false });
  if (!readResult.ok) {
    if (readResult.error && readResult.error.includes('symbolic link')) {
      return { blobHash: null, lineHash: null, exists: false, error: 'Evidence path is a symlink; symlinks are not followed for evidence snapshots' };
    }
    if (readResult.error && (readResult.error.includes('escapes') || readResult.error.includes('realpath'))) {
      return { blobHash: null, lineHash: null, exists: false, error: 'Resolved evidence path escapes repository root' };
    }
    return { blobHash: null, lineHash: null, exists: false };
  }

  try {
    const content = readResult.content;
    const blobHash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    const lines = content.split(/\r?\n/);
    const lineNum = Number(line);
    if (lineNum < 1 || lineNum > lines.length) {
      return { blobHash, lineHash: null, lineContent: null, exists: true, error: 'Line beyond EOF' };
    }
    const lineContent = lines[lineNum - 1] || '';
    const lineHash = crypto.createHash('sha256').update(lineContent.trim(), 'utf8').digest('hex');
    return {
      blobHash,
      lineHash,
      lineContent,
      exists: true
    };
  } catch {
    return { blobHash: null, lineHash: null, exists: false };
  }
}

/**
 * Checks whether evidence is stale by comparing current snapshot to recorded snapshot (R2-P1-04).
 */
export function isEvidenceStale(currentSnapshot, recordedSnapshot) {
  if (!currentSnapshot || !recordedSnapshot) return false;
  if (!currentSnapshot.exists && recordedSnapshot.exists) return true;
  if (currentSnapshot.error && !recordedSnapshot.error) return true;
  if (recordedSnapshot.lineHash && currentSnapshot.lineHash && recordedSnapshot.lineHash !== currentSnapshot.lineHash) {
    return true;
  }
  if (recordedSnapshot.blobHash && currentSnapshot.blobHash && recordedSnapshot.blobHash !== currentSnapshot.blobHash) {
    return true;
  }
  return false;
}

/**
 * Declares or infers the explicit security property violated (R2-P1-02).
 */
export function inferSecurityProperty(ruleId = '', title = '', explicitProperty = '') {
  if (typeof explicitProperty === 'string' && explicitProperty.trim().length > 0) {
    return explicitProperty.trim();
  }
  const std = resolveStandardsMapping(ruleId);
  if (std && std.securityProperty && std.securityProperty !== 'SECURITY_PROPERTY_UNSPECIFIED') {
    return std.securityProperty;
  }
  const combined = `${ruleId} ${title}`.toLowerCase();
  if (/auth|access|tenant|idor|ownership/i.test(combined)) return 'AUTHORIZATION_CONFINEMENT';
  if (/command|exec|spawn|process|subshell/i.test(combined)) return 'PROCESS_EXECUTION_INTEGRITY';
  if (/sqli|sql|injection|query/i.test(combined)) return 'INPUT_INTEGRITY_QUERY_CONFINEMENT';
  if (/traversal|path|file/i.test(combined)) return 'FILESYSTEM_CONTAINMENT';
  if (/ssrf|webhook|egress/i.test(combined)) return 'NETWORK_EGRESS_CONFINEMENT';
  if (/secret|token|password|credential/i.test(combined)) return 'SECRET_CONFIDENTIALITY';
  if (/xss|script/i.test(combined)) return 'CLIENT_CONTEXT_ISOLATION';
  if (/deserializ|eval|unpickle/i.test(combined)) return 'OBJECT_INSTANTIATION_INTEGRITY';
  return 'SECURITY_PROPERTY_UNSPECIFIED';
}

/**
 * Infers root cause and preventive action for verified findings (NIST SSDF RV.3 / SAMM Defect Management) (R2-P2-06).
 */
export function inferDefectManagement(ruleId = '', title = '', securityProperty = '', taxonomy = {}) {
  const combined = `${ruleId} ${title} ${securityProperty}`.toLowerCase();

  let rootCause = 'INSUFFICIENT_CONTROL_DEFENSE';
  let preventiveAction = 'Establish automated architectural validation and defensive assertions.';

  if (/auth|access|tenant|idor|ownership/i.test(combined)) {
    rootCause = 'BROKEN_AUTHORIZATION_BARRIER';
    preventiveAction = 'Enforce affirmative, policy-based authorization barriers at every service and handler boundary.';
  } else if (/command|exec|spawn|process|subshell/i.test(combined)) {
    rootCause = 'UNSAFE_PROCESS_EXECUTION';
    preventiveAction = 'Eliminate shell interpolation; invoke process execution APIs using strict argument vectors.';
  } else if (/sqli|sql|injection|query/i.test(combined)) {
    rootCause = 'UNCONFINED_DYNAMIC_QUERY_CONSTRUCTION';
    preventiveAction = 'Mandate parameterized queries or prepared statements; ban dynamic string concatenation in query builders.';
  } else if (/traversal|path|file/i.test(combined)) {
    rootCause = 'UNCONFINED_PATH_RESOLUTION';
    preventiveAction = 'Canonicalize target file paths using realpath and assert containment within authorized root boundary.';
  } else if (/ssrf|webhook|egress/i.test(combined)) {
    rootCause = 'UNRESTRICTED_NETWORK_EGRESS';
    preventiveAction = 'Restrict outbound HTTP/network requests via strict URL whitelisting and private IP range filtering.';
  } else if (/secret|token|password|credential/i.test(combined)) {
    rootCause = 'HARDCODED_AUTHENTICATION_CREDENTIAL';
    preventiveAction = 'Extract credentials into a cryptographically secured secrets manager and introduce pre-commit scanning.';
  } else if (/xss|script/i.test(combined)) {
    rootCause = 'UNSANITIZED_CLIENT_OUTPUT';
    preventiveAction = 'Apply context-aware output encoding or template engines with automatic HTML escaping enabled.';
  } else if (/deserializ|eval|unpickle/i.test(combined)) {
    rootCause = 'UNTRUSTED_OBJECT_INSTANTIATION';
    preventiveAction = 'Replace dynamic serialization mechanisms with schema-validated, type-safe data formats.';
  }

  const missingControl = (taxonomy && Array.isArray(taxonomy.ssdf) && taxonomy.ssdf.length > 0)
    ? `NIST-SSDF-${taxonomy.ssdf[0]}`
    : ((taxonomy && Array.isArray(taxonomy.asvs) && taxonomy.asvs.length > 0) ? `OWASP-ASVS-${taxonomy.asvs[0]}` : 'NIST-SSDF-PW.7.1');

  return {
    rootCause,
    missingControl,
    affectedPattern: title || ruleId,
    preventiveAction
  };
}

/**
 * Computes the canonical Execution Equivalence Key (R4-P1-03 / R5-P1-02).
 * Uses deterministic length-prefixed encoding to eliminate delimiter ambiguity.
 */
export function computeExecutionEquivalenceKey({
  targetRevision = 'HEAD',
  scopeFingerprint = '',
  surfaceFingerprint = '',
  threatModelFingerprint = '',
  coverageFingerprint = '',
  policyVersion = '1.0.0',
  promptContractVersion = '1.0.0',
  toolVersion = '1.0.0',
  modelProvider = 'deterministic-local',
  modelIdentifier = 'unspecified'
} = {}) {
  const parts = [
    targetRevision || 'HEAD',
    scopeFingerprint || '',
    surfaceFingerprint || '',
    threatModelFingerprint || '',
    coverageFingerprint || '',
    policyVersion || '1.0.0',
    promptContractVersion || '1.0.0',
    toolVersion || '1.0.0',
    modelProvider || 'deterministic-local',
    modelIdentifier || 'unspecified'
  ];
  const payload = parts.map(p => `${Buffer.byteLength(String(p), 'utf8')}:${String(p)}`).join(';');
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

/**
 * Producer Provenance (v1.1.0 P0)
 * Resolves tool release version, repository commit SHA, TCB integrity digest, and dirty state.
 */
export function getToolProvenance(toolRoot = null) {
  const defaultToolRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const resolvedTool = path.resolve(toolRoot || defaultToolRoot);

  // 1. Git provenance of the tool repository
  const gitProv = getHardenedGitProvenance(resolvedTool);
  const isRealSha = Boolean(gitProv?.revisionId
    && /^[0-9a-f]{40}$/i.test(gitProv.revisionId)
    && gitProv.revisionId !== '0000000000000000000000000000000000000000');
  const toolRevision = isRealSha ? gitProv.revisionId : 'UNCHECKED_REVISION';
  const toolBranch = (gitProv?.branch && gitProv.branch !== 'unknown') ? gitProv.branch : 'unknown';
  const toolDirty = Boolean(gitProv?.properties?.isDirty);

  // 2. Authoritative TCB manifest digest
  const manifestPath = path.resolve(resolvedTool, 'tool-integrity-manifest.json');
  let toolIntegrityDigest = null;
  if (fs.existsSync(manifestPath)) {
    try {
      const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      if (manifest && typeof manifest.manifestDigest === 'string') {
        toolIntegrityDigest = manifest.manifestDigest;
      }
    } catch {
      toolIntegrityDigest = null;
    }
  }

  return {
    toolName: '@arcobaleno64/agy-security-audit',
    toolVersion: TOOL_VERSION,
    toolRevision,
    toolBranch,
    toolDirty,
    toolIntegrityDigest
  };
}

/**
 * Builds an audit baseline artifact for tracking finding lineage and regression convergence (R2-P2-05 / R4-P1-03).
 */
export function buildAuditBaseline({
  repoRoot = process.cwd(),
  targetRevision = 'HEAD',
  canonicalFindings = [],
  threatModel = null,
  manifest = null,
  provenance = null,
  policyVersion = '1.0.0',
  promptContractVersion = '1.0.0',
  modelProvider = 'deterministic-local',
  modelIdentifier = 'unspecified',
  modelSnapshotImmutable = false,
  toolRevision = null,
  toolIntegrityDigest = null,
  toolProvenance = null
} = {}) {
  const effectiveToolProv = toolProvenance || getToolProvenance();
  const effectiveToolRev = toolRevision || effectiveToolProv.toolRevision;
  const effectiveDigest = toolIntegrityDigest !== undefined && toolIntegrityDigest !== null
    ? toolIntegrityDigest
    : effectiveToolProv.toolIntegrityDigest;
  const safeRepoRoot = path.resolve(repoRoot);
  const rev = targetRevision || provenance?.commitSha || 'HEAD';

  // 1. Scope fingerprint: deterministic hash of all scanned relative paths
  let scannedFiles = [];
  if (manifest) {
    if (Array.isArray(manifest.entries)) {
      scannedFiles = manifest.entries
        .filter(e => !e.status || e.status.startsWith('SCANNED') || e.isScanned !== false)
        .map(e => e.path || e.uri)
        .filter(Boolean);
    } else if (Array.isArray(manifest.files)) {
      scannedFiles = manifest.files
        .filter(f => f.isScanned !== false)
        .map(f => f.path || f.uri)
        .filter(Boolean);
    } else if (Array.isArray(manifest.changedFiles)) {
      scannedFiles = manifest.changedFiles
        .map(f => f.path || f.uri)
        .filter(Boolean);
    }
  }
  scannedFiles.sort();
  const scopeHash = crypto.createHash('sha256').update(scannedFiles.join('\n'), 'utf8').digest('hex');

  // 2. Surface fingerprint: entrypoints, frameworks, and manifests
  const frameworks = (threatModel && Array.isArray(threatModel.frameworks)) ? threatModel.frameworks.slice().sort() : [];
  const entrypoints = (threatModel && Array.isArray(threatModel.entrypoints)) ? threatModel.entrypoints.map(e => e.path || e).sort() : [];
  const surfaceHash = crypto.createHash('sha256').update([...frameworks, ...entrypoints].join('\n'), 'utf8').digest('hex');

  // 3. Threat model fingerprint: components & boundaries
  const components = (threatModel && Array.isArray(threatModel.components)) ? threatModel.components.map(c => c.name || c).sort() : [];
  const boundaries = (threatModel && Array.isArray(threatModel.trustBoundaries)) ? threatModel.trustBoundaries.map(b => b.boundary || b.name || b).filter(Boolean).sort() : [];
  const tmHash = crypto.createHash('sha256').update([...components, ...boundaries].join('\n'), 'utf8').digest('hex');

  // 4. Coverage fingerprint: directories & exclusion reasons
  let dirs = [];
  if (manifest) {
    if (Array.isArray(manifest.entries)) {
      dirs = manifest.entries.map(e => `${e.path}:${e.status}`).filter(Boolean);
    } else if (Array.isArray(manifest.directories)) {
      dirs = manifest.directories.map(d => `${d.path}:${d.status}`).filter(Boolean);
    }
  }
  dirs.sort();
  const covHash = crypto.createHash('sha256').update(dirs.join('\n'), 'utf8').digest('hex');

  // 5. Finding lineage IDs
  const safeFindings = Array.isArray(canonicalFindings) ? canonicalFindings : [];
  const findingLineageIds = safeFindings
    .map(f => f.lineageId || f.id)
    .filter(Boolean)
    .sort();

  // 6. Execution Equivalence Key (R4-P1-03)
  const executionEquivalenceKey = computeExecutionEquivalenceKey({
    targetRevision: rev,
    scopeFingerprint: scopeHash,
    surfaceFingerprint: surfaceHash,
    threatModelFingerprint: tmHash,
    coverageFingerprint: covHash,
    policyVersion,
    promptContractVersion,
    toolVersion: TOOL_VERSION,
    modelProvider,
    modelIdentifier
  });
  const executionEquivalence = modelSnapshotImmutable ? 'FULL' : 'PARTIAL';

  // R9-P1-04 & R9-P2-02: Project Context Fingerprints & Ignored Artifacts Tracking
  const projectContextRes = loadProjectSecurityContext(repoRoot);
  const projectContextFingerprint = projectContextRes?.projectContextFingerprint || null;
  const securityPropertiesFingerprint = projectContextRes?.securityPropertiesFingerprint || null;

  const ignoredCandidates = ['codeql-db', '.semgrep', 'reports', 'scratch', 'coverage', '.nyc_output'];
  const ignoredArtifactsPresent = ignoredCandidates.filter(dir => fs.existsSync(path.resolve(repoRoot, dir)));

  const provenanceTracking = {
    trackedDirty: Boolean(provenance?.properties?.isDirty),
    untrackedDirty: Boolean(provenance?.properties?.hasUntrackedChanges || false),
    ignoredArtifactsPresent
  };

  return {
    schemaVersion: '1.0.0',
    toolVersion: TOOL_VERSION,
    toolRevision: effectiveToolRev,
    toolIntegrityDigest: effectiveDigest,
    targetRevision: rev,
    modelProvider,
    modelIdentifier,
    scopeFingerprint: scopeHash,
    surfaceFingerprint: surfaceHash,
    threatModelFingerprint: tmHash,
    coverageFingerprint: covHash,
    projectContextFingerprint,
    securityPropertiesFingerprint,
    provenanceTracking,
    executionEquivalenceKey,
    executionEquivalence,
    findingLineageIds,
    canonicalFindingsSummary: {
      total: safeFindings.length,
      reportable: safeFindings.filter(f => f.disposition === 'REPORTABLE').length,
      deferred: safeFindings.filter(f => f.disposition === 'DEFERRED').length,
      suppressed: safeFindings.filter(f => f.disposition === 'SUPPRESSED').length
    },
    completedAt: new Date().toISOString()
  };
}

/**
 * Calculates evidence sufficiency completeness score in [0.0, 1.0].
 * Internal heuristic for evidence completeness gating; not formal mathematical proof or CVSS (R2-P0-07).
 */
export function calculateEvidenceSufficiency(metrics = {}) {
  const sSink = metrics.sinkVerified ? 1.0 : 0.0;
  const sSource = metrics.sourceVerified ? 1.0 : 0.0;
  const flowTotal = Number(metrics.dataflowTotalSteps) || 0;
  const flowVerified = Number(metrics.dataflowVerifiedSteps) || 0;
  const flowRatio = flowTotal > 0 ? Math.min(1.0, Math.max(0.0, flowVerified / flowTotal)) : 0.0;
  const sPoc = metrics.pocSyntacticDemonstrated ? 1.0 : 0.0;
  const sMitigation = metrics.mitigationInspected ? 1.0 : 0.0;

  const score = Number((0.25 * sSink + 0.25 * sSource + 0.25 * flowRatio + 0.15 * sPoc + 0.10 * sMitigation).toFixed(4));

  let sufficiencyLevel = 'LOW';
  let assuranceLevel = 'LOW_RIGOR';
  if (score >= 0.85) {
    sufficiencyLevel = 'HIGH';
    assuranceLevel = 'HIGH_RIGOR';
  } else if (score >= 0.60) {
    sufficiencyLevel = 'MODERATE';
    assuranceLevel = 'MODERATE_RIGOR';
  }

  return {
    score,
    sufficiencyLevel,
    assuranceLevel,
    sourceVerified: Boolean(metrics.sourceVerified),
    sinkVerified: Boolean(metrics.sinkVerified),
    flowVerified: flowRatio >= 1.0,
    defensesInspected: Boolean(metrics.mitigationInspected),
    impactVerified: Boolean(metrics.pocSyntacticDemonstrated),
    proofGaps: Number(metrics.proofGapsCount || 0),
    disclaimer: 'Internal heuristic for evidence completeness gating; not formal mathematical proof or CVSS.'
  };
}

/**
 * Backward-compatible alias for calculateEvidenceSufficiency.
 */
export function calculateRigor(metrics = {}) {
  return calculateEvidenceSufficiency(metrics);
}

/**
 * Normalizes a directory path for deterministic reconciliation.
 */
export function normalizeDirectoryPath(p) {
  if (!p || typeof p !== 'string') return '';
  let clean = p.replace(/\\/g, '/').trim();
  if (clean === '.' || clean === './' || clean === '/') return './';
  clean = clean.replace(/^\.\//, '').replace(/^\/+/, '');
  if (!clean.endsWith('/')) {
    clean += '/';
  }
  return clean;
}

/**
 * Normalizes a repo-relative file path.
 */
export function normalizeFilePath(p) {
  if (!p || typeof p !== 'string') return '';
  return p.replace(/\\/g, '/').replace(/^\.\//, '').replace(/^\/+/, '').trim();
}

/**
 * Normalizes legacy directory exclusion statuses to current explicit categories (R3-P1-02).
 */
export function normalizeDirectoryStatus(rawStatus) {
  if (rawStatus === 'EXCLUDED_GENERATED') return 'EXCLUDED_GENERATED_VERIFIED';
  if (rawStatus === 'EXCLUDED_NON_CODE') return 'EXCLUDED_STATIC_ASSET';
  if (rawStatus === 'EXCLUDED_TEST') return 'SCANNED_TEST_EXECUTABLE';
  return rawStatus;
}

/**
 * Validates Directory Reconciliation Manifest (P0 Hardening & R2-P0-10 & R3-P1-02).
 */
export function validateDirectoryManifest(manifest, repoRoot = null, options = {}) {
  if (repoRoot && typeof repoRoot === 'object' && !Array.isArray(repoRoot)) {
    options = repoRoot;
    repoRoot = options.repoRoot || null;
  }
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, status: 'UNCHECKABLE', error: 'Directory manifest is null or not an object.' };
  }

  // Unwrap directoryManifest if nested
  const rawEntries = Array.isArray(manifest.entries)
    ? manifest.entries
    : (manifest.directoryManifest && Array.isArray(manifest.directoryManifest.entries) ? manifest.directoryManifest.entries : null);

  if (!rawEntries) {
    return { valid: false, status: 'UNCHECKABLE', error: 'Manifest must contain an "entries" array.' };
  }
  if (rawEntries.length === 0) {
    return { valid: false, status: 'PARTIAL', error: 'UNACCOUNTED_DIRECTORY_ERROR: Directory manifest cannot be empty.' };
  }

  const validStatuses = new Set([
    'SCANNED',
    'SCANNED_RUNTIME',
    'SCANNED_BUILD',
    'SCANNED_CI',
    'SCANNED_AGENT_CONTEXT',
    'SCANNED_TEST_EXECUTABLE',
    'EXCLUDED_VENDORED',
    'EXCLUDED_GENERATED_VERIFIED',
    'EXCLUDED_STATIC_ASSET',
    'EXCLUDED_ANALYSIS_ARTIFACT'
  ]);

  const claimedMap = new Map();
  const duplicates = [];

  for (const entry of rawEntries) {
    if (!entry || !entry.path) {
      return { valid: false, status: 'PARTIAL', error: 'Directory entry missing "path" property.' };
    }
    // Migration normalization for legacy exclusion statuses (R3-P1-02)
    entry.status = normalizeDirectoryStatus(entry.status);

    const norm = normalizeDirectoryPath(entry.path);
    if (claimedMap.has(norm)) {
      duplicates.push(norm);
    }
    claimedMap.set(norm, entry);

    if (!validStatuses.has(entry.status)) {
      return {
        valid: false,
        status: 'PARTIAL',
        error: `UNACCOUNTED_DIRECTORY_ERROR: Directory "${entry.path}" has invalid or unaccounted status "${entry.status}".`
      };
    }
    if (entry.status.startsWith('EXCLUDED_') && (!entry.reason || entry.reason.trim().length === 0)) {
      return {
        valid: false,
        status: 'PARTIAL',
        error: `UNACCOUNTED_DIRECTORY_ERROR: Excluded directory "${entry.path}" lacks explicit audit reason.`
      };
    }
  }

  if (duplicates.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      duplicates,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Duplicate directory entries found: [${duplicates.join(', ')}]`
    };
  }

  // If repoRoot is omitted or null, syntax is valid but coverage cannot be verified
  if (!repoRoot || typeof repoRoot !== 'string' || !fs.existsSync(path.resolve(repoRoot))) {
    return {
      valid: true,
      status: 'UNCHECKABLE',
      missing: [],
      unexpected: [],
      error: 'UNCHECKABLE: Authoritative repoRoot is required to reconcile filesystem coverage.'
    };
  }

  // Authoritative Filesystem Reconciliation (P0-02)
  let actualManifest;
  try {
    actualManifest = buildDirectoryManifest(repoRoot);
  } catch (e) {
    return {
      valid: false,
      status: 'UNCHECKABLE',
      error: `FS_RECONCILIATION_ERROR: Failed to inspect filesystem at ${repoRoot}: ${e.message}`
    };
  }

  const actualMap = new Map();
  for (const actualEntry of actualManifest.entries) {
    actualMap.set(normalizeDirectoryPath(actualEntry.path), actualEntry);
  }

  const missing = [];
  for (const actualPath of actualMap.keys()) {
    if (!claimedMap.has(actualPath)) {
      missing.push(actualPath);
    }
  }

  const unexpected = [];
  for (const claimedPath of claimedMap.keys()) {
    if (!actualMap.has(claimedPath)) {
      unexpected.push(claimedPath);
    }
  }

  // Check for False Exclusion / Categorization Fabrication
  const statusMismatches = [];
  let hasScannedCodeDirectory = false;

  for (const [actualPath, actualEntry] of actualMap.entries()) {
    const claimedEntry = claimedMap.get(actualPath);
    if (claimedEntry) {
      const actualIsScanned = typeof actualEntry.status === 'string' && actualEntry.status.startsWith('SCANNED');
      const claimedIsScanned = typeof claimedEntry.status === 'string' && claimedEntry.status.startsWith('SCANNED');
      if (actualIsScanned) {
        if (!claimedIsScanned) {
          statusMismatches.push({ path: actualPath, expected: actualEntry.status, claimed: claimedEntry.status });
        } else {
          hasScannedCodeDirectory = true;
        }
      }
    }
  }

  if (statusMismatches.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      statusMismatches,
      missing,
      unexpected,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Source code directory falsely excluded: [${statusMismatches.map(m => `${m.path} claimed ${m.claimed}`).join(', ')}]`
    };
  }

  if (!hasScannedCodeDirectory) {
    return {
      valid: false,
      status: 'PARTIAL',
      error: 'UNACCOUNTED_DIRECTORY_ERROR: Complete scan must include at least one SCANNED source code directory.'
    };
  }

  if (missing.length > 0 || unexpected.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      missing,
      unexpected,
      error: `UNACCOUNTED_DIRECTORY_ERROR: Directory reconciliation mismatch. Missing: [${missing.join(', ')}]; Unexpected: [${unexpected.join(', ')}]`
    };
  }

  return { valid: true, status: 'COMPLETE', missing: [], unexpected: [] };
}

/**
 * Validates Review Manifest according to Review mode standards
 * and performs authoritative reconciliation against actual Git diff when repoRoot is supplied.
 */
export function validateReviewManifest(manifest, repoRoot = null) {
  if (!manifest || typeof manifest !== 'object') {
    return { valid: false, status: 'UNCHECKABLE', error: 'Review manifest must be a valid object.' };
  }
  const inventory = manifest.reviewInventory || manifest;
  const changed = Array.isArray(inventory.changedFiles) ? inventory.changedFiles : null;
  const deleted = Array.isArray(inventory.deletedFiles) ? inventory.deletedFiles : null;

  if (!changed && !deleted) {
    return { valid: false, status: 'PARTIAL', error: 'Review manifest must contain changedFiles or deletedFiles array.' };
  }

  const claimedChangedList = changed || [];
  const claimedDeletedList = deleted || [];

  for (const f of claimedChangedList) {
    if (!f || !f.path) return { valid: false, status: 'PARTIAL', error: 'Changed file entry missing path property.' };
  }
  for (const f of claimedDeletedList) {
    if (!f || !f.path) return { valid: false, status: 'PARTIAL', error: 'Deleted file entry missing path property.' };
  }

  // If repoRoot is omitted or null, syntax is valid but coverage cannot be verified
  if (!repoRoot || typeof repoRoot !== 'string' || !fs.existsSync(path.resolve(repoRoot))) {
    return {
      valid: true,
      status: 'UNCHECKABLE',
      totalAccounted: claimedChangedList.length + claimedDeletedList.length,
      error: 'UNCHECKABLE: Authoritative repoRoot is required to reconcile git review coverage.'
    };
  }

  // Authoritative Git Diff Reconciliation (P0-02)
  const baseRev = manifest.base || inventory.base || manifest.baselineRevision || inventory.baselineRevision || null;
  const headRev = manifest.head || inventory.head || manifest.targetRevision || inventory.targetRevision || null;

  if (baseRev && headRev && baseRev === headRev) {
    return {
      valid: false,
      status: 'PARTIAL',
      error: `REVIEW_RECONCILIATION_ERROR: Identical revisions specified (${baseRev}...${headRev}) which trivially suppresses review diff.`
    };
  }

  let actualChanged = [];
  let actualDeleted = [];
  try {
    const actualDiff = extractChangedFiles(repoRoot, { base: baseRev, head: headRev });
    actualChanged = actualDiff.changedFiles.map(f => normalizeFilePath(f.path));
    actualDeleted = actualDiff.deletedFiles.map(f => normalizeFilePath(f.path));
  } catch (e) {
    return {
      valid: false,
      status: 'UNCHECKABLE',
      error: `GIT_ACCOUNTING_ERROR: ${e.message}`
    };
  }

  const claimedChanged = claimedChangedList.map(f => normalizeFilePath(f.path));
  const claimedDeleted = claimedDeletedList.map(f => normalizeFilePath(f.path));

  const missingChanged = actualChanged.filter(f => !claimedChanged.includes(f));
  const missingDeleted = actualDeleted.filter(f => !claimedDeleted.includes(f));
  const unexpectedChanged = claimedChanged.filter(f => !actualChanged.includes(f));
  const unexpectedDeleted = claimedDeleted.filter(f => !actualDeleted.includes(f));

  if (missingChanged.length > 0 || missingDeleted.length > 0 || unexpectedChanged.length > 0 || unexpectedDeleted.length > 0) {
    return {
      valid: false,
      status: 'PARTIAL',
      missingChanged,
      missingDeleted,
      unexpectedChanged,
      unexpectedDeleted,
      error: `REVIEW_RECONCILIATION_ERROR: Changed/deleted files mismatch against git diff. Missing changed: [${missingChanged.join(', ')}], Missing deleted: [${missingDeleted.join(', ')}], Unexpected changed: [${unexpectedChanged.join(', ')}], Unexpected deleted: [${unexpectedDeleted.join(', ')}]`
    };
  }

  return {
    valid: true,
    status: 'COMPLETE',
    totalAccounted: claimedChangedList.length + claimedDeletedList.length,
    missingChanged: [],
    missingDeleted: [],
    unexpectedChanged: [],
    unexpectedDeleted: []
  };
}

/**
 * Reconciles coverage across scan and review manifests against authoritative filesystem/git ground truth.
 */
export function reconcileCoverage(manifest, repoRoot = null) {
  if (!manifest) {
    return { valid: false, status: 'UNCHECKABLE', mode: 'none', error: 'No coverage manifest provided.' };
  }
  if (manifest.mode === 'review' || manifest.reviewInventory || (Array.isArray(manifest.changedFiles) && !Array.isArray(manifest.entries))) {
    const res = validateReviewManifest(manifest, repoRoot);
    return {
      valid: res.valid,
      status: res.valid ? res.status : (res.status || 'PARTIAL'),
      mode: 'review',
      error: res.error || null,
      missingChanged: res.missingChanged || [],
      missingDeleted: res.missingDeleted || [],
      unexpectedChanged: res.unexpectedChanged || [],
      unexpectedDeleted: res.unexpectedDeleted || []
    };
  }
  const res = validateDirectoryManifest(manifest, repoRoot);
  return {
    valid: res.valid,
    status: res.valid ? res.status : (res.status || 'PARTIAL'),
    mode: 'scan',
    error: res.error || null,
    missing: res.missing || [],
    unexpected: res.unexpected || [],
    duplicates: res.duplicates || []
  };
}





/**
 * Validates a Component x Vulnerability-Family Discovery Matrix Cell.
 * Enforces zero finding quota: 'REVIEWED_NO_CANDIDATE' is a legitimate successful review outcome.
 * Permitted cell statuses: 'PENDING', 'REVIEWED_NO_CANDIDATE', 'CANDIDATE', 'NOT_APPLICABLE', 'UNRESOLVED'.
 */
export function validateDiscoveryCell(cell, repoRoot = null) {
  if (!cell || typeof cell !== 'object') {
    return { valid: false, error: 'Discovery cell must be an object' };
  }
  if (!cell.component || typeof cell.component !== 'string' || cell.component.trim().length === 0) {
    return { valid: false, error: 'Discovery cell requires a non-empty string component' };
  }
  if (!cell.family || typeof cell.family !== 'string' || cell.family.trim().length === 0) {
    return { valid: false, error: 'Discovery cell requires a non-empty string vulnerability family' };
  }
  const validStatuses = [
    'PENDING',
    'PENDING_DISCOVERY',
    'REVIEWED_NO_CANDIDATE',
    'CONFIRMED_ZERO_CANDIDATE',
    'PENDING_SECOND_OPINION',
    'CANDIDATE',
    'NOT_APPLICABLE',
    'UNRESOLVED'
  ];
  if (!validStatuses.includes(cell.status)) {
    return { valid: false, error: `Invalid cell status '${cell.status}'; must be one of: ${validStatuses.join(', ')}` };
  }
  if (cell.status === 'REVIEWED_NO_CANDIDATE' || cell.status === 'CONFIRMED_ZERO_CANDIDATE') {
    if (!Array.isArray(cell.reviewedEvidence) || cell.reviewedEvidence.length === 0) {
      return { valid: false, error: `${cell.status} requires non-empty reviewedEvidence array proving inspection` };
    }
    for (const ev of cell.reviewedEvidence) {
      if (!ev || typeof ev.path !== 'string' || ev.path.trim().length === 0) {
        return { valid: false, error: 'reviewedEvidence item must contain a non-empty string path' };
      }
      if (repoRoot) {
        if (!isPathContained(repoRoot, ev.path)) {
          return { valid: false, error: `reviewedEvidence path escapes repository: ${ev.path}` };
        }
        const resolved = path.resolve(repoRoot, ev.path);
        if (!fs.existsSync(resolved)) {
          return { valid: false, error: `reviewedEvidence file does not exist: ${ev.path}` };
        }
      }
    }
  }
  return { valid: true };
}

/**
 * Validates an entire Component x Family Discovery Matrix.
 */
export function validateDiscoveryMatrix(matrix, repoRoot = null) {
  if (!Array.isArray(matrix)) {
    return { valid: false, error: 'Discovery matrix must be an array of cells' };
  }
  for (let i = 0; i < matrix.length; i++) {
    const res = validateDiscoveryCell(matrix[i], repoRoot);
    if (!res.valid) {
      return { valid: false, error: `Cell [${i}] (${matrix[i]?.component} x ${matrix[i]?.family}): ${res.error}` };
    }
  }
  return { valid: true, totalCells: matrix.length };
}


/**
 * Normalizes any OS path to an RFC 3986 compliant relative forward-slash URI.
 */
export function normalizeUri(repoRoot, filePath) {
  if (!filePath) return 'unknown';
  const rel = path.isAbsolute(filePath)
    ? path.relative(repoRoot, filePath)
    : filePath;
  const forwardSlash = rel.split(path.sep).join('/');
  return forwardSlash.split('/').map(segment => encodeURIComponent(segment)).join('/');
}

/**
 * Parses a standard CVSS v4.0 vector string into a key-value metric map.
 */
export function parseCvssV4Vector(vectorStr) {
  if (!vectorStr || typeof vectorStr !== 'string') return null;
  const parts = vectorStr.trim().split('/');
  if (parts[0] !== 'CVSS:4.0') return null;
  const metrics = {};
  for (let i = 1; i < parts.length; i++) {
    const [k, v] = parts[i].split(':');
    if (k && v) metrics[k] = v;
  }
  return metrics;
}

/**
 * Validates consistency between CVSS v4.0 vector metrics, score, and severity.
 * Fails closed on any contradiction or fabricated authority claim (R1-P1-04).
 */
export function validateCvssV4Consistency(metrics, score, severity) {
  if (!metrics) return { valid: false, error: 'Missing metrics' };

  const allImpactsNone = (
    metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' &&
    metrics.SC === 'N' && metrics.SI === 'N' && metrics.SA === 'N'
  );

  // 1. Zero-impact invariant: if all impacts are None, score must be 0.0 or null
  if (allImpactsNone) {
    if (score !== null && score !== undefined && score > 0.0) {
      return {
        valid: false,
        error: `CVSS consistency violation: zero-impact vector (all N) cannot have non-zero score (${score})`
      };
    }
    if (severity && severity !== 'NONE' && severity !== 'UNRATED') {
      return {
        valid: false,
        error: `CVSS consistency violation: zero-impact vector cannot have severity '${severity}'`
      };
    }
  }

  // 2. Score vs Severity consistency check
  if (score !== null && score !== undefined && severity && severity !== 'UNRATED') {
    let expectedSeverity = 'NONE';
    if (score >= 9.0) expectedSeverity = 'CRITICAL';
    else if (score >= 7.0) expectedSeverity = 'HIGH';
    else if (score >= 4.0) expectedSeverity = 'MEDIUM';
    else if (score > 0.0) expectedSeverity = 'LOW';

    if (severity !== expectedSeverity) {
      return {
        valid: false,
        error: `CVSS consistency violation: score ${score} maps to ${expectedSeverity}, but claimed severity is '${severity}'`
      };
    }
  }

  // 3. Physical attack vector constraint: AV:P cannot be CRITICAL (neither score >= 9.0 nor severity 'CRITICAL')
  if (metrics.AV === 'P' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: Physical attack vector (AV:P) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 4. Zero vulnerable system impact constraint: VC:N, VI:N, VA:N cannot be CRITICAL
  if (metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: zero vulnerable-system impact (VC:N/VI:N/VA:N) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 4b. Vulnerable system impact without any High metric (VC/VI/VA not H) cannot be CRITICAL
  if (metrics.VC !== 'H' && metrics.VI !== 'H' && metrics.VA !== 'H' && ((score !== null && score !== undefined && score >= 9.0) || severity === 'CRITICAL')) {
    return {
      valid: false,
      error: `CVSS consistency violation: vulnerable system without High impact (VC/VI/VA not H) cannot be CRITICAL (score=${score}, severity=${severity})`
    };
  }

  // 5. Maximal impact and exploitability cannot have score < 7.0
  if (metrics.AV === 'N' && metrics.AC === 'L' && metrics.AT === 'N' && metrics.PR === 'N' && metrics.UI === 'N' &&
      metrics.VC === 'H' && metrics.VI === 'H' && metrics.VA === 'H' &&
      score !== null && score !== undefined && score < 7.0) {
    return {
      valid: false,
      error: `CVSS consistency violation: maximal impact and exploitability cannot have score < 7.0 (${score})`
    };
  }

  return { valid: true };
}

/**
 * Validates CVSS v4 vector fail-closed. Never substitutes a fake high-severity vector or clamped invalid scores.
 * Enforces consistency between vector metrics and score/severity under Default-Deny (R1-P1-04).
 */
export function validateCvssV4(cvssObj) {
  if (!cvssObj || typeof cvssObj !== 'object') {
    return { valid: false, vector: null, score: null, severity: 'UNRATED' };
  }

  const rawVector = cvssObj.vector;
  if (!rawVector || typeof rawVector !== 'string' || !CVSS_V4_REGEX.test(rawVector.trim())) {
    return {
      valid: false,
      vector: null,
      score: null,
      severity: 'UNRATED',
      error: 'Invalid or missing CVSS v4 vector'
    };
  }

  const trimmedVector = rawVector.trim();
  const metrics = parseCvssV4Vector(trimmedVector);

  let validatedScore = null;
  if (cvssObj.score !== undefined && cvssObj.score !== null) {
    if (
      typeof cvssObj.score !== 'number' ||
      !Number.isFinite(cvssObj.score) ||
      Number.isNaN(cvssObj.score) ||
      cvssObj.score < 0.0 ||
      cvssObj.score > 10.0
    ) {
      return {
        valid: false,
        vector: null,
        score: null,
        severity: 'UNRATED',
        error: `Invalid CVSS score: ${cvssObj.score}. Must be a finite number between 0.0 and 10.0.`
      };
    }
    validatedScore = Number(cvssObj.score.toFixed(1));
  }

  let severity = 'UNRATED';
  if (cvssObj.severity && typeof cvssObj.severity === 'string') {
    severity = cvssObj.severity.toUpperCase();
  } else if (validatedScore !== null) {
    severity = validatedScore >= 9.0 ? 'CRITICAL' : validatedScore >= 7.0 ? 'HIGH' : validatedScore >= 4.0 ? 'MEDIUM' : validatedScore > 0 ? 'LOW' : 'NONE';
  } else {
    // R2-P0-06: No heuristic guesswork on severity when score is null.
    // Only zero-impact vector maps to NONE; all other unscored vectors remain UNRATED.
    const allImpactsNone = (
      metrics.VC === 'N' && metrics.VI === 'N' && metrics.VA === 'N' &&
      metrics.SC === 'N' && metrics.SI === 'N' && metrics.SA === 'N'
    );
    severity = allImpactsNone ? 'NONE' : 'UNRATED';
  }

  // R1-P1-04: Strict consistency check between vector, score, and severity
  const consistencyCheck = validateCvssV4Consistency(metrics, validatedScore, severity);
  if (!consistencyCheck.valid) {
    return {
      valid: false,
      vector: null,
      score: null,
      severity: 'UNRATED',
      error: consistencyCheck.error
    };
  }

  return {
    valid: true,
    vector: trimmedVector,
    score: validatedScore,
    severity
  };
}


/**
 * Unifies multi-run discovery candidate sets using deterministic fingerprints.
 */
export function unionCandidates(runs = [], repoRoot = process.cwd(), options = {}) {
  if (!Array.isArray(runs) || runs.length === 0) return [];
  const dedupeBy = options.dedupeBy || 'lineage'; // 'lineage' or 'location'
  const candidateMap = new Map();
  const totalRuns = runs.length;

  for (let runIdx = 0; runIdx < totalRuns; runIdx++) {
    const runCandidates = runs[runIdx] || [];
    const seenInRun = new Set();

    for (const c of runCandidates) {
      if (!c || typeof c !== 'object') continue;
      const ruleId = c.ruleId || 'SEC-VULN';
      const loc = c.location || {};
      const rawUri = loc.uri || loc.path || 'unknown';
      const normUri = normalizeUri(repoRoot, rawUri);
      const startLine = Number(loc.startLine) || 1;
      const locFp = computeFindingFingerprint(ruleId, normUri, startLine);
      const sinkSymbol = c.symbol || c.sinkSymbol || c.sink?.symbol || '';
      const sinkKind = c.sinkKind || c.sink?.kind || '';
      const authoritativeLineageId = computeLineageFingerprint({
        ruleId,
        uri: normUri,
        component: c.component || '',
        family: c.family || '',
        sinkKind,
        symbol: sinkSymbol
      });

      const dedupeKey = (dedupeBy === 'lineage' && authoritativeLineageId)
        ? `${authoritativeLineageId}${sinkSymbol ? '' : `:${startLine}`}`
        : locFp;

      if (!candidateMap.has(dedupeKey)) {
        candidateMap.set(dedupeKey, {
          ...c,
          id: c.id || `SEC-${locFp.substring(0, 8)}`,
          location: {
            ...loc,
            uri: normUri,
            startLine
          },
          fingerprint: locFp,
          locationFingerprint: locFp,
          lineageId: authoritativeLineageId,
          lineage: c.lineage || {
            lineageId: authoritativeLineageId,
            novelty: 'NEW_SURFACE',
            whyNow: null,
            predecessorId: null,
            stabilityImpact: false
          },
          recurrenceCount: 1,
          runsObserved: [runIdx + 1],
          proofGaps: Array.isArray(c.proofGaps) ? [...c.proofGaps] : []
        });
        seenInRun.add(dedupeKey);
      } else {
        const existing = candidateMap.get(dedupeKey);
        // Only increment recurrence if not duplicate within this single run
        if (!seenInRun.has(dedupeKey)) {
          existing.recurrenceCount += 1;
          existing.runsObserved.push(runIdx + 1);
          seenInRun.add(dedupeKey);
        }

        // Structurally deduplicate proof gaps across runs
        if (Array.isArray(c.proofGaps)) {
          existing.proofGaps = existing.proofGaps || [];
          const existingKeys = new Set(existing.proofGaps.map(g => `${g.stepIndex ?? g.target}:${g.unprovenProperty}:${g.location || ''}`));
          for (const g of c.proofGaps) {
            const key = `${g.stepIndex ?? g.target}:${g.unprovenProperty}:${g.location || ''}`;
            if (!existingKeys.has(key)) {
              existingKeys.add(key);
              existing.proofGaps.push(g);
            }
          }
        }

        // Merge extra attack path dataflow steps if newly discovered in this run
        if (c.attackPath && Array.isArray(c.attackPath.steps) && (!existing.attackPath || !existing.attackPath.steps || c.attackPath.steps.length > existing.attackPath.steps.length)) {
          existing.attackPath = c.attackPath;
        }
      }
    }
  }

  return Array.from(candidateMap.values());
}

/**
 * Extracts candidate evidence items from a verifier vote (P1-02).
 */
export function extractVoteEvidence(vote, candidate = {}) {
  const items = [];
  const defaultCandidatePath = candidate.location?.uri || candidate.location?.path || null;

  const parsePathLine = (val, defaultPath, defaultRole = null) => {
    if (val === null || val === undefined) return null;
    if (typeof val === 'number') {
      return { path: defaultPath, line: val, role: defaultRole };
    }
    if (typeof val === 'string') {
      const trimmed = val.trim();
      const match = trimmed.match(/^([^:]+):(\d+)$/);
      if (match) {
        return { path: match[1], line: parseInt(match[2], 10), role: defaultRole };
      }
      const lineOnly = parseInt(trimmed, 10);
      if (!isNaN(lineOnly) && lineOnly > 0 && !trimmed.includes('/') && !trimmed.includes('\\')) {
        return { path: defaultPath, line: lineOnly, role: defaultRole };
      }
      return { path: trimmed, line: null, role: defaultRole };
    }
    if (typeof val === 'object' && val !== null) {
      const p = val.path || val.uri || val.file || defaultPath;
      const l = Number(val.line || val.startLine);
      return { path: p, line: (!isNaN(l) && l > 0) ? l : null, role: val.role || defaultRole };
    }
    return null;
  };

  const voteLens = vote.lens ? String(vote.lens).toUpperCase() : null;

  if (Array.isArray(vote.evidence)) {
    for (let i = 0; i < vote.evidence.length; i++) {
      const e = vote.evidence[i];
      let defRole = null;
      if (voteLens === 'REACHABILITY') {
        if (vote.evidence.length >= 2) defRole = (i === 0) ? 'source' : 'sink';
        else defRole = 'entrypoint';
      } else if (voteLens === 'DEFENSES') {
        defRole = 'control';
      } else if (voteLens === 'IMPACT') {
        defRole = 'impact-boundary';
      }
      const parsed = parsePathLine(e, defaultCandidatePath, defRole);
      if (parsed) items.push(parsed);
    }
  } else if (vote.evidence) {
    let defRole = null;
    if (voteLens === 'REACHABILITY') defRole = 'entrypoint';
    else if (voteLens === 'DEFENSES') defRole = 'control';
    else if (voteLens === 'IMPACT') defRole = 'impact-boundary';
    const parsed = parsePathLine(vote.evidence, defaultCandidatePath, defRole);
    if (parsed) items.push(parsed);
  }

  if (vote.source) {
    const parsed = parsePathLine(vote.source, defaultCandidatePath, 'source');
    if (parsed) items.push(parsed);
  }
  if (vote.entrypoint) {
    const parsed = parsePathLine(vote.entrypoint, defaultCandidatePath, 'entrypoint');
    if (parsed) items.push(parsed);
  }
  if (vote.sink) {
    const parsed = parsePathLine(vote.sink, defaultCandidatePath, 'sink');
    if (parsed) items.push(parsed);
  }
  if (vote.mitigationProofLine) {
    const parsed = parsePathLine(vote.mitigationProofLine, defaultCandidatePath, 'guard');
    if (parsed) items.push(parsed);
  }
  if (vote.unreachableProofLine) {
    const parsed = parsePathLine(vote.unreachableProofLine, defaultCandidatePath, 'dead-path');
    if (parsed) items.push(parsed);
  }
  if (vote.containmentProofLine) {
    const parsed = parsePathLine(vote.containmentProofLine, defaultCandidatePath, 'impact-boundary');
    if (parsed) items.push(parsed);
  }
  if (vote.proofLine) {
    const parsed = parsePathLine(vote.proofLine, defaultCandidatePath, 'guard');
    if (parsed) items.push(parsed);
  }
  if (vote.path && vote.line) {
    const parsed = parsePathLine({ path: vote.path, line: vote.line }, defaultCandidatePath);
    if (parsed) items.push(parsed);
  }

  return items;
}

/**
 * Validates vote evidence fail-closed under Default-Deny (P1-02, R1-P0-01).
 * Both SUPPORTS and REFUTES decisions mandate verified evidence binding.
 */
export function validateVoteEvidence(vote, candidate = {}, repoRoot = null) {
  if (!vote || typeof vote !== 'object') {
    return { valid: false, reason: 'Malformed vote object' };
  }

  // 1. FindingId Match
  const voteFindingId = vote.findingId;
  const candidateId = candidate.id || candidate.findingId;
  if (!voteFindingId || (candidateId && voteFindingId !== candidateId)) {
    return { valid: false, reason: `Vote findingId '${voteFindingId}' does not match candidate '${candidateId}'` };
  }

  // 2. Extract Evidence
  const evidenceItems = extractVoteEvidence(vote, candidate);
  if (evidenceItems.length === 0) {
    return { valid: false, reason: 'Vote requires non-empty evidence binding' };
  }

  // 3. Validate Each Evidence Item
  for (const item of evidenceItems) {
    if (!item.path || typeof item.path !== 'string') {
      return { valid: false, reason: 'Evidence missing valid file path' };
    }
    if (!Number.isInteger(item.line) || item.line <= 0) {
      return { valid: false, reason: `Evidence line must be a positive integer, got '${item.line}'` };
    }

    const normPath = item.path.replace(/\\/g, '/').replace(/^\.\//, '');

    // Anti-traversal check
    if (normPath.startsWith('..') || normPath.includes('/../') || path.isAbsolute(item.path)) {
      return { valid: false, reason: `Evidence path escapes workspace: '${item.path}'` };
    }

    // Real filesystem verification if repoRoot is provided
    if (repoRoot) {
      const fullTarget = path.resolve(repoRoot, normPath);
      const relToRepo = path.relative(repoRoot, fullTarget);
      if (relToRepo.startsWith('..') || path.isAbsolute(relToRepo)) {
        return { valid: false, reason: `Evidence path outside repository root: '${normPath}'` };
      }
      if (!fs.existsSync(fullTarget)) {
        return { valid: false, reason: `Evidence file does not exist: '${normPath}'` };
      }
      try {
        const fileContent = fs.readFileSync(fullTarget, 'utf8');
        const lineCount = fileContent.split('\n').length;
        if (item.line > lineCount) {
          return { valid: false, reason: `Evidence line ${item.line} exceeds file length (${lineCount} lines) in '${normPath}'` };
        }
      } catch (e) {
        return { valid: false, reason: `Failed to inspect evidence file '${normPath}': ${e.message}` };
      }
    }
  }

  return { valid: true, evidence: evidenceItems };
}

/**
 * Derives authoritative evidence sufficiency completeness from validated evidence (R2-P0-07).
 * Raw candidate.rigorMetrics is strictly treated as an untrusted hint and CANNOT self-certify authority (R1-P0-01).
 */
export function deriveAuthoritativeRigor(candidate = {}, validSupportVotes = [], repoRoot = null) {
  const allEvidence = [];
  for (const v of validSupportVotes) {
    if (v && v._validatedEvidence) {
      allEvidence.push(...v._validatedEvidence);
    }
  }

  const hasSource = allEvidence.some(e => ['source', 'entrypoint', 'origin'].includes(e.role));
  const candidateUri = candidate.location?.uri || candidate.location?.path;
  const candidateLine = Number(candidate.location?.startLine);
  const hasSink = allEvidence.some(e => ['sink', 'root-control', 'target'].includes(e.role)) ||
    (candidateUri && allEvidence.some(e => e.path === candidateUri && e.line === candidateLine));
  const hasControlInspection = allEvidence.some(e => ['control', 'closest-control', 'guard', 'defense', 'inspected-control', 'mitigation'].includes(e.role));

  const sSource = hasSource ? 1.0 : 0.0;
  const sSink = hasSink ? 1.0 : 0.0;
  const sMitigation = hasControlInspection ? 1.0 : 0.0;

  // Dataflow verification
  let flowTotal = 0;
  let flowVerified = 0;
  if (candidate.attackPath && Array.isArray(candidate.attackPath.steps)) {
    flowTotal = candidate.attackPath.steps.length;
    flowVerified = (candidate.proofGaps && candidate.proofGaps.length > 0) ? 0 : flowTotal;
  } else if (hasSource && hasSink) {
    flowTotal = 1;
    flowVerified = 1;
  }
  const flowRatio = flowTotal > 0 ? Math.min(1.0, Math.max(0.0, flowVerified / flowTotal)) : 0.0;
  const sPoc = (candidate.attackPath?.proofOfConcept || candidate.pocSyntacticDemonstrated) ? 1.0 : 0.0;

  const score = Number((0.25 * sSink + 0.25 * sSource + 0.25 * flowRatio + 0.15 * sPoc + 0.10 * sMitigation).toFixed(4));

  let assuranceLevel = 'LOW_RIGOR';
  if (score >= 0.85) {
    assuranceLevel = 'HIGH_RIGOR';
  } else if (score >= 0.60) {
    assuranceLevel = 'MODERATE_RIGOR';
  }

  const sufficiencyLevel = score >= 0.85 ? 'HIGH' : score >= 0.60 ? 'MODERATE' : 'LOW';

  return {
    score,
    sufficiencyLevel,
    assuranceLevel,
    sourceVerified: hasSource,
    sinkVerified: hasSink,
    flowVerified: flowRatio >= 1.0,
    defensesInspected: hasControlInspection,
    impactVerified: sPoc === 1.0,
    proofGaps: (candidate.proofGaps && candidate.proofGaps.length) || 0,
    disclaimer: 'Internal heuristic for evidence completeness gating; not formal mathematical proof or CVSS.',
    metrics: {
      sinkVerified: hasSink,
      sourceVerified: hasSource,
      dataflowTotalSteps: flowTotal,
      dataflowVerifiedSteps: flowVerified,
      mitigationInspected: hasControlInspection
    }
  };
}

/**
 * Derives authoritative evidence sufficiency completeness from validated evidence (R2-P0-07).
 */
export function deriveAuthoritativeEvidenceSufficiency(candidate = {}, validSupportVotes = [], repoRoot = null) {
  return deriveAuthoritativeRigor(candidate, validSupportVotes, repoRoot);
}

/**
 * Validates a verifier ballot against candidate identity and task correlation nonce (R1-P1-05).
 */
export function validateBallot(vote, candidate = null, options = {}) {
  if (!vote || typeof vote !== 'object') {
    return { valid: false, reason: 'Ballot must be a non-null object' };
  }
  if (!vote.findingId || typeof vote.findingId !== 'string') {
    return { valid: false, reason: 'Ballot missing valid findingId string' };
  }
  if (candidate && candidate.id && vote.findingId !== candidate.id) {
    return { valid: false, reason: `Finding ID mismatch: ballot for '${vote.findingId}' passed to candidate '${candidate.id}'` };
  }

  // Task-correlation nonce enforcement: execution options take strict precedence over candidate self-assertions
  const expectedNonce = ('expectedNonce' in options)
    ? options.expectedNonce
    : (('nonce' in options) ? options.nonce : (candidate?.nonce || null));
  if (expectedNonce) {
    if (!vote.nonce) {
      return { valid: false, reason: `Missing required task-correlation nonce (expected '${expectedNonce}')` };
    }
    if (vote.nonce !== expectedNonce) {
      return { valid: false, reason: `Task-correlation nonce mismatch: expected '${expectedNonce}', got '${vote.nonce}'` };
    }
  }

  const validLenses = ['REACHABILITY', 'DEFENSES', 'IMPACT'];
  if (vote.lens && !validLenses.includes(String(vote.lens).toUpperCase())) {
    return { valid: false, reason: `Invalid lens '${vote.lens}'. Must be one of: ${validLenses.join(', ')}` };
  }

  // Gate 0 (M54-P1-F03): Ballots for effort-directed candidates strictly require a valid lens
  if ((candidate?.modelEffort || candidate?.effort) && (!vote.lens || !validLenses.includes(String(vote.lens).toUpperCase()))) {
    return { valid: false, reason: `Effort-directed candidate strictly requires a valid lens ballot from: ${validLenses.join(', ')}` };
  }

  const validDecisions = ['CONFIRMED', 'SUPPORTS', 'REPORTABLE', 'FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED', 'DEFERRED', 'NEEDS_MANUAL_REVIEW'];
  const decision = String(vote.decision || vote.verdict || '').toUpperCase();
  if (!validDecisions.includes(decision)) {
    return { valid: false, reason: `Invalid ballot decision '${vote.decision}'` };
  }

  return { valid: true };
}

/**
 * Derives the deterministic disposition under the Presumption of Non-Pass (Default-Deny).
 * Raw verdict from input is strictly treated as an untrusted candidate hint and NEVER has authority.
 * Every REFUTES decision strictly requires verifiable evidence binding (P1-02).
 * Every SUPPORTS decision strictly requires verifiable evidence binding and cannot self-certify via raw rigorMetrics (R1-P0-01).
 */
export function deriveFinalDisposition(candidate, votes = [], rigor = { score: 0 }, repoRoot = null, options = {}) {
  // 1. Schema & Location Containment Validation
  if (!candidate || typeof candidate !== 'object') {
    return { disposition: 'DEFERRED', mappedVerdict: 'NEEDS_MANUAL_REVIEW', reason: 'Malformed candidate' };
  }

  const loc = candidate.location || {};
  const uri = loc.uri || loc.path;
  const startLine = Number(loc.startLine);

  if (!uri || isNaN(startLine) || startLine < 1) {
    return { disposition: 'DEFERRED', mappedVerdict: 'NEEDS_MANUAL_REVIEW', reason: 'Missing concrete location' };
  }

  // 1.5 Proof-Gap Check (Default-Deny)
  const rawGaps = candidate.proofGaps?.proofGaps || candidate.proofGaps;
  if (Array.isArray(rawGaps) && rawGaps.length > 0) {
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: `Unclosed proof gap: ${rawGaps.length} step(s) unverified under default-deny`,
      votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false },
      proofGaps: rawGaps
    };
  }

  // 2. Candidate task-binding and deduplication of votes
  const safeVotes = Array.isArray(votes) ? votes : [];
  // R8-F03-01: executionNonce derives strictly from trusted execution context, never untrusted candidate
  const executionNonce = options.expectedNonce || options.nonce || null;
  const candidateNonce = candidate?.nonce || null;

  // 1. If candidate self-asserts a nonce that contradicts the execution context nonce, fail-closed
  if (candidateNonce && executionNonce && candidateNonce !== executionNonce) {
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: `Candidate task-correlation nonce mismatch: candidate claims '${candidateNonce}', execution expected '${executionNonce}'; deferred under default-deny`,
      votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
    };
  }

  const isEffortCandidate = Boolean(
    candidate?.modelEffort ||
    candidate?.effort ||
    candidate?.reasoningProfile ||
    candidate?.tier ||
    options?.modelEffort ||
    options?.effort ||
    options?.modelProvenance?.effort
  );
  const requiresNonce = Boolean(isEffortCandidate || options?.enforceThreeLens || options?.requireNonce);

  // 2. Gate 0 (R8-F03-02 / RFC 0003 Section 3):
  // Candidate disposition mutation (both REPORTABLE and SUPPRESSED) strictly requires verified execution nonce from execution context!
  // Untrusted candidate.nonce cannot substitute for executionNonce to achieve authority.
  if (requiresNonce && !executionNonce) {
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: 'Candidate subject to task-correlation requirement strictly requires verified execution nonce from execution context; deferred under default-deny',
      votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
    };
  }

  // 3. For ballot filtering: ballot must match executionNonce if present, or candidateNonce
  const expectedNonce = executionNonce || candidateNonce || null;
  const candidateVotes = safeVotes.filter(v => {
    if (!v) return false;
    return validateBallot(v, candidate, { expectedNonce }).valid;
  });

  // Gate 0 (M54-P1-F03 / R5-F03-01): Conflicting/Contradictory Ballot Detection
  // Check if any reviewerId, persona, or lens submitted contradictory/conflicting decisions
  const decisionsByReviewer = new Map();
  const decisionsByLens = new Map();
  let hasConflictingBallots = false;
  let conflictReason = null;

  for (const v of candidateVotes) {
    const revKey = v.reviewerId || v.persona || null;
    const lensKey = v.lens ? String(v.lens).toUpperCase() : null;
    const rawDecision = String(v.decision || v.verdict || '').toUpperCase();
    const normDecision = ['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(rawDecision)
      ? 'SUPPORTS'
      : (['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(rawDecision) ? 'REFUTES' : 'DEFERRED');

    if (revKey) {
      if (!decisionsByReviewer.has(revKey)) {
        decisionsByReviewer.set(revKey, new Set());
      }
      const set = decisionsByReviewer.get(revKey);
      if (set.size > 0 && !set.has(normDecision)) {
        hasConflictingBallots = true;
        conflictReason = `Reviewer '${revKey}' submitted conflicting decisions: [${[...set, normDecision].join(', ')}]`;
      }
      set.add(normDecision);
    }

    if (lensKey) {
      if (!decisionsByLens.has(lensKey)) {
        decisionsByLens.set(lensKey, new Set());
      }
      const set = decisionsByLens.get(lensKey);
      if (set.size > 0 && !set.has(normDecision)) {
        hasConflictingBallots = true;
        conflictReason = `Lens '${lensKey}' received conflicting decisions: [${[...set, normDecision].join(', ')}]`;
      }
      set.add(normDecision);
    }
  }

  // Under Default-Deny, any candidate with contradictory/conflicting ballots strictly fails closed to DEFERRED
  if (hasConflictingBallots) {
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: `Contradictory ballots detected (${conflictReason}); deferred under default-deny`,
      votesSummary: { total: candidateVotes.length, supports: 0, refutes: 0, unanimous: false }
    };
  }

  const dedupedVotes = [];
  const seenKeys = new Set();

  for (const v of candidateVotes) {
    const key = v.reviewerId || v.persona || (v.lens ? `lens:${String(v.lens).toUpperCase()}` : null) || JSON.stringify(v);
    if (!seenKeys.has(key)) {
      seenKeys.add(key);
      dedupedVotes.push(v);
    }
  }

  // 3. Evaluate votes if present
  if (dedupedVotes.length > 0) {
    let supports = 0;
    let refutes = 0;
    let validDecisiveMitigationVote = null;
    let reachabilityRefuted = false;
    let defensesRefuted = false;
    let impactRefuted = false;
    let invalidRefutation = null;
    let invalidSupport = null;
    const validSupportVotes = [];
    let reachabilitySupports = null;
    let defensesSupports = null;
    let impactSupports = null;
    const lenses = new Set();
    const lensVotes = {
      REACHABILITY: [],
      DEFENSES: [],
      IMPACT: []
    };

    for (const v of dedupedVotes) {
      if (v.lens) {
        const uLens = String(v.lens).toUpperCase();
        lenses.add(uLens);
        if (lensVotes[uLens]) {
          lensVotes[uLens].push(v);
        }
      }
      const decision = String(v.decision || v.verdict || '').toUpperCase();
      const lens = v.lens ? String(v.lens).toUpperCase() : null;

      if (['CONFIRMED', 'SUPPORTS', 'REPORTABLE'].includes(decision)) {
        // R1-P0-01: SUPPORTS must also be evidence-bound
        const evCheck = validateVoteEvidence(v, candidate, repoRoot);
        if (!evCheck.valid) {
          invalidSupport = {
            vote: v,
            lens: lens || 'GENERAL',
            reason: evCheck.reason
          };
        } else {
          v._validatedEvidence = evCheck.evidence;
          supports++;
          validSupportVotes.push(v);
          if (lens === 'REACHABILITY') reachabilitySupports = v;
          if (lens === 'DEFENSES') defensesSupports = v;
          if (lens === 'IMPACT') impactSupports = v;
        }
      } else if (['FALSE_POSITIVE', 'REFUTES', 'SUPPRESSED'].includes(decision)) {
        refutes++;
        // P1-02: Every REFUTES must have verifiable evidence binding
        const evCheck = validateVoteEvidence(v, candidate, repoRoot);
        if (!evCheck.valid) {
          invalidRefutation = {
            vote: v,
            lens: lens || 'GENERAL',
            reason: evCheck.reason
          };
        } else {
          validDecisiveMitigationVote = v;
          if (lens === 'REACHABILITY') {
            reachabilityRefuted = true;
          } else if (lens === 'DEFENSES') {
            defensesRefuted = true;
          } else if (lens === 'IMPACT') {
            impactRefuted = true;
          }
        }
      }
    }

    const total = dedupedVotes.length;
    const isThreeLens = lenses.has('REACHABILITY') && lenses.has('DEFENSES') && lenses.has('IMPACT');

    // If any refutation failed evidence validation, candidate cannot be suppressed OR confirmed -> DEFERRED
    if (invalidRefutation) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Unverified refutation: ${invalidRefutation.lens} lens refuted without valid evidence binding (${invalidRefutation.reason}); deferred under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
      };
    }

    // 3-Lens Conjunctive Evaluation
    if (isThreeLens) {
      // If Reachability refutes with valid evidence -> Unreachable (FALSE_POSITIVE)
      if (reachabilityRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Unreachable: refuted by 3-Lens REACHABILITY analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If Defenses refutes with valid evidence -> Neutralized by sanitizer / validation barrier (FALSE_POSITIVE)
      if (defensesRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Neutralized: affirmative defense proven by 3-Lens DEFENSES analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If Impact refutes with valid evidence -> Purely theoretical / zero demonstrable harm (FALSE_POSITIVE)
      if (impactRefuted) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Zero demonstrable harm: refuted by 3-Lens IMPACT analysis with verified evidence',
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // If any support failed evidence validation, candidate cannot be confirmed -> DEFERRED (R1-P0-01)
      if (invalidSupport) {
        return {
          disposition: 'DEFERRED',
          mappedVerdict: 'NEEDS_MANUAL_REVIEW',
          reason: `Unverified support: ${invalidSupport.lens} lens voted SUPPORTS without valid evidence binding (${invalidSupport.reason}); deferred under default-deny`,
          votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
        };
      }

      // Gate 0 (M54-P1-F03 / R5-F03-01): Strict 3-Lens Unanimous Panel Enforcement
      // Requires exactly 1 valid supporting ballot for REACHABILITY, 1 for DEFENSES, and 1 for IMPACT.
      // Must have zero conflicting ballots, total === 3, candidateVotes.length === 3, and dedupedVotes.length === 3.
      // Any duplicate votes per lens, split votes, deferrals, refutations, or total !== 3 strictly fails closed to DEFERRED
      const isUnanimousThreeLens = Boolean(
        !hasConflictingBallots &&
        candidateVotes.length === 3 &&
        dedupedVotes.length === 3 &&
        total === 3 &&
        supports === 3 &&
        refutes === 0 &&
        reachabilitySupports &&
        defensesSupports &&
        impactSupports &&
        lensVotes.REACHABILITY.length === 1 &&
        lensVotes.DEFENSES.length === 1 &&
        lensVotes.IMPACT.length === 1 &&
        validSupportVotes.length === 3
      );

      if (isUnanimousThreeLens) {
        // R1-P0-01: Verify required evidence tuple:
        // 1. REACHABILITY must prove source/entrypoint
        const reachEv = reachabilitySupports?._validatedEvidence || [];
        const hasSource = reachEv.some(e => ['source', 'entrypoint', 'origin'].includes(e.role));
        if (!hasSource) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: 'Incomplete evidence tuple: REACHABILITY lens missing verified source/entrypoint evidence; deferred under default-deny',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }

        // 2. Must prove sink / root-control
        const allEv = validSupportVotes.flatMap(v => v._validatedEvidence || []);
        const candidatePath = candidate.location?.uri || candidate.location?.path;
        const candidateLine = Number(candidate.location?.startLine);

        if (candidatePath && repoRoot) {
          const fullCandTarget = path.resolve(repoRoot, candidatePath);
          if (!fs.existsSync(fullCandTarget)) {
            return {
              disposition: 'DEFERRED',
              mappedVerdict: 'NEEDS_MANUAL_REVIEW',
              reason: `Candidate target file does not exist: '${candidatePath}'; deferred under default-deny`,
              votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
            };
          }
        }

        const hasSink = allEv.some(e => ['sink', 'root-control', 'target'].includes(e.role)) ||
          (candidatePath && allEv.some(e => e.path === candidatePath && e.line === candidateLine));
        if (!hasSink) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: 'Incomplete evidence tuple: missing verified sink/root-control evidence; deferred under default-deny',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }

        // 3. Authoritative rigor derived strictly from verified evidence (R1-P0-01)
        const authoritativeRigor = deriveAuthoritativeRigor(candidate, validSupportVotes, repoRoot);
        if (authoritativeRigor.score < 0.60) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: `Authoritative rigor insufficient (${authoritativeRigor.score} < 0.60); candidate claims lack validated evidence backing; deferred under default-deny`,
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) },
            authoritativeRigor
          };
        }

        // Gate 0 (R7-F03-01 / RFC 0003 Section 3):
        // Promotion to REPORTABLE strictly requires a verifiable execution task-correlation nonce!
        // When expectedNonce is null, unassigned/un-correlated ballots cannot achieve REPORTABLE authority.
        if (requiresNonce && !expectedNonce) {
          return {
            disposition: 'DEFERRED',
            mappedVerdict: 'NEEDS_MANUAL_REVIEW',
            reason: 'Candidate subject to task-correlation requirement strictly requires verified execution nonce to achieve REPORTABLE; deferred under default-deny',
            votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
          };
        }

        return {
          disposition: 'REPORTABLE',
          mappedVerdict: 'CONFIRMED',
          reason: 'Confirmed by unanimous 3-Lens panel with verified source-control-sink evidence',
          votesSummary: { total, supports: 3, refutes: 0, unanimous: true, isThreeLens, lenses: Array.from(lenses) },
          authoritativeRigor
        };
      }

      // Any split or incomplete support in 3-Lens defaults to DEFERRED
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: '3-Lens panel non-unanimous; candidate unproven under default-deny',
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens, lenses: Array.from(lenses) }
      };
    }

    // Gate 0 (M54-P1-F03 / R5-F03-02 / RFC 0003):
    // 3-Lens verification panel is required if:
    // 1. Candidate carries effort metadata (modelEffort, reasoningProfile, tier, etc.)
    // 2. Execution context mandates 3-lens (options.enforceThreeLens === true)
    // 3. Any lens-based ballots were submitted (lenses.size > 0)
    const requiresThreeLens = Boolean(
      isEffortCandidate ||
      options?.enforceThreeLens ||
      lenses.size > 0
    );

    // Gate 0 (M54-P1-F03 / R5-F03-02 / RFC 0003): All candidates subject to 3-Lens requirement strictly require unanimous Fixed 3-Lens panel
    if (requiresThreeLens && !isThreeLens) {
      if (validDecisiveMitigationVote && refutes / total >= 0.66) {
        return {
          disposition: 'SUPPRESSED',
          mappedVerdict: 'FALSE_POSITIVE',
          reason: 'Affirmatively refuted by verifier with verified mitigation evidence',
          votesSummary: { total, supports, refutes, unanimous: refutes === total, isThreeLens: false, lenses: Array.from(lenses) }
        };
      }
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Candidate subject to Fixed 3-Lens requirement strictly requires unanimous 3-Lens panel verification (REACHABILITY, DEFENSES, IMPACT); non-lens or partial ballots cannot grant REPORTABLE disposition under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens: false, lenses: Array.from(lenses) }
      };
    }

    // If lens ballots were submitted but the 3-Lens panel is incomplete (missing required lens), fail-closed under Default-Deny
    if (lenses.size > 0 && !isThreeLens) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Incomplete 3-Lens panel: received [${Array.from(lenses).join(', ')}]; missing required lenses under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, isThreeLens: false, lenses: Array.from(lenses) }
      };
    }

    // General Persona Evaluation: Decisive counterevidence refutation always suppresses
    if (validDecisiveMitigationVote) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Affirmatively refuted by verifier with verified mitigation evidence',
        votesSummary: { total, supports, refutes, unanimous: refutes === total, lenses: Array.from(lenses) }
      };
    }

    // If any support failed evidence validation, candidate cannot be confirmed -> DEFERRED (R1-P0-01)
    if (invalidSupport) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: `Unverified support: ${invalidSupport.lens} lens voted SUPPORTS without valid evidence binding (${invalidSupport.reason}); deferred under default-deny`,
        votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
      };
    }

    // Quorum rule: Need at least 2 independent votes
    if (total < 2) {
      return {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Quorum not met: requires at least 2 independent verifier votes',
        votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
      };
    }

    const supportRatio = supports / total;
    const authoritativeRigor = deriveAuthoritativeRigor(candidate, validSupportVotes, repoRoot);

    // Reportable requirement: 2/3 supermajority + authoritative rigor >= 0.60 + source & sink verified
    // Gate 0 (M54-P1-F03 / R5-F03-02): All candidates subject to 3-lens requirement cannot bypass via legacy 2/3
    if (!requiresThreeLens && supportRatio >= 0.66 && total >= 2 && authoritativeRigor.score >= 0.60 && authoritativeRigor.metrics.sourceVerified && authoritativeRigor.metrics.sinkVerified) {
      if (requiresNonce && !expectedNonce) {
        return {
          disposition: 'DEFERRED',
          mappedVerdict: 'NEEDS_MANUAL_REVIEW',
          reason: 'Candidate subject to task-correlation requirement strictly requires verified execution nonce to achieve REPORTABLE; deferred under default-deny',
          votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
        };
      }
      return {
        disposition: 'REPORTABLE',
        mappedVerdict: 'CONFIRMED',
        reason: 'Confirmed by 2/3 verifier supermajority with verified evidence',
        votesSummary: {
          total,
          supports,
          refutes,
          unanimous: supports === total,
          isThreeLens: false,
          lenses: Array.from(lenses)
        },
        authoritativeRigor
      };
    }

    // Refuted requirement: 3/4 supermajority + affirmative verifier mitigation proof
    if (refutes / total >= 0.75 && validDecisiveMitigationVote) {
      return {
        disposition: 'SUPPRESSED',
        mappedVerdict: 'FALSE_POSITIVE',
        reason: 'Refuted by 3/4 verifier supermajority with affirmative mitigation',
        votesSummary: { total, supports, refutes, unanimous: refutes === total, lenses: Array.from(lenses) }
      };
    }

    // Fallback on dispute / split decision
    return {
      disposition: 'DEFERRED',
      mappedVerdict: 'NEEDS_MANUAL_REVIEW',
      reason: 'Panel split or unproven evidence under default-deny',
      votesSummary: { total, supports, refutes, unanimous: false, lenses: Array.from(lenses) }
    };
  }

  // 4. Default-Deny: No independent verifier votes -> DEFERRED (Cannot self-certify)
  return {
    disposition: 'DEFERRED',
    mappedVerdict: 'NEEDS_MANUAL_REVIEW',
    reason: 'No independently recorded verifier votes; presumed unverified under default-deny',
    votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
  };
}



/**
 * Clamps confidence objectively based on derived disposition and panel agreement.
 */
export function clampConfidence(disposition, votesSummary = {}, rawConfidence = null) {
  const conf = typeof rawConfidence === 'number' ? rawConfidence : null;

  if (disposition === 'DEFERRED') {
    return { score: conf !== null ? Math.min(0.40, conf) : 0.30, level: 'low' };
  }

  if (disposition === 'SUPPRESSED') {
    return { score: conf !== null ? Math.min(0.50, conf) : 0.40, level: 'low' };
  }

  if (disposition === 'REPORTABLE') {
    const { total = 0, unanimous = false } = votesSummary;
    if (total >= 3 && unanimous) {
      return { score: conf !== null ? Math.min(0.95, Math.max(0.75, conf)) : 0.85, level: 'high' };
    }
    // 2/3 majority or 2-member unanimous panel clamps to medium
    return { score: conf !== null ? Math.min(0.70, Math.max(0.50, conf)) : 0.65, level: 'medium' };
  }

  return { score: 0.20, level: 'low' };
}

/**
 * Computes deterministic partial fingerprint for line hash.
 */
export function computeLineHash(content) {
  if (!content) return '0000000000000000';
  return crypto.createHash('sha256').update(content.trim()).digest('hex').substring(0, 16);
}

/**
 * Computes stable finding fingerprint.
 */
export function computeFindingFingerprint(ruleId, uri, startLine) {
  const r = String(ruleId || 'SEC');
  const u = String(uri || 'unknown');
  const l = String(startLine || 1);
  const payload = `${r.length}:${r}:${u.length}:${u}:${l}`;
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 32);
}

export const VALID_NOVELTY_STATES = [
  'NEW_SURFACE',
  'PREVIOUSLY_MISSED',
  'FIX_INTRODUCED',
  'REFINEMENT',
  'DUPLICATE',
  'HARDENING'
];

/**
 * Computes semantic lineage fingerprint v2.
 * Independent of exact line shifts.
 * Built from: ruleId + normalized relative uri + component + family + symbol/operation.
 */
export function computeLineageFingerprint({
  ruleId = 'SEC-VULN',
  uri = 'unknown',
  component = '',
  family = '',
  sinkKind = '',
  symbol = ''
}) {
  const r = String(ruleId || 'SEC').trim().toUpperCase();
  const u = String(uri || 'unknown').replace(/\\/g, '/').replace(/^\.\//, '').toLowerCase();
  const c = String(component || '').trim().toLowerCase();
  const f = String(family || '').trim().toLowerCase();
  let s = String(symbol || sinkKind || '').trim().replace(/\(\s*\)$/, '').trim().toLowerCase();
  s = s.replace(/^(?:mockdatabase|db|collection)\./, '');
  const payload = `L2:${r.length}:${r}:${u.length}:${u}:${c}:${f}:${s}`;
  return crypto.createHash('sha256').update(payload).digest('hex').substring(0, 32);
}

/**
 * Normalizes a candidate finding's symbol to its canonical sink call or function name.
 * Resolves local variable names or router handlers to the underlying sink when evident in source lines.
 */
export function normalizeCandidateSymbol(cand, fileContent = '') {
  if (!cand || typeof cand !== 'object') return cand;

  let sym = String(cand.symbol || '').trim();
  // Strip trailing call parentheses: e.g. 'find()' -> 'find'
  sym = sym.replace(/\(\s*\)$/, '').trim();

  // If file content is available, inspect target lines to resolve variable/router drift to canonical sinks
  if (fileContent && typeof fileContent === 'string' && cand.location) {
    const lines = fileContent.split(/\r?\n/);
    const startLine = Math.max(1, Number(cand.location.startLine) || 1);
    const endLine = Math.min(lines.length, Number(cand.location.endLine) || startLine);

    // Extract snippet around target lines (expanding slightly for route block scopes)
    const scanStart = Math.max(0, startLine - 3);
    const scanEnd = Math.min(lines.length, endLine + 2);
    const snippet = lines.slice(scanStart, scanEnd).join('\n');

    // Known canonical sink resolution:
    // 1. Database/collection lookups: if symbol is a result variable ('doc') or router method, but line has mockDatabase.find / db.find
    if (/(?:mockDatabase|db|collection|repository|model)\.find\b/.test(snippet)) {
      if (sym === 'doc' || sym === 'router.get' || sym === 'find' || sym === '' || sym === 'mockDatabase') {
        sym = 'mockDatabase.find';
      }
    }
    // 2. Object mutation / prototype pollution: recursiveMerge / merge
    if (/\brecursiveMerge\b/.test(snippet) && (sym === 'merged' || sym === 'userConfig' || sym === 'router.post' || sym === '' || sym === 'merge')) {
      sym = 'recursiveMerge';
    }
    // 3. Cryptographic deciphering
    if (/crypto\.createDecipheriv\b/.test(snippet) && (sym === 'decipher' || sym === 'router.post' || sym === 'createDecipheriv')) {
      sym = 'crypto.createDecipheriv';
    }
    // 4. Policy evaluation
    if (/\bevalPermit\b/.test(snippet) && (sym === 'permit' || sym === 'router.post' || sym === '')) {
      sym = 'evalPermit';
    }
    // 5. Code execution / vm
    if (/vm\.runInNewContext\b/.test(snippet) && (sym === 'runInNewContext' || sym === 'worker' || sym === '')) {
      sym = 'vm.runInNewContext';
    }
  }

  cand.symbol = sym;
  return cand;
}

/**
 * Validates the lineage and novelty metadata of a finding.
 * Enforces non-empty whyNow rationale for FIX_INTRODUCED and PREVIOUSLY_MISSED.
 */
export function validateFindingLineage(lineage) {
  if (!lineage || typeof lineage !== 'object') {
    return {
      valid: true,
      lineage: {
        lineageId: null,
        novelty: 'NEW_SURFACE',
        whyNow: null,
        predecessorId: null,
        stabilityImpact: false
      }
    };
  }

  const novelty = String(lineage.novelty || 'NEW_SURFACE').toUpperCase();
  if (!VALID_NOVELTY_STATES.includes(novelty)) {
    return {
      valid: false,
      error: `Invalid novelty '${lineage.novelty}'. Must be one of: ${VALID_NOVELTY_STATES.join(', ')}`
    };
  }

  const needsWhyNow = (novelty === 'FIX_INTRODUCED' || novelty === 'PREVIOUSLY_MISSED');
  if (needsWhyNow) {
    if (!lineage.whyNow || typeof lineage.whyNow !== 'string' || lineage.whyNow.trim().length === 0) {
      return {
        valid: false,
        error: `Novelty '${novelty}' strictly requires a non-empty 'whyNow' rationale explaining why this finding appeared now.`
      };
    }
  }

  const stabilityImpact = Boolean(lineage.stabilityImpact || novelty === 'PREVIOUSLY_MISSED');

  return {
    valid: true,
    lineage: {
      lineageId: lineage.lineageId || null,
      novelty,
      whyNow: lineage.whyNow || null,
      predecessorId: lineage.predecessorId || null,
      stabilityImpact
    }
  };
}

/**
 * External Tool Evidence Interface (R2-P1-06)
 * Ingests external deterministic scanner outputs (CodeQL, Semgrep, Trivy, Gitleaks, osv-scanner)
 * via generic SARIF 2.1.0 or JSON adapter for semantic corroboration.
 */
/**
 * Cross-platform URI and path resolver for external tool SARIF/JSON evidence (R7-P0-02).
 * Normalizes Windows backslashes, percent-encoded characters, and file:// URLs regardless of host platform.
 */
export function resolveExternalUri(repoRoot, rawUri) {
  if (!rawUri || rawUri === 'unknown') return 'unknown';
  let clean = String(rawUri).trim();
  if (clean.startsWith('file://')) {
    clean = clean.replace(/^file:\/\/\/?/, '');
    if (!/^[a-zA-Z]:/.test(clean) && !clean.startsWith('/')) {
      clean = '/' + clean;
    }
  }
  try {
    clean = decodeURIComponent(clean);
  } catch {
    // ignore decode error
  }
  clean = clean.replaceAll('\\', '/');
  const resolvedRoot = path.resolve(repoRoot).replaceAll('\\', '/');
  let rel;
  if (/^[a-zA-Z]:\//.test(clean) || clean.startsWith('/')) {
    rel = path.relative(resolvedRoot, clean);
  } else {
    rel = clean;
  }
  return rel.replaceAll('\\', '/').replace(/\/+/g, '/').replace(/^\.\//, '');
}

/**
 * External Tool Evidence Interface (R2-P1-06 & R7-P0-02)
 * Ingests external deterministic scanner outputs (CodeQL, Semgrep, Trivy, Gitleaks, osv-scanner)
 * via generic SARIF 2.1.0 or JSON adapter for semantic corroboration.
 * Enforces cross-platform URI normalization, shadow context duplicate detection,
 * and granular evidence-binding accounting (BOUND, UNBOUND_PATH, UNBOUND_MISSING_FILE, GENERATED_DUPLICATE, OUTSIDE_SCOPE).
 */
export function ingestExternalEvidence(input, repoRoot = process.cwd()) {
  if (!input) {
    return {
      success: false,
      error: 'No input provided',
      parsedCount: 0,
      canonicalCount: 0,
      boundCount: 0,
      unboundCount: 0,
      duplicateGeneratedCount: 0,
      count: 0,
      findings: []
    };
  }
  let data = input;
  if (typeof input === 'string') {
    if (fs.existsSync(input)) {
      try {
        data = JSON.parse(fs.readFileSync(input, 'utf8'));
      } catch (err) {
        return {
          success: false,
          error: `Failed reading external evidence file: ${err.message}`,
          parsedCount: 0,
          canonicalCount: 0,
          boundCount: 0,
          unboundCount: 0,
          duplicateGeneratedCount: 0,
          count: 0,
          findings: []
        };
      }
    } else {
      try {
        data = JSON.parse(input);
      } catch {
        return {
          success: false,
          error: 'Input string is neither valid file path nor valid JSON',
          parsedCount: 0,
          canonicalCount: 0,
          boundCount: 0,
          unboundCount: 0,
          duplicateGeneratedCount: 0,
          count: 0,
          findings: []
        };
      }
    }
  }

  const rawItems = [];
  // Case A: Standard SARIF 2.1.0 (Semgrep, CodeQL, Trivy)
  if (data && data.version === '2.1.0' && Array.isArray(data.runs)) {
    for (const run of data.runs) {
      const toolName = run.tool?.driver?.name || 'EXTERNAL_SAST';
      const results = Array.isArray(run.results) ? run.results : [];
      for (const res of results) {
        const ruleId = res.ruleId || 'EXTERNAL-FINDING';
        const rawUri = res.locations?.[0]?.physicalLocation?.artifactLocation?.uri || 'unknown';
        const startLine = Number(res.locations?.[0]?.physicalLocation?.region?.startLine || 1);
        rawItems.push({
          tool: toolName,
          ruleId,
          title: res.message?.text || ruleId,
          rawUri,
          startLine,
          severity: String(res.level || 'warning').toUpperCase(),
          rawFinding: res
        });
      }
    }
  } else {
    // Case B: Array of scanner items or object with results/vulnerabilities
    const rawList = Array.isArray(data)
      ? data
      : (Array.isArray(data?.results) ? data.results : (Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : null));

    if (rawList) {
      for (const item of rawList) {
        const tool = item.tool || item.scanner || 'EXTERNAL_SCANNER';
        const ruleId = item.ruleId || item.cwe || item.id || 'EXTERNAL-FINDING';
        const rawUri = item.location?.uri || item.file || item.path || 'unknown';
        const startLine = Number(item.location?.startLine || item.line || 1);
        rawItems.push({
          tool,
          ruleId,
          title: item.title || item.message || ruleId,
          rawUri,
          startLine,
          severity: String(item.severity || 'MEDIUM').toUpperCase(),
          rawFinding: item
        });
      }
    } else {
      return {
        success: false,
        error: 'Unsupported external evidence format',
        parsedCount: 0,
        canonicalCount: 0,
        boundCount: 0,
        unboundCount: 0,
        duplicateGeneratedCount: 0,
        count: 0,
        findings: []
      };
    }
  }

  const resolvedRepoRoot = path.resolve(repoRoot);
  const findings = [];
  let canonicalCount = 0;
  let boundCount = 0;
  let unboundCount = 0;
  let duplicateGeneratedCount = 0;
  let outsideScopeCount = 0;
  const seenSignatures = new Set();

  for (const item of rawItems) {
    const relPath = resolveExternalUri(resolvedRepoRoot, item.rawUri);
    const isShadow = relPath.startsWith('scratch/context/');
    const canonicalUri = isShadow ? relPath.slice('scratch/context/'.length) : relPath;
    const sig = `${item.tool}::${item.ruleId}::${canonicalUri}::${item.startLine}`;

    let isDuplicate = false;
    if (isShadow || seenSignatures.has(sig)) {
      if (seenSignatures.has(sig)) {
        isDuplicate = true;
      } else if (isShadow && fs.existsSync(path.resolve(resolvedRepoRoot, canonicalUri))) {
        const hasOriginal = rawItems.some(other => {
          const otherRel = resolveExternalUri(resolvedRepoRoot, other.rawUri);
          return otherRel === canonicalUri && other.ruleId === item.ruleId && other.startLine === item.startLine;
        });
        if (hasOriginal) {
          isDuplicate = true;
        }
      }
    }

    let evidenceBinding;
    let evidenceHash = null;

    if (isDuplicate) {
      evidenceBinding = 'GENERATED_DUPLICATE';
      duplicateGeneratedCount++;
      const snap = computeEvidenceSnapshot(resolvedRepoRoot, canonicalUri, item.startLine);
      evidenceHash = snap.error ? null : snap.lineHash;
    } else {
      seenSignatures.add(sig);
      canonicalCount++;
      const fullPath = path.resolve(resolvedRepoRoot, canonicalUri);
      if (!isPathContained(resolvedRepoRoot, fullPath)) {
        evidenceBinding = 'OUTSIDE_SCOPE';
        unboundCount++;
        outsideScopeCount++;
      } else {
        const snap = computeEvidenceSnapshot(resolvedRepoRoot, canonicalUri, item.startLine);
        if (snap.exists && !snap.error && snap.lineHash) {
          evidenceBinding = 'BOUND';
          evidenceHash = snap.lineHash;
          boundCount++;
        } else if (!snap.exists) {
          evidenceBinding = 'UNBOUND_MISSING_FILE';
          unboundCount++;
        } else {
          evidenceBinding = 'UNBOUND_PATH';
          unboundCount++;
        }
      }
    }

    findings.push({
      tool: item.tool,
      ruleId: item.ruleId,
      title: item.title,
      location: {
        uri: isShadow ? canonicalUri : relPath,
        startLine: item.startLine,
        ...(isShadow ? { originalShadowUri: relPath } : {})
      },
      severity: item.severity,
      evidenceBinding,
      evidenceHash,
      rawFinding: item.rawFinding
    });
  }

  return {
    success: true,
    parsedCount: rawItems.length,
    canonicalCount,
    boundCount,
    unboundCount,
    duplicateGeneratedCount,
    outsideScopeCount,
    count: canonicalCount,
    findings
  };
}

/**
 * Execution Attestation (R2-P1-05)
 * Produces cryptographic and verifiable attestation of executed audit stages and delegation.
 */
export function buildExecutionAttestation({
  repoRoot = process.cwd(),
  target = null,
  auditIntent = 'DISCOVERY',
  executedStages = ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION'],
  failedStages = [],
  coverageComplete = true,
  delegationObserved = false,
  zeroCandidates = false,
  canonicalFindingsCount = null,
  capabilities = null,
  contextIsolation = null,
  toolProvenance = null
} = {}) {
  const isZeroCandidates = Boolean(zeroCandidates || canonicalFindingsCount === 0);
  const allPossibleStages = ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'VERIFICATION_PANEL', 'FINALIZATION'];
  const requiredStages = auditIntent === 'REGRESSION'
    ? (isZeroCandidates ? ['INVENTORY', 'FINALIZATION'] : ['INVENTORY', 'VERIFICATION_PANEL', 'FINALIZATION'])
    : (isZeroCandidates ? ['INVENTORY', 'THREAT_MODELING', 'DISCOVERY_MATRIX', 'FINALIZATION'] : allPossibleStages);

  const safeExecuted = Array.isArray(executedStages) ? executedStages : [];
  const safeFailed = Array.isArray(failedStages) ? failedStages : [];
  const executedSet = new Set(safeExecuted);
  const skippedStages = requiredStages.filter(s => !executedSet.has(s));

  // Capabilities Attestation (R4-P1-02 & R5-P0-02: Default-Unknown)
  const defaultRequired = ['repository.read'];
  const defaultForbidden = ['filesystem.write', 'process.execute', 'network.external'];
  let capObj;

  if (capabilities && typeof capabilities === 'object') {
    const req = Array.isArray(capabilities.required) ? capabilities.required : defaultRequired;
    const obs = Array.isArray(capabilities.observed) ? capabilities.observed : [];
    const forb = Array.isArray(capabilities.forbidden) ? capabilities.forbidden : defaultForbidden;

    let stat = capabilities.status;
    let confidence = capabilities.attestationConfidence;
    let source = capabilities.observationSource || null;

    if (!stat) {
      if (obs.length > 0) {
        const hasForbidden = obs.some(c => forb.includes(c));
        stat = hasForbidden ? 'VIOLATION' : 'CONFORMANT';
        confidence = 'OBSERVED';
        source = source || 'runtime-telemetry';
      } else if (capabilities.declaration || confidence === 'DECLARED') {
        stat = 'DECLARED';
        confidence = 'DECLARED';
        source = source || 'agent-manifest-declaration';
      } else {
        stat = 'UNKNOWN';
        confidence = 'UNKNOWN';
        source = null;
      }
    } else {
      if (!confidence) {
        confidence = (stat === 'CONFORMANT' || stat === 'VIOLATION') && obs.length > 0
          ? 'OBSERVED'
          : (stat === 'DECLARED' ? 'DECLARED' : 'UNKNOWN');
      }
    }

    capObj = {
      required: req,
      observed: obs,
      forbidden: forb,
      status: stat,
      observationSource: source,
      attestationConfidence: confidence
    };
  } else {
    // Default-Unknown: absence of telemetry is NEVER assumed to be compliant
    capObj = {
      required: defaultRequired,
      observed: [],
      forbidden: defaultForbidden,
      status: 'UNKNOWN',
      observationSource: null,
      attestationConfidence: 'UNKNOWN'
    };
  }

  const stagesComplete = skippedStages.length === 0 && safeFailed.length === 0 && Boolean(coverageComplete);
  let verdict;

  if (capObj.status === 'VIOLATION' || safeFailed.length > 0) {
    verdict = 'INCOMPLETE';
  } else if (!stagesComplete) {
    verdict = 'DEGRADED';
  } else if (capObj.status === 'CONFORMANT' && capObj.attestationConfidence === 'OBSERVED' && (delegationObserved || isZeroCandidates)) {
    verdict = 'COMPLETE_VERIFIED';
  } else if (capObj.status === 'DECLARED' || (stagesComplete && (delegationObserved || isZeroCandidates || capObj.status === 'UNKNOWN'))) {
    verdict = 'COMPLETE_DECLARED';
  } else {
    verdict = 'DEGRADED';
  }

  return {
    schemaVersion: '1.0.0',
    attestationId: `ATT-${crypto.randomBytes(6).toString('hex')}`,
    timestamp: new Date().toISOString(),
    toolProvenance: toolProvenance || getToolProvenance(),
    target: target || {
      repositoryUri: repoRoot,
      revision: 'HEAD'
    },
    auditIntent,
    requiredStages,
    executedStages: safeExecuted,
    skippedStages,
    failedStages: safeFailed,
    coverageComplete: Boolean(coverageComplete),
    delegationRequired: !isZeroCandidates,
    delegationObserved: isZeroCandidates ? false : Boolean(delegationObserved),
    verificationStatus: isZeroCandidates ? 'NOT_APPLICABLE_ZERO_CANDIDATES' : (delegationObserved ? 'VERIFIED_PANEL' : 'UNVERIFIED'),
    verdict,
    capabilities: capObj,
    contextIsolation: contextIsolation || {
      status: 'MANDATED',
      pipeline: 'MANDATED_SHADOW_CONTEXT_PIPELINE',
      shadowContextRoot: 'scratch/context',
      tokenizedFilesCount: 0,
      totalSecretsTokenized: 0
    }
  };
}

/**
 * Verifies runtime guard telemetry for context isolation attestation (F-02 / Invariant 113).
 * Under Default-Deny, OBSERVED attestation requires conclusive affirmative proof:
 * 1. Telemetry file exists in trusted execution location or repo mirror.
 * 2. Parsed JSON lines are non-empty and structurally valid.
 * 3. Event manifestDigest matches active shadow context manifest (prevents stale / forged replay).
 * 4. Event conversationId matches current run (if specified).
 * 5. Event timestamps fall within the scan execution window.
 * 6. Zero illegal raw repository allowances (unshadowed target path must not be allowed).
 */
export function verifyGuardTelemetry({
  telemetryPath = null,
  artifactDirectoryPath = null,
  shadowRoot = null,
  manifestDigest = null,
  conversationId = null,
  scanStartedAt = null
} = {}) {
  const candidatePaths = [];
  if (telemetryPath) {
    candidatePaths.push({ path: path.resolve(telemetryPath), isTrusted: true });
  }
  if (artifactDirectoryPath) {
    candidatePaths.push({
      path: path.join(path.resolve(artifactDirectoryPath), 'shadow-guard-telemetry.jsonl'),
      isTrusted: true
    });
  }
  if (process.env.AGY_GUARD_TELEMETRY_PATH) {
    candidatePaths.push({
      path: path.resolve(process.env.AGY_GUARD_TELEMETRY_PATH),
      isTrusted: true
    });
  }
  if (shadowRoot) {
    candidatePaths.push({
      path: path.resolve(shadowRoot, 'guard-events.jsonl'),
      isTrusted: false
    });
  }

  let chosen = null;
  for (const c of candidatePaths) {
    if (fs.existsSync(c.path)) {
      chosen = c;
      break;
    }
  }

  if (!chosen) {
    return { verified: false, reason: 'NO_TELEMETRY_FOUND' };
  }

  // Under Default-Deny, untrusted workspace telemetry (!chosen.isTrusted) MUST NOT be accepted unless manifestDigest is non-null
  if (!chosen.isTrusted && !manifestDigest) {
    return {
      verified: false,
      reason: 'UNTRUSTED_TELEMETRY_REQUIRES_MANIFEST_BINDING'
    };
  }

  let lines = [];
  try {
    lines = fs.readFileSync(chosen.path, 'utf8')
      .split('\n')
      .map(l => l.trim())
      .filter(l => l.length > 0);
  } catch (err) {
    return { verified: false, reason: `READ_ERROR: ${err.message}` };
  }

  if (lines.length === 0) {
    return { verified: false, reason: 'EMPTY_TELEMETRY' };
  }

  const events = [];
  for (let i = 0; i < lines.length; i++) {
    try {
      const evt = JSON.parse(lines[i]);
      if (!evt || typeof evt !== 'object') {
        return { verified: false, reason: `MALFORMED_EVENT_AT_LINE_${i + 1}` };
      }
      events.push(evt);
    } catch {
      return { verified: false, reason: `JSON_PARSE_ERROR_AT_LINE_${i + 1}` };
    }
  }

  // 1. Manifest Digest Binding: every event must match the current active shadow context manifest digest
  if (manifestDigest) {
    for (const evt of events) {
      if (!evt.manifestDigest || evt.manifestDigest !== manifestDigest) {
        return {
          verified: false,
          reason: `MANIFEST_DIGEST_MISMATCH: expected ${manifestDigest}, got ${evt.manifestDigest || 'missing'}`
        };
      }
    }
  }

  // 2. Conversation ID Binding (if specified or in env)
  const effectiveConvId = conversationId || process.env.AGY_CONVERSATION_ID || null;
  if (effectiveConvId) {
    for (const evt of events) {
      if (evt.conversationId && evt.conversationId !== 'UNKNOWN' && evt.conversationId !== effectiveConvId) {
        return {
          verified: false,
          reason: `CONVERSATION_ID_MISMATCH: expected ${effectiveConvId}, got ${evt.conversationId}`
        };
      }
    }
  }

  // 3. Time Window Validation
  if (scanStartedAt) {
    const startedMs = new Date(scanStartedAt).getTime();
    if (!isNaN(startedMs)) {
      for (const evt of events) {
        const evtMs = new Date(evt.timestamp).getTime();
        if (isNaN(evtMs) || evtMs < (startedMs - 60000)) {
          return {
            verified: false,
            reason: 'EVENT_PREDATES_SCAN_WINDOW'
          };
        }
      }
    }
  }

  // 4. Zero Illegal Raw Access Allowances:
  // If an event targets a raw file (outside scratch/context), decision MUST be 'deny'
  for (const evt of events) {
    const normalizedTarget = (evt.targetPath || '').replace(/\\/g, '/');
    const isShadowPath = normalizedTarget.includes('scratch/context');
    if (!isShadowPath && evt.decision === 'allow' && evt.action !== 'passthrough_outside_workspace') {
      return {
        verified: false,
        reason: `ILLEGAL_RAW_ACCESS_ALLOWED: ${evt.targetPath}`
      };
    }
  }

  return {
    verified: true,
    telemetrySource: chosen.isTrusted ? 'TRUSTED_ARTIFACT_DIR' : 'WORKSPACE_MIRROR',
    telemetryPath: chosen.path,
    eventsCount: events.length,
    manifestDigest: manifestDigest || null
  };
}

/**
 * Central deterministic finalizer: transforms candidates into canonical findings.
 */
export function finalizeScan({
  candidates = [],
  manifest = null,
  repoRoot = process.cwd(),
  provenance = null,
  votes = [],
  waivers = [],
  expectedMode = null,
  auditIntent = 'DISCOVERY',
  discoveryMatrix = [],
  threatModel = null,
  targetProfile = null,
  modelProvenance = null,
  capabilities = null,
  executedStages = null,
  allowSelfAudit = false,
  toolRoot = null,
  toolProvenance = null,
  contextIsolation = null,
  artifactDirectoryPath = null,
  telemetryPath = null,
  conversationId = null,
  shadowRoot = null,
  contextPrep = null,
  scanRunId = null,
  nonce = null,
  cloudflareCoverage = null,
  compactedAuditEnvelope = null,
  compactedAuditContent = null,
  compactOptions = null,
  preCompactionState = null,
  isCompactedSession = false
} = {}) {
  const effectiveToolProvenance = toolProvenance || getToolProvenance(toolRoot);
  const safeVotes = Array.isArray(votes) ? votes : [];
  const safeRepoRoot = (typeof repoRoot === 'string' && repoRoot.trim().length > 0) ? repoRoot : null;
  // RFC 0003 Section 3 / R10-F03-01: Under Default-Deny on Authority Claims,
  // an execution nonce from manifest is ONLY inheritable if:
  // 1. Manifest exists and is incomplete (manifest.complete !== true)
  // 2. Both executionRunId and manifestRunId are non-empty strings
  // 3. executionRunId strictly equals manifestRunId
  // Missing Run ID on either or both sides strictly refuses nonce inheritance under default-deny.
  const manifestRunId = (manifest?.scanRunId && String(manifest.scanRunId).trim().length > 0)
    ? String(manifest.scanRunId).trim()
    : null;
  const executionRunId = (scanRunId && String(scanRunId).trim().length > 0)
    ? String(scanRunId).trim()
    : null;
  const isManifestRunBound = Boolean(
    manifest &&
    !manifest.complete &&
    executionRunId &&
    manifestRunId &&
    executionRunId === manifestRunId
  );
  let effectiveNonce = nonce || (isManifestRunBound ? (manifest?.taskCorrelationNonce || manifest?.nonce || null) : null);

  // M54-P2-F06: CASE Compacted Audit State Envelope verification
  const isCompactedSessionEffective = Boolean(
    isCompactedSession ||
    compactOptions?.requireCompactEnvelope ||
    manifest?.isCompacted === true ||
    preCompactionState
  );

  let compactGuardResult = null;
  if (compactedAuditContent || compactedAuditEnvelope || isCompactedSessionEffective) {
    let env = compactedAuditEnvelope;
    if (!env && compactedAuditContent) {
      const extracted = extractCompactedAuditHeader(compactedAuditContent, {
        failClosed: false,
        verifierPublicKey: compactOptions?.verifierPublicKey,
        requireSignature: compactOptions?.requireSignature
      });
      if (!extracted.valid) {
        compactGuardResult = { valid: false, error: extracted.error, status: 'UNCHECKABLE' };
      } else {
        env = extracted.envelope;
      }
    }

    if (!compactGuardResult && env) {
      const expectedRepoRootFp = repoRoot ? crypto.createHash('sha256').update(path.resolve(repoRoot), 'utf8').digest('hex') : null;
      // R08-B03: Runtime tool provenance is authoritative under Default-Deny.
      // Expected tool digest passed via compactOptions cannot override runtime provenance;
      // any divergence between caller expectation and runtime provenance is a conflict failure.
      const runtimeToolDigest = effectiveToolProvenance?.toolIntegrityDigest || null;
      const expectedCallerDigest = compactOptions?.expectedToolManifestDigest || null;
      if (runtimeToolDigest && expectedCallerDigest && runtimeToolDigest !== expectedCallerDigest) {
        compactGuardResult = {
          valid: false,
          error: `[TOOL_DIGEST_AUTHORITY_CONFLICT] Caller expectedToolManifestDigest (${expectedCallerDigest}) conflicts with authoritative runtime tool provenance (${runtimeToolDigest})`,
          status: 'UNCHECKABLE',
          envelope: env
        };
      }
      const trustedToolDigest = runtimeToolDigest || expectedCallerDigest || null;
      if (!compactGuardResult && preCompactionState?.toolManifestDigest && trustedToolDigest && preCompactionState.toolManifestDigest !== trustedToolDigest) {
        compactGuardResult = {
          valid: false,
          error: `Pre-compaction state toolManifestDigest (${preCompactionState.toolManifestDigest}) does not match trusted runtime tool provenance (${trustedToolDigest})`,
          status: 'UNCHECKABLE',
          envelope: env
        };
      }

      const expectedContext = {
        scanRunId: executionRunId || manifestRunId || preCompactionState?.scanRunId || null,
        executionNonce: effectiveNonce || preCompactionState?.executionNonce || null,
        toolManifestDigest: trustedToolDigest || preCompactionState?.toolManifestDigest || null,
        repoRootFingerprint: compactOptions?.requireRepoRootFingerprint
          ? expectedRepoRootFp
          : (env?.repoRootFingerprint ? expectedRepoRootFp : (preCompactionState?.repoRootFingerprint || null))
      };
      if (preCompactionState?.persistedState !== undefined) {
        expectedContext.persistedState = preCompactionState.persistedState;
      }

      // R04-B04 & R05-B05: In a compacted session, binding context is mandatory under Default-Deny
      if (isCompactedSessionEffective) {
        if (!expectedContext.scanRunId || !expectedContext.executionNonce || !expectedContext.toolManifestDigest) {
          compactGuardResult = {
            valid: false,
            error: 'Compacted session requires authoritative scanRunId, executionNonce, and toolManifestDigest context bindings (R04-B04)',
            status: 'UNCHECKABLE',
            envelope: env
          };
        }
      }

      if (!compactGuardResult) {
        const validation = validateCompactedStateEnvelope(env, expectedContext, compactOptions || {});
        if (!validation.valid) {
          compactGuardResult = { valid: false, error: validation.error, status: 'UNCHECKABLE', envelope: env };
        } else if (preCompactionState) {
          // Enforce end-to-end assertCompactSafe check
          const rawContent = compactedAuditContent || serializeCompactedAuditHeader(env);
          const safeCheck = assertCompactSafe(preCompactionState, rawContent, compactOptions || {});
          if (!safeCheck.safe) {
            compactGuardResult = { valid: false, error: safeCheck.error, status: 'UNCHECKABLE', envelope: env };
          } else {
            // Round 07 F-06: Under Default-Deny, VERIFIED status requires verified cryptographic signature
            const hasVerifiedSig = (validation.signatureValid === true) || (env?.signature && compactOptions?.verifierPublicKey);
            if (hasVerifiedSig) {
              compactGuardResult = { valid: true, error: null, status: 'VERIFIED', envelope: env };
            } else if (compactOptions?.requireSignature) {
              compactGuardResult = {
                valid: false,
                error: 'Compacted state envelope requires verified cryptographic signature under Default-Deny (F-06)',
                status: 'UNCHECKABLE',
                envelope: env
              };
            } else {
              compactGuardResult = { valid: true, error: null, status: 'UNAUTHENTICATED', envelope: env };
            }
          }
        } else if (env?.signature && compactOptions?.verifierPublicKey) {
          compactGuardResult = { valid: true, error: null, status: 'VERIFIED', envelope: env };
        } else {
          // R05-B05: Without authenticated preCompactionState or verified cryptographic signature,
          // internal mathematical consistency alone cannot prove continuity relative to pre-compaction state.
          compactGuardResult = {
            valid: false,
            error: 'Compacted state envelope lacks authoritative integrity basis: must carry either verified cryptographic signature or authenticated preCompactionState (R05-B05)',
            status: 'UNCHECKABLE',
            envelope: env
          };
        }
      }
    } else if (!compactGuardResult && isCompactedSessionEffective && !env) {
      compactGuardResult = {
        valid: false,
        error: 'Mandatory compacted audit state envelope missing in compacted session (F06)',
        status: 'UNCHECKABLE'
      };
    }
  }
  const validIntents = ['DISCOVERY', 'VALIDATION', 'REGRESSION'];
  const safeAuditIntent = validIntents.includes(String(auditIntent).toUpperCase())
    ? String(auditIntent).toUpperCase()
    : 'DISCOVERY';
  const safeTargetProfile = targetProfile || threatModel?.targetProfile?.primary || threatModel?.targetProfile || 'web-api';
  const safeModelProvenance = {
    modelProvider: modelProvenance?.modelProvider || 'antigravity-orchestrator',
    modelIdentifier: modelProvenance?.modelIdentifier || 'unknown',
    executionDate: new Date().toISOString(),
    toolVersion: TOOL_VERSION,
    toolRevision: effectiveToolProvenance.toolRevision,
    toolIntegrityDigest: effectiveToolProvenance.toolIntegrityDigest,
    promptContractVersion: '1.0.0',
    systemPromptIntegrity: modelProvenance?.systemPromptIntegrity || 'UNKNOWN'
  };
  const safeMatrixInput = Array.isArray(discoveryMatrix) ? discoveryMatrix : [];
  let safeMatrix = safeMatrixInput;
  if (safeMatrix.length === 0 && Array.isArray(cloudflareCoverage?.discoveryMatrix) && cloudflareCoverage.discoveryMatrix.length > 0) {
    const testVal = validateDiscoveryMatrix(cloudflareCoverage.discoveryMatrix, safeRepoRoot);
    if (testVal.valid) {
      safeMatrix = cloudflareCoverage.discoveryMatrix;
    }
  }
  const matrixValidation = safeMatrix.length > 0 ? validateDiscoveryMatrix(safeMatrix, safeRepoRoot) : { valid: true };

  // 1. Coverage Reconciliation against real repoRoot
  let coverageReconciliation;
  let coverageStatus;
  let coverageMode;

  if (cloudflareCoverage && !manifest) {
    const isComplete = cloudflareCoverage.coverageStatus === 'COMPLETE';
    coverageStatus = isComplete ? 'COMPLETE' : 'COVERAGE_PARTIAL';
    coverageMode = 'cloudflare';
    coverageReconciliation = {
      valid: isComplete,
      status: coverageStatus,
      mode: 'cloudflare',
      error: isComplete ? null : (cloudflareCoverage.summary?.reason || 'Cloudflare coverage is partial under Presumption of Non-Pass.'),
      partialUnits: cloudflareCoverage.partialUnits || []
    };
  } else {
    coverageReconciliation = reconcileCoverage(manifest, safeRepoRoot);
    coverageStatus = coverageReconciliation.status;
    coverageMode = coverageReconciliation.mode;

    if (cloudflareCoverage) {
      if (cloudflareCoverage.coverageStatus !== 'COMPLETE' || cloudflareCoverage.canDeclareClean === false) {
        coverageStatus = 'COVERAGE_PARTIAL';
        coverageReconciliation.valid = false;
        coverageReconciliation.status = 'COVERAGE_PARTIAL';
        coverageReconciliation.error = cloudflareCoverage.summary?.reason || 'Cloudflare coverage ledger contains partial or deferred units.';
      }
    }
  }

  if (expectedMode && coverageMode !== expectedMode) {
    coverageStatus = 'PARTIAL';
  }
  if (!safeRepoRoot || !fs.existsSync(path.resolve(safeRepoRoot))) {
    coverageStatus = 'UNCHECKABLE';
  }




  // 2. Process Candidates into Canonical Findings
  const canonicalFindings = [];

  for (let i = 0; i < candidates.length; i++) {
    const raw = { ...candidates[i] };
    const candidateId = raw.id || `SEC-${String(i + 1).padStart(3, '0')}`;
    raw.id = candidateId;
    const ruleId = raw.ruleId || 'SEC-VULN';

    // Strip untrusted authority self-assertions from candidate ingress
    delete raw.consensus;
    delete raw.sourceVerified;
    delete raw.dataflowVerified;
    delete raw.pocSyntacticDemonstrated;
    delete raw.isSingleCandidate;
    delete raw.mitigationProofLine;
    delete raw.mitigationReason;
    // R8-F03-01: Untrusted candidate cannot self-assert execution nonce authority
    const candidateClaimedNonce = raw.nonce || null;
    delete raw.nonce;
    if (candidateClaimedNonce && effectiveNonce && candidateClaimedNonce !== effectiveNonce) {
      raw.nonce = candidateClaimedNonce; // Retain mismatch for deterministic fail-closed check
    }

    // Sanitize attackPath location types: candidates cannot self-assert preimage/artifact types
    if (raw.attackPath && typeof raw.attackPath === 'object') {
      if (raw.attackPath.source && typeof raw.attackPath.source === 'object') delete raw.attackPath.source.locationType;
      if (raw.attackPath.sink && typeof raw.attackPath.sink === 'object') delete raw.attackPath.sink.locationType;
      if (Array.isArray(raw.attackPath.steps)) {
        for (const s of raw.attackPath.steps) {
          if (s && typeof s === 'object') delete s.locationType;
        }
      }
    }

    // If attackPath is supplied, validate schema and detect proof gaps
    if (raw.attackPath && typeof raw.attackPath === 'object') {
      const apVal = validateAttackPath(raw.attackPath, safeRepoRoot);
      if (!apVal.valid) {
        raw.proofGaps = raw.proofGaps || [];
        raw.proofGaps.push({ target: 'attackPath', unprovenProperty: apVal.error });
      } else {
        const gapCheck = detectProofGaps(raw.attackPath);
        if (gapCheck.hasGaps) {
          raw.proofGaps = raw.proofGaps || [];
          raw.proofGaps.push(...gapCheck.proofGaps);
        }
      }
    }


    // Target containment check
    const rawUri = raw.location?.uri || raw.location?.path || 'unknown';
    const pathContained = isPathContained(safeRepoRoot, rawUri);
    const normalizedRelativeUri = pathContained ? normalizeUri(safeRepoRoot, rawUri) : 'invalid_path_escaped';

    const startLine = Number(raw.location?.startLine) >= 1 ? Number(raw.location?.startLine) : 1;
    const endLine = Number(raw.location?.endLine) >= startLine ? Number(raw.location?.endLine) : startLine;

    // Evidence Sufficiency (Internal Heuristic)
    const rigor = calculateEvidenceSufficiency(raw.rigorMetrics);

    // Check for IMPACT lens calibration (strictly validating candidate identity, lens, and nonce)
    const expectedCandidateNonce = effectiveNonce || candidateClaimedNonce || null;
    const candidateVotes = safeVotes.filter(v => {
      if (!v || (v.findingId !== raw.id && v.findingId !== candidateId)) return false;
      return validateBallot(v, raw, { expectedNonce: expectedCandidateNonce }).valid;
    });
    const impactVote = candidateVotes.find(v => v.lens && String(v.lens).toUpperCase() === 'IMPACT');

    // CVSS v4 Validation (calibrated by impact verifier if present)
    const cvss = validateCvssV4((impactVote && impactVote.cvssV4Vector) ? { vector: impactVote.cvssV4Vector } : raw.cvssV4);



    // Check if this is a credential/secret finding
    const isCredentialFinding = /secret|credential|cwe-798|token|password|api[_-]?key/i.test(ruleId) ||
      /secret|credential|token|password|api[_-]?key/i.test(raw.title || '');

    // Secret Redaction & Sanitization
    const rawSnippet = raw.location?.lineSnippet || '';
    const sanitizedSnippet = isCredentialFinding
      ? '[Line snippet suppressed for credential finding]'
      : sanitizeCodeSnippet(redactSecrets(rawSnippet));

    const lineHash = computeLineHash(rawSnippet);

    const titleRedacted = redactSecrets(raw.title || `Security finding in ${normalizedRelativeUri}`);
    const descRedacted = redactSecrets(raw.description || titleRedacted);

    // Disposition Derivation
    let dispositionResult;
    if (!pathContained) {
      dispositionResult = {
        disposition: 'DEFERRED',
        mappedVerdict: 'NEEDS_MANUAL_REVIEW',
        reason: 'Path escapes repository root via traversal sequence',
        votesSummary: { total: 0, supports: 0, refutes: 0, unanimous: false }
      };
    } else {
      const dispositionOptions = {
        enforceThreeLens: true,
        auditIntent: safeAuditIntent,
        modelProvenance: safeModelProvenance,
        modelEffort: raw.modelEffort || raw.effort || modelProvenance?.effort,
        nonce: effectiveNonce || null,
        expectedNonce: effectiveNonce || null
      };
      dispositionResult = deriveFinalDisposition(raw, safeVotes, rigor, safeRepoRoot, dispositionOptions);
    }



    // Confidence Clamp
    const confidence = clampConfidence(
      dispositionResult.disposition,
      dispositionResult.votesSummary,
      raw.confidence
    );

    // Severity determination (calibrated by impact verifier if available)
    let severity = 'UNRATED';
    if (cvss.valid && cvss.severity && cvss.severity !== 'UNRATED') {
      severity = cvss.severity;
    } else if (impactVote && impactVote.calibratedSeverity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(String(impactVote.calibratedSeverity).toUpperCase())) {
      severity = String(impactVote.calibratedSeverity).toUpperCase();
    } else if (raw.severity && ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].includes(String(raw.severity).toUpperCase())) {
      severity = String(raw.severity).toUpperCase();
    } else {
      severity = 'UNRATED';
    }

    const locationFingerprint = computeFindingFingerprint(ruleId, normalizedRelativeUri, startLine);
    const sinkSymbol = raw.symbol || raw.sinkSymbol || raw.sink?.symbol || '';
    const sinkKind = raw.sinkKind || raw.sink?.kind || '';
    const comp = raw.component || '';
    const fam = raw.family || '';
    const authoritativeLineageId = computeLineageFingerprint({
      ruleId,
      uri: normalizedRelativeUri,
      component: comp,
      family: fam,
      sinkKind,
      symbol: sinkSymbol
    });

    const lineageRes = validateFindingLineage(raw.lineage);
    let finalDisposition = dispositionResult.disposition;
    let finalVerdict = dispositionResult.mappedVerdict;
    let finalReason = dispositionResult.reason;

    if (raw.lineage && !lineageRes.valid) {
      finalDisposition = 'DEFERRED';
      finalVerdict = 'NEEDS_MANUAL_REVIEW';
      finalReason = `Lineage validation failure: ${lineageRes.error}`;
    }

    // R4-P2-01: Formal Risk Acceptance / Waiver Workflow
    let riskAcceptanceRecord = null;
    const safeWaivers = Array.isArray(waivers) ? waivers : [];
    const matchedWaiver = raw.riskAcceptance || safeWaivers.find(w => w && (w.findingLineageId === authoritativeLineageId || w.findingLineageId === raw.id || w.findingLineageId === candidateId));
    if (matchedWaiver) {
      const waiverVal = validateRiskAcceptance(matchedWaiver, authoritativeLineageId, candidateId);
      if (waiverVal.valid) {
        finalDisposition = 'ACCEPTED_RISK';
        finalVerdict = 'ACCEPTED_RISK';
        finalReason = `Risk accepted: ${matchedWaiver.reason} (by ${matchedWaiver.acceptedBy} until ${matchedWaiver.expiresAt})`;
        riskAcceptanceRecord = matchedWaiver;
      }
    }

    // R2-P0-11: Finding Type Calibration (VULNERABILITY, HARDENING, INFORMATIONAL)
    const typeRes = validateFindingType(raw.findingType, ruleId, raw.title);
    const safeFindingType = typeRes.findingType;

    // R2-P0-12: Safe Defensive Proof Policy Check
    const rawProof = [
      raw.proof,
      typeof raw.attackPath === 'string' ? raw.attackPath : JSON.stringify(raw.attackPath || ''),
      raw.evidence,
      raw.poc
    ].filter(Boolean).join('\n');
    const proofRes = validateSafeProof(rawProof, raw.proofKind || 'STATIC_TRACE');
    const safeProofKind = proofRes.proofKind;

    if (!proofRes.valid) {
      finalDisposition = 'DEFERRED';
      finalVerdict = 'NEEDS_MANUAL_REVIEW';
      finalReason = proofRes.error;
    }

    // R2-P0-11: Hardening / Informational findings cannot be elevated to CRITICAL or HIGH vulnerability
    let finalSeverity = severity;
    if (safeFindingType !== 'VULNERABILITY' && ['CRITICAL', 'HIGH'].includes(finalSeverity)) {
      finalSeverity = 'LOW';
    }

    const resolvedLineage = {
      ...lineageRes.lineage,
      lineageId: authoritativeLineageId
    };

    const authoritativeSufficiency = dispositionResult.authoritativeRigor || rigor;

    // R2-P1-01 Standards Mapping & R2-P1-02 Security Property
    const standardsTaxonomy = resolveStandardsMapping(ruleId, safeTargetProfile);
    const securityProperty = inferSecurityProperty(ruleId, titleRedacted, raw.securityProperty || standardsTaxonomy.securityProperty);

    // R2-P1-10 Failure Taxonomy Reason Code
    const reasonCode = deriveReasonCode(finalDisposition, finalReason, proofRes.valid, coverageStatus);

    // R2-P1-04 Evidence Snapshot
    const evidenceSnapshot = computeEvidenceSnapshot(safeRepoRoot, normalizedRelativeUri, startLine);

    // R2-P2-06 Defect Management (NIST SSDF RV.3 / SAMM)
    const defectManagement = inferDefectManagement(ruleId, titleRedacted, securityProperty, standardsTaxonomy);

    canonicalFindings.push({
      id: candidateId,
      ruleId,
      title: titleRedacted,
      description: descRedacted,
      disposition: finalDisposition,
      verdict: finalVerdict,
      dispositionReason: finalReason,
      reasonCode,
      severity: finalSeverity,
      findingType: safeFindingType,
      proofKind: safeProofKind,
      securityProperty,
      taxonomy: standardsTaxonomy,
      defectManagement,
      modelProvenance: safeModelProvenance,
      confidenceScore: confidence.score,
      confidenceLevel: confidence.level,
      location: {
        uri: normalizedRelativeUri,
        startLine,
        endLine,
        lineSnippet: sanitizedSnippet,
        lineHash
      },
      evidenceHash: evidenceSnapshot.lineHash,
      blobHash: evidenceSnapshot.blobHash,
      cvssV4: cvss.valid ? { vector: cvss.vector, score: cvss.score, severity: cvss.severity } : null,
      evidenceSufficiency: authoritativeSufficiency,
      rigor: authoritativeSufficiency,
      consensus: dispositionResult.votesSummary || {
        totalVotes: 0,
        unanimous: false,
        minorityEscalated: false
      },
      fingerprint: locationFingerprint,
      locationFingerprint,
      lineageId: authoritativeLineageId,
      lineage: resolvedLineage,
      tags: raw.tags || [],
      proofGaps: Array.isArray(raw.proofGaps) ? raw.proofGaps : (dispositionResult.proofGaps || []),
      attackPath: raw.attackPath || null,
      ...(riskAcceptanceRecord ? { riskAcceptance: riskAcceptanceRecord } : {})
    });
  }


  // 3. Summary Statistics
  const confirmedCount = canonicalFindings.filter(f => f.disposition === 'REPORTABLE' && (f.findingType === 'VULNERABILITY' || !f.findingType)).length;
  const hardeningCount = canonicalFindings.filter(f => f.findingType === 'HARDENING').length;
  const informationalCount = canonicalFindings.filter(f => f.findingType === 'INFORMATIONAL').length;
  const deferredCount = canonicalFindings.filter(f => f.disposition === 'DEFERRED').length;
  const suppressedCount = canonicalFindings.filter(f => f.disposition === 'SUPPRESSED').length;
  const acceptedRiskCount = canonicalFindings.filter(f => f.disposition === 'ACCEPTED_RISK').length;

  // R11-P0-01 & R11-P1-01: Matrix completion authority & critical zero second opinion
  const unresolvedMatrixCells = safeMatrix.filter(c =>
    ['PENDING', 'PENDING_DISCOVERY', 'PENDING_SECOND_OPINION', 'UNRESOLVED'].includes(c.status)
  );

  const unconfirmedCriticalZeros = safeMatrix.filter(c =>
    (c.criticality === 'critical' || c.isCritical === true) &&
    c.status === 'REVIEWED_NO_CANDIDATE'
  );

  const hasUnresolvedCells = unresolvedMatrixCells.length > 0;
  const hasUnconfirmedCriticalZeros = unconfirmedCriticalZeros.length > 0;

  // In DISCOVERY mode, matrix is mandatory for clean. In REGRESSION mode, if a matrix is provided, it must also be complete.
  const isMatrixComplete = safeMatrix.length > 0
    ? (matrixValidation.valid && !hasUnresolvedCells && !hasUnconfirmedCriticalZeros)
    : (safeAuditIntent === 'REGRESSION');

  let effectiveManifest = manifest ? { ...manifest } : null;
  if (!effectiveManifest && cloudflareCoverage) {
    effectiveManifest = {
      schemaVersion: '1.0.0',
      mode: 'cloudflare',
      generatedAt: new Date().toISOString(),
      complete: cloudflareCoverage.coverageStatus === 'COMPLETE',
      coverageStatus: cloudflareCoverage.coverageStatus,
      canDeclareClean: cloudflareCoverage.canDeclareClean,
      units: cloudflareCoverage.summary?.totalUnits || 0,
      entries: []
    };
  }

  // R10-P0-01 & R11-P0-01: Execution stages accounting under Default-Deny.
  // Spoofed stages are strictly rejected: every claimed stage must be verified by physical artifacts.
  const claimedStages = Array.isArray(executedStages) ? new Set(executedStages) : null;
  const safeExecutedStages = ['FINALIZATION'];

  if ((!claimedStages || claimedStages.has('INVENTORY')) && effectiveManifest) {
    safeExecutedStages.push('INVENTORY');
  }
  if ((!claimedStages || claimedStages.has('THREAT_MODELING')) && threatModel && validateThreatModel(threatModel, safeRepoRoot || process.cwd()).valid) {
    safeExecutedStages.push('THREAT_MODELING');
  }
  if ((!claimedStages || claimedStages.has('DISCOVERY_MATRIX')) && isMatrixComplete && safeMatrix.length > 0) {
    safeExecutedStages.push('DISCOVERY_MATRIX');
  }
  if ((!claimedStages || claimedStages.has('VERIFICATION_PANEL')) && (safeVotes.length > 0 || canonicalFindings.length === 0)) {
    safeExecutedStages.push('VERIFICATION_PANEL');
  }

  // R5-P0-01: Context Preparation & Pre-Context Secret Protection Preflight
  const effectiveContextPrep = contextPrep || prepareReviewContext(safeRepoRoot || process.cwd());

  // R5-P1-01 / R6-P1-01 / R6-P1-02: Tool Self-Integrity Verification Preflight (explicit opt-in only)
  const toolIntegrity = verifyToolSelfIntegrity(
    toolRoot,
    safeRepoRoot || process.cwd(),
    { allowSelfAudit: Boolean(allowSelfAudit) }
  );

  const effectiveShadowRoot = shadowRoot || contextPrep?.contextRoot || null;
  const manifestDigest = contextPrep?.manifest?.manifestDigest || null;
  const telemetryVerification = verifyGuardTelemetry({
    telemetryPath,
    artifactDirectoryPath,
    shadowRoot: effectiveShadowRoot,
    manifestDigest,
    conversationId,
    scanStartedAt: (contextPrep || effectiveContextPrep)?.manifest?.createdAt || (contextPrep || effectiveContextPrep)?.manifest?.generatedAt || null
  });
  const hasRuntimeGuardTelemetry = telemetryVerification.verified;

  let effectiveContextIsolation;
  if (contextIsolation && typeof contextIsolation === 'object') {
    if (contextIsolation.status === 'OBSERVED' && !hasRuntimeGuardTelemetry) {
      effectiveContextIsolation = {
        ...contextIsolation,
        status: 'MANDATED',
        pipeline: 'MANDATED_SHADOW_CONTEXT_PIPELINE',
        attestationWarning: `OBSERVED status claimed but unverified: ${telemetryVerification.reason}`
      };
    } else {
      effectiveContextIsolation = {
        ...contextIsolation,
        guardTelemetry: hasRuntimeGuardTelemetry ? {
          source: telemetryVerification.telemetrySource,
          eventsCount: telemetryVerification.eventsCount,
          manifestDigest: telemetryVerification.manifestDigest
        } : null
      };
    }
  } else {
    effectiveContextIsolation = {
      status: hasRuntimeGuardTelemetry ? 'OBSERVED' : 'MANDATED',
      pipeline: hasRuntimeGuardTelemetry ? 'OBSERVED_SHADOW_CONTEXT_RUNTIME_GUARD' : 'MANDATED_SHADOW_CONTEXT_PIPELINE',
      shadowContextRoot: effectiveContextPrep?.contextRoot || 'scratch/context',
      tokenizedFilesCount: effectiveContextPrep?.manifest?.tokenizedFilesCount || 0,
      totalSecretsTokenized: effectiveContextPrep?.manifest?.totalSecretsTokenized || 0,
      guardTelemetry: hasRuntimeGuardTelemetry ? {
        source: telemetryVerification.telemetrySource,
        eventsCount: telemetryVerification.eventsCount,
        manifestDigest: telemetryVerification.manifestDigest
      } : null
    };
  }

  // R6-P1-03 & R11-P1-02: Truthful Execution & Capabilities Attestation (no fake delegationObserved on zero candidates)
  const execution = buildExecutionAttestation({
    repoRoot: safeRepoRoot || process.cwd(),
    target: {
      repositoryUri: safeRepoRoot || process.cwd(),
      revision: provenance?.commitSha || 'HEAD'
    },
    auditIntent: safeAuditIntent,
    executedStages: safeExecutedStages,
    failedStages: [],
    coverageComplete: coverageStatus === 'COMPLETE',
    delegationObserved: Boolean(safeVotes.length > 0),
    zeroCandidates: canonicalFindings.length === 0,
    canonicalFindingsCount: canonicalFindings.length,
    toolProvenance: effectiveToolProvenance,
    capabilities: capabilities || {
      required: ['repository.read'],
      observed: [],
      forbidden: ['filesystem.write', 'process.execute', 'network.external'],
      status: 'DECLARED',
      attestationConfidence: 'DECLARED',
      observationSource: 'agent-manifest-declaration'
    },
    contextIsolation: effectiveContextIsolation
  });

  // R11-P0-02: Context Drift baseline check and fail-closed enforcement (no silent swallow, no const reassignment)
  const projectContextRes = loadProjectSecurityContext(safeRepoRoot || process.cwd());
  const hasConfirmedProjectContext = (projectContextRes.status === 'CONFIRMED' && threatModel?.contextStatus !== 'GENERIC_SECURITY_REVIEW');

  let contextDrift = null;
  let contextDriftEvaluationError = null;
  const loadedBaseline = loadBaselineContext(safeRepoRoot || process.cwd());

  if (loadedBaseline.exists && loadedBaseline.baseline && projectContextRes.context) {
    try {
      contextDrift = detectContextDrift(projectContextRes.context, loadedBaseline.baseline);
    } catch (err) {
      contextDriftEvaluationError = err;
      console.error(`[CONTEXT-DRIFT] Critical evaluation error: ${err.message}`);
    }
  }

  const driftBlocksClean = (safeAuditIntent === 'REGRESSION') && (
    contextDriftEvaluationError !== null ||
    (contextDrift && contextDrift.hasDrift && ['THREAT_MODEL_REVIEW_REQUIRED', 'CONTEXT_DRIFT'].includes(contextDrift.status))
  );

  // R6-P0-01 & R11-P0-01: Six-Pillar Assurance Gates (extended with M54-P2-F06 compactGate & R08-B06)
  // In compacted sessions, continuity requires VERIFIED status under Default-Deny; UNAUTHENTICATED fails compactGate
  const compactGate = !isCompactedSessionEffective
    ? (!compactGuardResult || compactGuardResult.valid === true)
    : Boolean(compactGuardResult && compactGuardResult.valid === true && compactGuardResult.status === 'VERIFIED');
  const coverageGate = (coverageStatus === 'COMPLETE') && compactGate;
  const matrixGate = Boolean(matrixValidation.valid && isMatrixComplete);
  const findingGate = (confirmedCount === 0 && deferredCount === 0 && acceptedRiskCount === 0);
  const contextGate = Boolean(
    effectiveContextPrep
    && effectiveContextPrep.success === true
    && effectiveContextPrep.manifest
    && typeof effectiveContextPrep.manifest.preparedFilesCount === 'number'
    && typeof effectiveContextPrep.manifest.scannedFilesCount === 'number'
    && effectiveContextPrep.manifest.preparedFilesCount >= effectiveContextPrep.manifest.scannedFilesCount
    && !effectiveContextPrep.error
  );
  const executionGate = Boolean(
    execution
    && (execution.verdict === 'COMPLETE_VERIFIED' || execution.verdict === 'COMPLETE_DECLARED')
  );
  const toolIntegrityGate = Boolean(
    toolIntegrity
    && toolIntegrity.valid === true
    && (toolIntegrity.status === 'CONFORMANT' || toolIntegrity.status === 'SELF_AUDIT_MODE')
  );

  const baseCleanEligible = Boolean(
    coverageGate
    && matrixGate
    && findingGate
    && contextGate
    && executionGate
    && toolIntegrityGate
    && compactGate
  );

  let canDeclareClean = Boolean(baseCleanEligible && !driftBlocksClean);

  let assuranceLabel = 'NON_CLEAN';
  if (!compactGate) {
    assuranceLabel = 'UNCHECKABLE';
    coverageStatus = 'UNCHECKABLE';
    canDeclareClean = false;
  } else if (canDeclareClean) {
    if (toolIntegrity.status === 'SELF_AUDIT_MODE') {
      assuranceLabel = 'SELF_AUDIT_BOUNDED_CLEAN';
    } else if (!hasConfirmedProjectContext) {
      // R9-T10 & R01-F08: Project Security Context absent -> assurance CONTEXT_LIMITED
      // Under Default-Deny, CONTEXT_LIMITED cannot declare clean (preventing downstream misinterpretation as Clean Attestation)
      assuranceLabel = 'CONTEXT_LIMITED';
      canDeclareClean = false;
    } else {
      // R9-T11: confirmed Project Security Context -> eligible for BOUNDED_CLEAN
      assuranceLabel = 'BOUNDED_CLEAN';
    }
  } else {
    if (driftBlocksClean) {
      if (contextDriftEvaluationError) {
        assuranceLabel = 'CONTEXT_DRIFT_EVALUATION_FAILED';
      } else if (contextDrift?.status === 'THREAT_MODEL_REVIEW_REQUIRED') {
        assuranceLabel = 'THREAT_MODEL_REVIEW_REQUIRED';
      } else if (contextDrift?.status === 'CONTEXT_DRIFT') {
        assuranceLabel = 'CONTEXT_DRIFT';
      }
    }
  }

  // R9-P0-01 & R9-P1-05: Update scan-manifest lifecycle & identity atomically
  let updatedManifest = effectiveManifest;
  const effectiveScanRunId = scanRunId || effectiveManifest?.scanRunId || `SCAN-${crypto.randomBytes(4).toString('hex')}`;
  effectiveNonce = effectiveNonce || (isManifestRunBound ? (effectiveManifest?.nonce || effectiveManifest?.taskCorrelationNonce || null) : null);
  let projectId = null;
  // R10-P1-05: Identity precedence: USER_CONFIRMED Project Context > manifest.projectId > package.json > directory basename
  if (projectContextRes.context?.project?.projectId && projectContextRes.context.project.source !== 'SUGGESTED') {
    projectId = projectContextRes.context.project.projectId;
  } else if (effectiveManifest?.projectId) {
    projectId = effectiveManifest.projectId;
  } else {
    try {
      const pkgPath = path.join(path.resolve(safeRepoRoot || process.cwd()), 'package.json');
      if (fs.existsSync(pkgPath)) {
        const p = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
        if (p.name) projectId = p.name;
      }
    } catch {}
  }
  if (!projectId) {
    projectId = path.basename(path.resolve(safeRepoRoot || process.cwd()));
  }

  if (effectiveManifest && typeof effectiveManifest === 'object') {
    effectiveManifest.complete = true;
    effectiveManifest.completedAt = new Date().toISOString();
    effectiveManifest.finalVerdict = assuranceLabel;
    effectiveManifest.canDeclareClean = canDeclareClean;
    effectiveManifest.auditIntent = safeAuditIntent;
    effectiveManifest.coverageStatus = coverageStatus;
    effectiveManifest.scanRunId = effectiveScanRunId;
    if (effectiveNonce) {
      effectiveManifest.nonce = effectiveNonce;
      effectiveManifest.taskCorrelationNonce = effectiveNonce;
    } else if (!isManifestRunBound) {
      delete effectiveManifest.nonce;
      delete effectiveManifest.taskCorrelationNonce;
    }
    effectiveManifest.projectId = projectId;
    effectiveManifest.findingCounts = {
      reportable: confirmedCount,
      deferred: deferredCount,
      acceptedRisk: acceptedRiskCount,
      hardening: hardeningCount,
      informational: informationalCount,
      suppressed: suppressedCount
    };
    updatedManifest = effectiveManifest;
  }

  const dependencyBoundary = detectDependencyBoundary(safeRepoRoot || process.cwd());

  const baseline = buildAuditBaseline({
    repoRoot: safeRepoRoot || process.cwd(),
    targetRevision: provenance?.commitSha || 'HEAD',
    canonicalFindings,
    threatModel,
    manifest: effectiveManifest,
    provenance,
    modelProvider: safeModelProvenance.modelProvider,
    modelIdentifier: safeModelProvenance.modelIdentifier,
    modelSnapshotImmutable: Boolean(modelProvenance?.modelSnapshotImmutable),
    toolProvenance: effectiveToolProvenance
  });

  const summary = {
    totalCandidates: canonicalFindings.length,
    confirmedCount,
    hardeningCount,
    informationalCount,
    deferredCount,
    suppressedCount,
    acceptedRiskCount,
    findingCounts: {
      reportable: confirmedCount,
      hardening: hardeningCount,
      informational: informationalCount,
      deferred: deferredCount,
      suppressed: suppressedCount,
      acceptedRisk: acceptedRiskCount
    },
    coverageStatus,
    manifestValid: coverageReconciliation.valid,
    coverageMode,
    canDeclareClean,
    auditIntent: safeAuditIntent,
    cleanAssuranceBounded: canDeclareClean,
    assuranceLabel,
    gates: {
      coverageGate,
      matrixGate,
      findingGate,
      contextGate,
      executionGate,
      toolIntegrityGate,
      compactGate
    },
    compactGuard: compactGuardResult || { valid: true, status: 'NOT_APPLICABLE' },
    discoveryMatrixValid: matrixValidation.valid,
    discoveryCellsSummary: {
      total: safeMatrix.length,
      applicableTotal: safeMatrix.filter(c => c.status !== 'NOT_APPLICABLE').length,
      reviewedNoCandidate: safeMatrix.filter(c => c.status === 'REVIEWED_NO_CANDIDATE').length,
      confirmedZero: safeMatrix.filter(c => c.status === 'CONFIRMED_ZERO_CANDIDATE').length,
      candidates: safeMatrix.filter(c => c.status === 'CANDIDATE').length,
      notApplicable: safeMatrix.filter(c => c.status === 'NOT_APPLICABLE').length,
      pending: safeMatrix.filter(c => ['PENDING', 'PENDING_DISCOVERY'].includes(c.status)).length,
      pendingSecondOpinion: safeMatrix.filter(c => c.status === 'PENDING_SECOND_OPINION').length,
      unresolved: safeMatrix.filter(c => c.status === 'UNRESOLVED').length,
      unconfirmedCriticalZeros: unconfirmedCriticalZeros.length,
      completionRate: safeMatrix.length > 0
        ? Number((((safeMatrix.length - unresolvedMatrixCells.length - unconfirmedCriticalZeros.length) / safeMatrix.length) * 100).toFixed(1))
        : 100.0,
      isComplete: isMatrixComplete
    },
    contextDrift,
    execution,
    dependencyBoundary,
    baseline,
    modelProvenance: safeModelProvenance,
    toolProvenance: effectiveToolProvenance,
    toolIntegrity,
    contextPreparation: effectiveContextPrep?.manifest || null
  };

  // R10-P1-03: Persist verified baseline to .security-audit/baseline.json upon clean DISCOVERY scan
  if (canDeclareClean && safeAuditIntent === 'DISCOVERY' && fs.existsSync(path.join(safeRepoRoot || process.cwd(), '.security-audit'))) {
    try {
      const baselineData = {
        project: projectContextRes.context?.project || {},
        trustModel: projectContextRes.context?.trustModel || {},
        actors: projectContextRes.context?.actors || [],
        securityProperties: projectContextRes.context?.securityProperties || [],
        projectContextFingerprint: projectContextRes.projectContextFingerprint,
        securityPropertiesFingerprint: projectContextRes.securityPropertiesFingerprint,
        surfaceFingerprint: baseline.surfaceFingerprint,
        threatModelFingerprint: baseline.threatModelFingerprint,
        targetRevision: baseline.targetRevision,
        completedAt: new Date().toISOString(),
        finalVerdict: assuranceLabel
      };
      persistBaselineContext(safeRepoRoot || process.cwd(), baselineData);
    } catch {}
  }

  return {
    summary,
    coverageStatus,
    coverageMode,
    compactGuard: compactGuardResult || { valid: true, status: 'NOT_APPLICABLE' },
    manifest: updatedManifest,
    manifestValidation: coverageReconciliation,
    provenance: provenance || getHardenedGitProvenance(repoRoot),
    canonicalFindings,
    auditIntent: safeAuditIntent,
    discoveryMatrix: safeMatrix,
    baseline,
    modelProvenance: safeModelProvenance,
    toolProvenance: effectiveToolProvenance,
    toolIntegrity,
    contextPreparation: effectiveContextPrep?.manifest || null
  };

}

/**
 * Checks whether an audit run or manifest is authoritative clean (R9-P0-01, R9-T01, R9-T02).
 * Fails closed if scanManifest.complete is false or completedAt is null.
 */
export function isAuthoritativeClean(scanResultOrManifest) {
  if (!scanResultOrManifest) return false;
  const manifest = scanResultOrManifest.manifest || scanResultOrManifest.summary?.scanManifest || scanResultOrManifest;
  if (manifest && typeof manifest === 'object') {
    if (manifest.complete === false) return false;
    if (!manifest.completedAt) return false;
  }
  return Boolean(scanResultOrManifest.canDeclareClean !== undefined ? scanResultOrManifest.canDeclareClean : (scanResultOrManifest.summary ? scanResultOrManifest.summary.canDeclareClean : manifest?.canDeclareClean));
}

/**
 * Computes deterministic hashes across all canonical artifacts (R9-P0-03).
 */
export function computeCanonicalArtifactHashes({
  canonicalResult = null,
  markdownText = null,
  sarifJson = null,
  coverageJson = null,
  threatModelJson = null,
  directoryManifestJson = null,
  canonicalPath = null,
  markdownPath = null,
  sarifPath = null,
  coveragePath = null,
  threatModelPath = null,
  directoryManifestPath = null
} = {}) {
  const readOrData = (data, filePath) => {
    if (data !== null && data !== undefined) return data;
    if (filePath && fs.existsSync(filePath)) {
      try {
        return fs.readFileSync(filePath, 'utf8');
      } catch {}
    }
    return null;
  };

  const hash = (data) => {
    if (!data) return null;
    const str = typeof data === 'string' ? data : JSON.stringify(data);
    return crypto.createHash('sha256').update(str, 'utf8').digest('hex');
  };

  const cRes = readOrData(canonicalResult, canonicalPath);
  const mdTxt = readOrData(markdownText, markdownPath);
  const sarifObj = readOrData(sarifJson, sarifPath);
  const covObj = readOrData(coverageJson, coveragePath);
  const tmObj = readOrData(threatModelJson, threatModelPath);
  const dmObj = readOrData(directoryManifestJson, directoryManifestPath);

  return {
    canonicalResultHash: hash(cRes),
    markdownHash: hash(mdTxt),
    sarifHash: hash(sarifObj),
    coverageHash: hash(covObj),
    threatModelHash: hash(tmObj),
    directoryManifestHash: hash(dmObj)
  };
}

/**
 * Validates cross-format consistency across SARIF, Markdown, scan-manifest, and coverage (R9-P0-03, R9-T05, R9-T06, R9-T07).
 */
export function validateCrossFormatParity({
  sarif,
  markdown,
  scanManifest,
  coverage,
  sarifPath,
  markdownPath,
  manifestPath,
  coveragePath,
  canonicalPath
} = {}) {
  let loadedSarif = sarif;
  let loadedMarkdown = markdown;
  let loadedManifest = scanManifest;
  let loadedCoverage = coverage;

  if (!loadedSarif && sarifPath && fs.existsSync(sarifPath)) {
    try { loadedSarif = JSON.parse(fs.readFileSync(sarifPath, 'utf8')); } catch {}
  }
  if (!loadedMarkdown && markdownPath && fs.existsSync(markdownPath)) {
    try { loadedMarkdown = fs.readFileSync(markdownPath, 'utf8'); } catch {}
  }
  if (!loadedManifest && manifestPath && fs.existsSync(manifestPath)) {
    try { loadedManifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8')); } catch {}
  }
  if (!loadedCoverage && coveragePath && fs.existsSync(coveragePath)) {
    try { loadedCoverage = JSON.parse(fs.readFileSync(coveragePath, 'utf8')); } catch {}
  }

  const errors = [];
  let sarifClean = null;
  let manifestClean = null;
  let mdClean = null;

  if (loadedSarif?.runs?.[0]?.properties?.canDeclareClean !== undefined) {
    sarifClean = Boolean(loadedSarif.runs[0].properties.canDeclareClean);
  }
  if (loadedManifest?.canDeclareClean !== undefined) {
    manifestClean = Boolean(loadedManifest.canDeclareClean);
  }
  if (typeof loadedMarkdown === 'string') {
    if (loadedMarkdown.includes('- **Can Declare Clean**: **true**')) mdClean = true;
    else if (loadedMarkdown.includes('- **Can Declare Clean**: **false**')) mdClean = false;
  }

  // R9-T05: SARIF / Markdown / Manifest verdict mismatch
  if (sarifClean !== null && manifestClean !== null && sarifClean !== manifestClean) {
    errors.push(`Verdict mismatch: SARIF.canDeclareClean (${sarifClean}) !== scanManifest.canDeclareClean (${manifestClean})`);
  }
  if (sarifClean !== null && mdClean !== null && sarifClean !== mdClean) {
    errors.push(`Verdict mismatch: SARIF.canDeclareClean (${sarifClean}) !== Markdown.canDeclareClean (${mdClean})`);
  }
  if (manifestClean !== null && mdClean !== null && manifestClean !== mdClean) {
    errors.push(`Verdict mismatch: scanManifest.canDeclareClean (${manifestClean}) !== Markdown.canDeclareClean (${mdClean})`);
  }

  // R9-T06: Finding count mismatch
  if (loadedSarif?.runs?.[0]?.properties?.findingCounts && loadedManifest?.findingCounts) {
    const sfc = loadedSarif.runs[0].properties.findingCounts;
    const mfc = loadedManifest.findingCounts;
    if (sfc.reportable !== mfc.reportable || sfc.deferred !== mfc.deferred) {
      errors.push(`Finding count mismatch: SARIF (${JSON.stringify(sfc)}) !== Manifest (${JSON.stringify(mfc)})`);
    }
  }

  if (loadedSarif?.runs?.[0]?.results && typeof loadedMarkdown === 'string') {
    const sarifCount = loadedSarif.runs[0].results.filter(
      r => !r.properties?.disposition || r.properties.disposition === 'REPORTABLE'
    ).length;
    const match = loadedMarkdown.match(/- \*\*Confirmed Vulnerabilities \(Reportable\)\*\*:\s*(\d+)/);
    if (match) {
      const mdCount = parseInt(match[1], 10);
      if (sarifCount !== mdCount) {
        errors.push(`Finding count mismatch: SARIF results (${sarifCount}) !== Markdown confirmed (${mdCount})`);
      }
    }
  }

  // R9-T07: Coverage status mismatch
  let sarifCov = loadedSarif?.runs?.[0]?.properties?.coverageStatus;
  let manifestCov = loadedManifest?.coverageStatus;
  let covCov = loadedCoverage?.coverageStatus;
  if (sarifCov && manifestCov && sarifCov !== manifestCov) {
    errors.push(`Coverage mismatch: SARIF (${sarifCov}) !== Manifest (${manifestCov})`);
  }
  if (sarifCov && covCov && sarifCov !== covCov) {
    errors.push(`Coverage mismatch: SARIF (${sarifCov}) !== Coverage JSON (${covCov})`);
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

/**
 * Evaluates selective second opinion for critical zero-candidate discovery cells (R10-P1-06).
 */
export function evaluateSecondOpinion({ cell, firstReview, secondReview }) {
  if (!cell) {
    return { valid: false, status: 'INVALID_CELL', error: 'Cell must be provided' };
  }
  const isCritical = cell.criticality === 'critical' || cell.isCritical === true;
  const firstIsZero = firstReview && (firstReview.status === 'REVIEWED_NO_CANDIDATE' || (firstReview.candidates && firstReview.candidates.length === 0));

  if (!isCritical || !firstIsZero) {
    return {
      status: 'NOT_REQUIRED',
      required: false,
      agreement: true,
      escalation: false,
      verdict: firstReview?.status || cell.status
    };
  }

  if (!secondReview) {
    return {
      status: 'PENDING_SECOND_OPINION',
      required: true,
      agreement: false,
      escalation: false,
      verdict: 'PENDING_SECOND_OPINION'
    };
  }

  const secondIsZero = secondReview.status === 'REVIEWED_NO_CANDIDATE' || (secondReview.candidates && secondReview.candidates.length === 0);
  if (secondIsZero) {
    return {
      status: 'CONFIRMED_ZERO_CANDIDATE',
      required: true,
      agreement: true,
      escalation: false,
      verdict: 'CONFIRMED_ZERO_CANDIDATE',
      evidence: [
        ...(Array.isArray(firstReview.reviewedEvidence) ? firstReview.reviewedEvidence : []),
        ...(Array.isArray(secondReview.reviewedEvidence) ? secondReview.reviewedEvidence : [])
      ]
    };
  } else {
    return {
      status: 'ESCALATED_TO_CANDIDATE',
      required: true,
      agreement: false,
      escalation: true,
      verdict: 'CANDIDATE',
      candidates: secondReview.candidates || []
    };
  }
}

/**
 * Maps finding severity to SARIF level and security-severity float.
 */
export function mapSeverityToSarif(severity, cvssScore) {
  const sev = String(severity || '').toUpperCase();
  let level = 'warning';
  let defaultScore = null;

  if (sev === 'CRITICAL') {
    level = 'error';
    defaultScore = '9.5';
  } else if (sev === 'HIGH') {
    level = 'error';
    defaultScore = '8.0';
  } else if (sev === 'MEDIUM') {
    level = 'warning';
    defaultScore = '5.5';
  } else if (sev === 'LOW') {
    level = 'note';
    defaultScore = '2.5';
  } else if (sev === 'UNRATED') {
    level = 'warning';
    defaultScore = null;
  }

  const numericScore = (typeof cvssScore === 'number' && !Number.isNaN(cvssScore))
    ? cvssScore.toFixed(1)
    : defaultScore;

  return { level, securitySeverity: numericScore };
}

/**
 * Validates canonical findings under Default-Deny before rendering.
 * Enforces schema integrity, reapplies secret redaction, and downgrades
 * any self-asserted or unsupported REPORTABLE claims to DEFERRED.
 */
export function validateCanonicalFindings(findings, repoRoot = process.cwd(), options = {}) {
  if (!Array.isArray(findings)) {
    if (findings && typeof findings === 'object' && Array.isArray(findings.canonicalFindings)) {
      findings = findings.canonicalFindings;
    } else {
      return [];
    }
  }

  const validated = [];

  for (const raw of findings) {
    if (!raw || typeof raw !== 'object') continue;

    const id = String(raw.id || raw.findingId || 'SEC-UNKNOWN');
    const ruleId = String(raw.ruleId || 'SEC-VULN');
    const severity = String(raw.severity || 'UNRATED').toUpperCase();

    // Re-apply secret redaction and sanitization across all text fields
    const title = redactSecrets(stripControlAndBidi(String(raw.title || 'Security Finding')));
    const description = redactSecrets(stripControlAndBidi(String(raw.description || '')));
    const uri = raw.location?.uri ? String(raw.location.uri) : 'unknown';
    const startLine = Number(raw.location?.startLine || 1);
    const endLine = Number(raw.location?.endLine || startLine);
    let lineSnippet = raw.location?.lineSnippet ? redactSecrets(stripControlAndBidi(String(raw.location.lineSnippet))) : null;

    // Suppress snippet for secrets
    const isCredential = /(?:secret|credential|token|password|api[_-]?key|cwe-798)/i.test(`${title} ${ruleId} ${id}`);
    if (isCredential) {
      lineSnippet = '[Line snippet suppressed for credential finding]';
    }

    let disposition = String(raw.disposition || 'DEFERRED').toUpperCase();
    let verdict = String(raw.verdict || 'NEEDS_MANUAL_REVIEW').toUpperCase();
    let dispositionReason = redactSecrets(stripControlAndBidi(String(raw.dispositionReason || '')));

    const consensus = (raw.consensus && typeof raw.consensus === 'object') ? raw.consensus : { supports: 0, refutes: 0, totalVotes: 0, unanimous: false };
    const rigor = (raw.rigor && typeof raw.rigor === 'object') ? raw.rigor : { score: 0.0, assuranceLevel: 'NONE' };

    // Default-Deny Invariant: REPORTABLE / CONFIRMED cannot be asserted without quorum, unanimity/supermajority, and rigor
    if (disposition === 'REPORTABLE' || verdict === 'CONFIRMED') {
      const totalVotes = Number(consensus.total !== undefined ? consensus.total : (consensus.totalVotes !== undefined ? consensus.totalVotes : 0));
      const supports = Number(consensus.supports || 0);
      const refutes = Number(consensus.refutes || 0);
      const hasQuorum = supports >= 2 && totalVotes >= 2 && refutes === 0 && (supports === totalVotes || (supports / totalVotes >= 0.66));
      const hasRigor = Number(rigor.score || 0) >= 0.60;
      let fileExists = true;
      if (repoRoot && uri !== 'unknown') {
        const normUri = uri.replace(/\\/g, '/').replace(/^\.\//, '');
        if (normUri.startsWith('..') || normUri.includes('/../') || path.isAbsolute(uri)) {
          fileExists = false;
        } else {
          const fullTarget = path.resolve(repoRoot, normUri);
          const relToRepo = path.relative(repoRoot, fullTarget);
          if (relToRepo.startsWith('..') || path.isAbsolute(relToRepo) || !fs.existsSync(fullTarget)) {
            fileExists = false;
          }
        }
      }

      if (!hasQuorum || !hasRigor || !fileExists) {
        disposition = 'DEFERRED';
        verdict = 'NEEDS_MANUAL_REVIEW';
        dispositionReason = `Presumption of Non-Pass: Canonical finding lacked authoritative verifier quorum (${supports}/${totalVotes}, refutes=${refutes}) or rigor (${rigor.score || 0}).`;
      }
    }

    let validatedCvss = null;
    if (raw.cvssV4 && typeof raw.cvssV4 === 'object') {
      const cvssRes = validateCvssV4(raw.cvssV4);
      if (cvssRes && cvssRes.valid) {
        validatedCvss = {
          vector: cvssRes.vector,
          score: cvssRes.score,
          severity: cvssRes.severity
        };
      }
    }

    const locFingerprint = computeFindingFingerprint(ruleId, uri, startLine);
    const sinkSymbol = raw.symbol || raw.sinkSymbol || raw.sink?.symbol || '';
    const sinkKind = raw.sinkKind || raw.sink?.kind || '';
    const comp = raw.component || '';
    const fam = raw.family || '';
    const linId = computeLineageFingerprint({
      ruleId,
      uri,
      component: comp,
      family: fam,
      sinkKind,
      symbol: sinkSymbol
    });
    const linRes = validateFindingLineage(raw.lineage);

    if (raw.lineage && !linRes.valid) {
      disposition = 'DEFERRED';
      verdict = 'NEEDS_MANUAL_REVIEW';
      dispositionReason = `Presumption of Non-Pass: Invalid finding lineage: ${linRes.error}`;
    }

    // R2-P0-11: Validate findingType
    const typeRes = validateFindingType(raw.findingType, ruleId, title);
    const safeFindingType = typeRes.findingType;

    // R2-P0-12: Validate safe proof
    const rawProof = [
      raw.proof,
      typeof raw.attackPath === 'string' ? raw.attackPath : JSON.stringify(raw.attackPath || ''),
      raw.evidence,
      raw.poc
    ].filter(Boolean).join('\n');
    const proofRes = validateSafeProof(rawProof, raw.proofKind);
    const safeProofKind = proofRes.proofKind;

    if (!proofRes.valid) {
      disposition = 'DEFERRED';
      verdict = 'NEEDS_MANUAL_REVIEW';
      dispositionReason = `Presumption of Non-Pass: ${proofRes.error}`;
    }

    let finalSeverity = severity;
    if (safeFindingType !== 'VULNERABILITY' && ['CRITICAL', 'HIGH'].includes(finalSeverity)) {
      finalSeverity = 'LOW';
    }

    // R2-P1-01 Standards Mapping & R2-P1-02 Security Property
    const safeTargetProfile = options.targetProfile || 'web-api';
    const standardsTaxonomy = resolveStandardsMapping(ruleId, safeTargetProfile);
    const securityProperty = inferSecurityProperty(ruleId, title, raw.securityProperty || standardsTaxonomy.securityProperty);

    // R2-P1-10 Failure Taxonomy Reason Code
    const reasonCode = deriveReasonCode(disposition, dispositionReason, proofRes.valid, 'COMPLETE');

    // R2-P1-04 Evidence Snapshot
    const evidenceSnapshot = computeEvidenceSnapshot(repoRoot, uri, startLine);

    // R2-P2-06 Defect Management & R2-P2-04 Model Provenance
    const defectManagement = raw.defectManagement || inferDefectManagement(ruleId, title, securityProperty, standardsTaxonomy);
    const modelProvenance = raw.modelProvenance || {
      modelProvider: options.modelProvider || 'antigravity-orchestrator',
      modelIdentifier: options.modelIdentifier || 'unknown',
      executionDate: new Date().toISOString(),
      toolVersion: TOOL_VERSION,
      promptContractVersion: '1.0.0',
      systemPromptIntegrity: 'UNKNOWN'
    };

    validated.push({
      ...raw,
      id,
      ruleId,
      severity: finalSeverity,
      findingType: safeFindingType,
      proofKind: safeProofKind,
      securityProperty,
      taxonomy: standardsTaxonomy,
      defectManagement,
      modelProvenance,
      reasonCode,
      title,
      description,
      location: {
        uri,
        startLine,
        endLine,
        lineSnippet,
        lineHash: raw.location?.lineHash || evidenceSnapshot.lineHash || ''
      },
      evidenceHash: raw.evidenceHash || evidenceSnapshot.lineHash,
      blobHash: raw.blobHash || evidenceSnapshot.blobHash,
      confidenceScore: raw.confidenceScore !== undefined ? raw.confidenceScore : 0.5,
      confidenceLevel: raw.confidenceLevel || 'LOW',
      cvssV4: validatedCvss,
      evidenceSufficiency: raw.evidenceSufficiency || raw.rigor || calculateEvidenceSufficiency(raw.rigorMetrics),
      rigor,
      consensus,
      disposition,
      verdict,
      dispositionReason,
      fingerprint: locFingerprint,
      locationFingerprint: locFingerprint,
      lineageId: linId,
      lineage: {
        ...linRes.lineage,
        lineageId: linId
      },
      tags: Array.isArray(raw.tags) ? raw.tags : []
    });
  }

  return validated;
}

/**
 * Renders SARIF 2.1.0 document from canonical findings.
 */
export function renderSarifFromCanonical({
  canonicalFindings = [],
  manifest = null,
  coverageStatus = 'COMPLETE',
  provenance = null,
  repoRoot = process.cwd(),
  auditIntent = 'DISCOVERY',
  canDeclareClean = null,
  executionAttestation = null,
  dependencyBoundary = null,
  assuranceLevel = null,
  findingCounts = null,
  scanRunId = null,
  nonce = null,
  projectId = null,
  toolProvenance = null
} = {}) {
  const effectiveToolProv = toolProvenance || getToolProvenance();
  const safeFindings = validateCanonicalFindings(canonicalFindings, repoRoot);
  const rulesMap = new Map();
  const results = [];

  for (const f of safeFindings) {
    const ruleId = f.ruleId || 'SEC-VULN';
    const cvssScore = f.cvssV4 ? f.cvssV4.score : null;
    const { level, securitySeverity } = mapSeverityToSarif(f.severity, cvssScore);

    if (!rulesMap.has(ruleId)) {
      rulesMap.set(ruleId, {
        id: ruleId,
        name: f.title || ruleId,
        shortDescription: { text: f.title || ruleId },
        fullDescription: { text: f.description || f.title || ruleId },
        properties: {
          'security-severity': securitySeverity,
          cvssV4Vector: f.cvssV4?.vector || null,
          findingType: f.findingType || 'VULNERABILITY',
          tags: ['security', String(f.findingType || 'vulnerability').toLowerCase(), ...(f.tags || [])]
        }
      });
    }

    const ruleIndex = Array.from(rulesMap.keys()).indexOf(ruleId);

    // SARIF result level: error for reportable, warning for deferred and accepted_risk, note for suppressed
    const resultLevel = f.disposition === 'REPORTABLE' ? level : (f.disposition === 'DEFERRED' || f.disposition === 'ACCEPTED_RISK') ? 'warning' : 'note';

    results.push({
      ruleId,
      ruleIndex,
      level: resultLevel,
      message: { text: f.description || f.title || ruleId },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: normalizeUri(repoRoot, f.location.uri),
              uriBaseId: '%SRCROOT%'
            },
            region: {
              startLine: f.location.startLine || 1,
              endLine: f.location.endLine || f.location.startLine || 1
            }
          }
        }
      ],
      partialFingerprints: {
        primaryLocationLineHash: f.location.lineHash,
        stableFingerprint: f.fingerprint,
        locationFingerprint: f.locationFingerprint || f.fingerprint,
        lineageFingerprint: f.lineageId || f.fingerprint
      },
      properties: {
        disposition: f.disposition,
        verdict: f.verdict,
        findingType: f.findingType || 'VULNERABILITY',
        proofKind: f.proofKind || 'STATIC_TRACE',
        confidenceScore: f.confidenceScore,
        confidenceLevel: f.confidenceLevel,
        cvssV4: f.cvssV4,
        evidenceSufficiency: f.evidenceSufficiency || f.rigor,
        rigor: f.rigor,
        fingerprint: f.fingerprint,
        locationFingerprint: f.locationFingerprint || f.fingerprint,
        lineageId: f.lineageId || f.fingerprint,
        lineage: f.lineage || null,
        consensus: f.consensus,
        dispositionReason: f.dispositionReason,
        securityProperty: f.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED',
        taxonomy: f.taxonomy || null,
        defectManagement: f.defectManagement || null,
        modelProvenance: f.modelProvenance || null,
        reasonCode: f.reasonCode || 'EVIDENCE_INCOMPLETE',
        evidenceHash: f.evidenceHash || null,
        ...(f.riskAcceptance ? { riskAcceptance: f.riskAcceptance } : {})
      }
    });
  }

  const run = {
    tool: {
      driver: {
        name: 'AGY Security Audit',
        version: effectiveToolProv.toolVersion || TOOL_VERSION,
        semanticVersion: effectiveToolProv.toolVersion || TOOL_VERSION,
        informationUri: 'https://antigravity.google/docs/security',
        properties: {
          toolRevision: effectiveToolProv.toolRevision,
          toolIntegrityDigest: effectiveToolProv.toolIntegrityDigest,
          toolDirty: effectiveToolProv.toolDirty
        },
        rules: Array.from(rulesMap.values())
      }
    },
    versionControlProvenance: provenance ? [provenance] : [],
    results,
    properties: {
      coverageStatus,
      auditAxiom: 'Presumption of Non-Pass (Default-Deny on Authority Claims)',
      auditIntent: auditIntent || 'DISCOVERY',
      canDeclareClean: (canDeclareClean !== null && canDeclareClean !== undefined)
        ? Boolean(canDeclareClean)
        : (coverageStatus === 'COMPLETE' && safeFindings.filter(f => f.disposition === 'REPORTABLE' && (f.findingType === 'VULNERABILITY' || !f.findingType)).length === 0 && safeFindings.filter(f => f.disposition === 'DEFERRED').length === 0),
      assuranceLevel: assuranceLevel || (canDeclareClean ? 'BOUNDED_CLEAN' : 'NON_CLEAN'),
      findingCounts: findingCounts || {
        reportable: safeFindings.filter(f => f.disposition === 'REPORTABLE' && (f.findingType === 'VULNERABILITY' || !f.findingType)).length,
        deferred: safeFindings.filter(f => f.disposition === 'DEFERRED').length,
        acceptedRisk: safeFindings.filter(f => f.disposition === 'ACCEPTED_RISK').length,
        hardening: safeFindings.filter(f => f.findingType === 'HARDENING').length,
        informational: safeFindings.filter(f => f.findingType === 'INFORMATIONAL').length,
        suppressed: safeFindings.filter(f => f.disposition === 'SUPPRESSED').length
      },
      scanRunId: scanRunId || manifest?.scanRunId || `SCAN-${crypto.randomBytes(4).toString('hex')}`,
      nonce: nonce || manifest?.nonce || manifest?.taskCorrelationNonce || null,
      projectId: projectId || manifest?.projectId || 'security-audit',
      directoryReconciliationManifest: manifest,
      executionAttestation: executionAttestation || buildExecutionAttestation({
        repoRoot,
        auditIntent: auditIntent || 'DISCOVERY',
        coverageComplete: coverageStatus === 'COMPLETE',
        delegationObserved: safeFindings.some(f => f.consensus && f.consensus.total > 0),
        toolProvenance: effectiveToolProv,
        capabilities: {
          required: ['repository.read'],
          observed: [],
          forbidden: ['filesystem.write', 'process.execute', 'network.external'],
          status: 'DECLARED',
          attestationConfidence: 'DECLARED',
          observationSource: 'agent-manifest-declaration'
        }
      }),
      dependencyBoundary: dependencyBoundary || detectDependencyBoundary(repoRoot)
    }
  };

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [run]
  };
}

/**
 * Renders hardened Markdown report from canonical findings.
 */
export function renderMarkdownFromCanonical({
  canonicalFindings = [],
  manifest = null,
  coverageStatus = 'COMPLETE',
  provenance = null,
  repoRoot = process.cwd(),
  auditIntent = 'DISCOVERY',
  modelProvenance = null,
  canDeclareClean = null,
  assuranceLevel = null,
  scanRunId = null,
  nonce = null,
  projectId = null,
  findingCounts = null,
  toolProvenance = null
}) {
  const effectiveToolProv = toolProvenance || getToolProvenance();
  const toolVer = effectiveToolProv.toolVersion || TOOL_VERSION;
  const toolRevShort = effectiveToolProv.toolRevision
    ? (effectiveToolProv.toolRevision === 'UNCHECKED_REVISION' ? 'UNCHECKED_REVISION' : effectiveToolProv.toolRevision.slice(0, 12))
    : 'unknown';
  const toolDigestShort = effectiveToolProv.toolIntegrityDigest
    ? (effectiveToolProv.toolIntegrityDigest.slice(0, 12) + '...')
    : 'none';

  const timestamp = new Date().toISOString();
  const sha12 = (provenance?.properties?.sha12) || 'unknown';
  const branch = provenance?.branch || 'unknown';
  const isDirty = (provenance?.properties?.isDirty) ? ' (DIRTY)' : ' (CLEAN)';

  let md = '# Security Audit Report\n\n';
  md += `- **Generated At (UTC)**: \`${timestamp}\`\n`;
  md += `- **Target Revision**: \`${sha12}\` on branch \`${branch}\`${isDirty}\n`;
  md += `- **Tool Producer**: \`@arcobaleno64/agy-security-audit\` v\`${toolVer}\` (rev: \`${toolRevShort}\`, TCB digest: \`${toolDigestShort}\`)\n`;
  if (provenance?.properties?.dirtyDiffSha256) {
    md += `- **Dirty Diff SHA-256**: \`${provenance.properties.dirtyDiffSha256}\`\n`;
  }
  md += `- **Coverage Status**: **${coverageStatus}**\n`;
  md += `- **Audit Intent**: \`${sanitizeInlineText(auditIntent || 'DISCOVERY')}\`\n`;
  md += '- **Audit Axiom**: **Presumption of Non-Pass (Default-Deny on Authority Claims)**\n';
  if (canDeclareClean !== null && canDeclareClean !== undefined) {
    md += `- **Can Declare Clean**: **${Boolean(canDeclareClean)}**\n`;
  }
  if (assuranceLevel) {
    md += `- **Assurance Level**: **${sanitizeInlineText(assuranceLevel)}**\n`;
  }
  const effectiveScanRunId = scanRunId || manifest?.scanRunId || null;
  if (effectiveScanRunId) {
    md += `- **Scan Run ID**: \`${sanitizeInlineText(effectiveScanRunId)}\`\n`;
  }
  const effectiveNonce = nonce || manifest?.nonce || manifest?.taskCorrelationNonce || null;
  if (effectiveNonce) {
    md += `- **Task Correlation Nonce**: \`${sanitizeInlineText(effectiveNonce)}\`\n`;
  }
  if (projectId || manifest?.projectId) {
    md += `- **Project ID**: \`${sanitizeInlineText(projectId || manifest.projectId)}\`\n`;
  }
  md += '\n---\n\n';

  // Coverage Reconciliation Section
  if (manifest && (manifest.mode === 'review' || manifest.reviewInventory || (Array.isArray(manifest.changedFiles) && !Array.isArray(manifest.entries)))) {
    md += '## 1. Changed Files Accounting Manifest (Review Mode)\n\n';
    const inv = manifest.reviewInventory || manifest;
    const changed = Array.isArray(inv.changedFiles) ? inv.changedFiles : [];
    const deleted = Array.isArray(inv.deletedFiles) ? inv.deletedFiles : [];
    if (changed.length === 0 && deleted.length === 0) {
      md += '*No files modified or deleted in target diff.*\n';
    } else {
      md += '| File Path | Status | Details |\n';
      md += '| :--- | :--- | :--- |\n';
      for (const f of changed) {
        md += `| \`${sanitizeTableCell(f.path)}\` | **${sanitizeTableCell(f.status)}** | ${f.originalPath ? `Renamed from \`${sanitizeTableCell(f.originalPath)}\`` : 'Active in change diff'} |\n`;
      }
      for (const f of deleted) {
        md += `| \`${sanitizeTableCell(f.path)}\` | **${sanitizeTableCell(f.status)}** | Baseline: \`${sanitizeTableCell(f.baselineRevision ? f.baselineRevision.substring(0, 12) : 'HEAD')}\` |\n`;
      }
    }
  } else {
    // Directory Reconciliation Section (Scan Mode)
    md += '## 1. Directory Reconciliation Manifest\n\n';
    const entries = manifest && (Array.isArray(manifest.entries) ? manifest.entries : (manifest.directoryManifest && Array.isArray(manifest.directoryManifest.entries) ? manifest.directoryManifest.entries : null));
    if (entries) {
      md += '| Directory Path | Audit Status | Files | Reconciliation Reason |\n';
      md += '| :--- | :--- | :--- | :--- |\n';
      for (const e of entries) {
        md += `| \`${sanitizeTableCell(e.path)}\` | **${sanitizeTableCell(e.status)}** | ${Number(e.fileCount) || 0} | ${sanitizeTableCell(e.reason)} |\n`;
      }
    } else {
      md += '> [!WARNING]\n> No Directory Reconciliation Manifest provided. Default-deny flags this audit as unverified coverage.\n';
    }

  }


  if (coverageStatus !== 'COMPLETE') {
    md += '\n> [!WARNING]\n> **Incomplete Coverage**: Under Default-Deny, repository cannot be certified clean when coverage is PARTIAL or UNCHECKABLE.\n';
  }
  md += '\n---\n\n';

  const safeFindings = validateCanonicalFindings(canonicalFindings, repoRoot);

  // Categorize canonical findings (R2-P0-11 / R4-P2-01)
  const confirmed = safeFindings.filter(f => f.disposition === 'REPORTABLE' && (f.findingType === 'VULNERABILITY' || !f.findingType));
  const hardening = safeFindings.filter(f => f.findingType === 'HARDENING' && f.disposition === 'REPORTABLE');
  const informational = safeFindings.filter(f => f.findingType === 'INFORMATIONAL' && f.disposition === 'REPORTABLE');
  const acceptedRisks = safeFindings.filter(f => f.disposition === 'ACCEPTED_RISK');
  const manualReview = safeFindings.filter(f => f.disposition === 'DEFERRED');
  const falsePositives = safeFindings.filter(f => f.disposition === 'SUPPRESSED');

  const reportedConfirmedCount = (findingCounts && typeof findingCounts.reportable === 'number') ? findingCounts.reportable : confirmed.length;
  const reportedHardeningCount = (findingCounts && typeof findingCounts.hardening === 'number') ? findingCounts.hardening : hardening.length;
  const reportedInfoCount = (findingCounts && typeof findingCounts.informational === 'number') ? findingCounts.informational : informational.length;
  const reportedAcceptedCount = (findingCounts && typeof findingCounts.acceptedRisk === 'number') ? findingCounts.acceptedRisk : acceptedRisks.length;
  const reportedDeferredCount = (findingCounts && typeof findingCounts.deferred === 'number') ? findingCounts.deferred : manualReview.length;
  const reportedSuppressedCount = (findingCounts && typeof findingCounts.suppressed === 'number') ? findingCounts.suppressed : falsePositives.length;

  md += '## 2. Findings Summary\n\n';
  md += `- **Confirmed Vulnerabilities (Reportable)**: ${reportedConfirmedCount}\n`;
  md += `- **Advisory Hardening Opportunities**: ${reportedHardeningCount}\n`;
  md += `- **Informational Security Notes**: ${reportedInfoCount}\n`;
  md += `- **Accepted Risks / Documented Waivers**: ${reportedAcceptedCount}\n`;
  md += `- **Needs Manual Review (Deferred / Presumption of Non-Pass)**: ${reportedDeferredCount}\n`;
  md += `- **Affirmatively Refuted (Suppressed)**: ${reportedSuppressedCount}\n`;
  const prov = modelProvenance || safeFindings.find(f => f.modelProvenance)?.modelProvenance;
  if (prov) {
    md += `- **Model Behavior Provenance**: Provider: \`${sanitizeInlineText(prov.modelProvider || 'antigravity-orchestrator')}\` | Model: \`${sanitizeInlineText(prov.modelIdentifier || 'unknown')}\` | Prompt Integrity: \`${sanitizeInlineText(prov.systemPromptIntegrity || 'UNKNOWN')}\`\n`;
  }
  md += '\n';

  let sectionNum = 3;

  // Section: Confirmed
  md += `## ${sectionNum++}. Confirmed Vulnerabilities (High Assurance)\n\n`;
  if (confirmed.length === 0) {
    if (coverageStatus === 'COMPLETE') {
      if (manualReview.length > 0) {
        md += `*No validated reportable findings were identified within the defined and reconciled audit scope (${manualReview.length} item(s) deferred for manual review under default-deny). This result is bounded by the declared coverage, tool capabilities, model behavior, and available evidence.*\n\n`;
      } else {
        md += '*No validated reportable findings were identified within the defined and reconciled audit scope. This result is bounded by the declared coverage, tool capabilities, model behavior, and available evidence.*\n\n';
      }
    } else {
      md += '*No validated reportable findings were identified in reviewed coverage (Coverage is PARTIAL/UNCHECKABLE; repository cannot be certified clean under default-deny).*\n\n';
    }
  } else {
    for (const f of confirmed) {
      md += `### [${sanitizeInlineText(f.severity)}] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Finding Type**: \`${sanitizeInlineText(f.findingType || 'VULNERABILITY')}\`\n`;
      md += `- **Safe Proof Kind**: \`${sanitizeInlineText(f.proofKind || 'STATIC_TRACE')}\`\n`;
      md += `- **Security Property**: \`${sanitizeInlineText(f.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED')}\`\n`;
      const stds = [...(f.taxonomy?.asvs || []), ...(f.taxonomy?.ssdf || []), ...(f.taxonomy?.owaspTop10 || [])].join(', ');
      if (stds) {
        md += `- **Standards Mapping**: \`${sanitizeInlineText(stds)}\`\n`;
      }
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      if (f.lineageId) {
        const nov = f.lineage?.novelty || 'NEW_SURFACE';
        md += `- **Lineage ID**: \`${sanitizeInlineText(f.lineageId)}\` (Novelty: \`${sanitizeInlineText(nov)}\`)\n`;
      }
      if (f.lineage?.whyNow) {
        md += `- **Lineage Rationale (Why Now)**: ${sanitizeInlineText(f.lineage.whyNow)}\n`;
      }
      md += `- **Confidence**: \`${f.confidenceScore}\` (${f.confidenceLevel})\n`;
      if (f.cvssV4?.vector) {
        md += `- **CVSS v4.0**: \`${sanitizeInlineText(f.cvssV4.vector)}\`${f.cvssV4.score !== null ? ` (Score: ${f.cvssV4.score})` : ' (Score: Unrated / Vector-Only)'}\n`;
      }
      const suff3 = f.evidenceSufficiency || f.rigor;
      const suffLevel3 = suff3?.sufficiencyLevel || suff3?.assuranceLevel || 'LOW';
      const suffScore3 = suff3?.score !== undefined ? suff3.score : 'N/A';
      md += `- **Evidence Sufficiency**: \`${suffScore3}\` (${suffLevel3}) [Internal Heuristic]\n`;
      md += `- **Verifier Consensus**: ${f.consensus.supports}/${f.consensus.totalVotes} votes support (unanimous=${f.consensus.unanimous})\n`;
      if (f.defectManagement) {
        md += `- **Defect Management**: Root Cause: \`${sanitizeInlineText(f.defectManagement.rootCause || 'INSUFFICIENT_CONTROL')}\` | Control: \`${sanitizeInlineText(f.defectManagement.missingControl || 'NIST-SSDF-PW.7.1')}\` | Preventive Action: ${sanitizeInlineText(f.defectManagement.preventiveAction || 'None')}\n`;
      }
      if (f.modelProvenance) {
        md += `- **Model Provenance**: \`${sanitizeInlineText(f.modelProvenance.modelProvider || 'antigravity')}/${sanitizeInlineText(f.modelProvenance.modelIdentifier || 'unknown')}\` (Prompt Integrity: \`${sanitizeInlineText(f.modelProvenance.systemPromptIntegrity || 'UNKNOWN')}\`)\n`;
      }
      md += `\n**Description**:\n${sanitizeBlockText(f.description)}\n\n`;
      if (f.location.lineSnippet) {
        md += `**Code Reference**:\n\`\`\`\n${f.location.lineSnippet}\n\`\`\`\n\n`;
      }
    }
  }

  // Section: Advisory Hardening Opportunities (R2-P0-11)
  if (hardening.length > 0) {
    md += `## ${sectionNum++}. Advisory Hardening Opportunities\n\n`;
    for (const f of hardening) {
      md += `### [HARDENING] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Finding Type**: \`HARDENING\`\n`;
      md += `- **Safe Proof Kind**: \`${sanitizeInlineText(f.proofKind || 'STATIC_TRACE')}\`\n`;
      md += `- **Security Property**: \`${sanitizeInlineText(f.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED')}\`\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      if (f.description) {
        md += `\n**Recommendation**:\n${sanitizeBlockText(f.description)}\n\n`;
      }
    }
  }

  // Section: Informational Security Notes (R2-P0-11)
  if (informational.length > 0) {
    md += `## ${sectionNum++}. Informational Security Notes\n\n`;
    for (const f of informational) {
      md += `### [INFORMATIONAL] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Finding Type**: \`INFORMATIONAL\`\n`;
      md += `- **Safe Proof Kind**: \`${sanitizeInlineText(f.proofKind || 'STATIC_TRACE')}\`\n`;
      md += `- **Security Property**: \`${sanitizeInlineText(f.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED')}\`\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      if (f.description) {
        md += `\n**Note**:\n${sanitizeBlockText(f.description)}\n\n`;
      }
    }
  }

  // Section: Deferred / Needs Manual Review
  md += `## ${sectionNum++}. Needs Manual Review (Presumption of Non-Pass / Deferred)\n\n`;
  if (manualReview.length === 0) {
    md += '*No open items pending manual review.*\n\n';
  } else {
    for (const f of manualReview) {
      md += `### [REVIEW REQUIRED] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Failure Reason Code**: \`${sanitizeInlineText(f.reasonCode || 'EVIDENCE_INCOMPLETE')}\`\n`;
      md += `- **Security Property**: \`${sanitizeInlineText(f.securityProperty || 'SECURITY_PROPERTY_UNSPECIFIED')}\`\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      if (f.lineageId) {
        const nov = f.lineage?.novelty || 'NEW_SURFACE';
        md += `- **Lineage ID**: \`${sanitizeInlineText(f.lineageId)}\` (Novelty: \`${sanitizeInlineText(nov)}\`)\n`;
      }
      if (f.lineage?.whyNow) {
        md += `- **Lineage Rationale (Why Now)**: ${sanitizeInlineText(f.lineage.whyNow)}\n`;
      }
      const suff4 = f.evidenceSufficiency || f.rigor;
      const suffLevel4 = suff4?.sufficiencyLevel || suff4?.assuranceLevel || 'LOW';
      const suffScore4 = suff4?.score !== undefined ? suff4.score : 'N/A';
      md += `- **Evidence Sufficiency**: \`${suffScore4}\` (${suffLevel4}) [Internal Heuristic]\n`;
      md += `- **Deferral Reason**: ${sanitizeInlineText(f.dispositionReason || 'Unproven taint flow or missing verifier consensus')}\n\n`;
      if (f.description) {
        md += `**Description**:\n${sanitizeBlockText(f.description)}\n\n`;
      }
      if (Array.isArray(f.proofGaps) && f.proofGaps.length > 0) {
        md += `- **Unclosed Proof Gaps**:\n`;
        for (const g of f.proofGaps) {
          const safeTarget = redactSecrets(sanitizeInlineText(String(g.target || (g.stepIndex !== undefined ? 'step ' + g.stepIndex : 'evidence'))));
          const safeProp = redactSecrets(sanitizeInlineText(g.unprovenProperty || 'Unverified step'));
          const safeLoc = g.location ? ` (\`${redactSecrets(sanitizeInlineText(g.location))}\`)` : '';
          md += `  - [${safeTarget}] ${safeProp}${safeLoc}\n`;
        }
        md += '\n';
      }
      if (f.location.lineSnippet) {
        md += `**Code Reference**:\n\`\`\`\n${f.location.lineSnippet}\n\`\`\`\n\n`;
      }
      md += '> [!IMPORTANT]\n> Under default-deny, this candidate is retained and marked unverified until manual inspection or panel quorum.\n\n';
    }
  }

  // Section: Affirmatively Refuted
  md += `## ${sectionNum++}. Affirmatively Refuted Items (Suppressed)\n\n`;
  if (falsePositives.length === 0) {
    md += '*No items affirmatively refuted.*\n\n';
  } else {
    for (const f of falsePositives) {
      md += `### [REFUTED] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      md += `- **Refutation Reason**: ${sanitizeInlineText(f.dispositionReason || 'Documented mitigation invariant verified by panel')}\n\n`;
    }
  }

  // Section: Accepted Risks & Documented Waivers (R4-P2-01)
  if (acceptedRisks.length > 0) {
    md += `## ${sectionNum++}. Accepted Risks & Documented Waivers (ACCEPTED_RISK)\n\n`;
    for (const f of acceptedRisks) {
      md += `### [ACCEPTED RISK] ${sanitizeInlineText(f.title)}\n\n`;
      md += `- **Location**: \`${sanitizeInlineText(f.location.uri)}:${f.location.startLine}\`\n`;
      md += `- **Rule / CWE**: \`${sanitizeInlineText(f.ruleId)}\`\n`;
      md += `- **Severity**: \`${sanitizeInlineText(f.severity)}\`\n`;
      md += `- **Lineage ID**: \`${sanitizeInlineText(f.lineageId || 'unknown')}\`\n`;
      if (f.riskAcceptance) {
        md += `- **Waiver Authorizer**: \`${sanitizeInlineText(f.riskAcceptance.acceptedBy)}\`\n`;
        md += `- **Waiver Expiration**: \`${sanitizeInlineText(f.riskAcceptance.expiresAt)}\`\n`;
        md += `- **Justification**: ${sanitizeInlineText(f.riskAcceptance.reason)}\n`;
        md += `- **Compensating Controls**: ${sanitizeInlineText(f.riskAcceptance.compensatingControls)}\n`;
      }
      md += '\n';
    }
  }

  return md;
}

/**
 * Canonical required critical scripts set (R6-P1-01 / v1.1.0 P0/P1).
 */
export const REQUIRED_CRITICAL_SCRIPTS = [
  'scripts/adapters/cloudflare-adapter.mjs',
  'scripts/adapters/plugin-data-adapter.mjs',
  'scripts/compact-guard.mjs',
  'scripts/safe-git.mjs',
  'scripts/finalize-scan.mjs',
  'scripts/build-inventory.mjs',
  'scripts/build-threat-model.mjs',
  'scripts/project-context.mjs',
  'scripts/validate-attack-path.mjs',
  'scripts/validate-patch.mjs',
  'scripts/render-sarif.mjs',
  'scripts/prepare-review-context.mjs',
  'scripts/path-containment.mjs'
].sort();

/**
 * Generates an authoritative release manifest for tool integrity verification (R5-P1-01).
 */
export function generateToolIntegrityManifest(toolRoot = null) {
  const defaultToolRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const resolvedTool = path.resolve(toolRoot || defaultToolRoot);
  const criticalScripts = REQUIRED_CRITICAL_SCRIPTS;

  const digests = {};
  for (const rel of criticalScripts) {
    const full = path.resolve(resolvedTool, rel);
    if (fs.existsSync(full)) {
      const content = fs.readFileSync(full, 'utf8').replace(/\r\n/g, '\n');
      digests[rel] = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
    }
  }

  const sortedDigests = {};
  for (const rel of criticalScripts) {
    sortedDigests[rel] = digests[rel];
  }
  const manifestDigest = crypto.createHash('sha256').update(JSON.stringify(sortedDigests), 'utf8').digest('hex');

  return {
    schemaVersion: '1.0.0',
    toolVersion: TOOL_VERSION,
    generatedAt: new Date().toISOString(),
    manifestDigest,
    criticalScripts: sortedDigests
  };
}

/**
 * Verifies tool self-integrity and Trusted Computing Base (TCB) isolation (R4-P2-02 / R5-P1-01 / R6-P1-01).
 * Enforces:
 * 1. Root separation & containment check (prevents target from mutating audit tools).
 * 2. Cryptographic digest verification against release manifest (detects tampering).
 * 3. Fail-closed manifest completeness and canonical manifestDigest verification.
 */
export function verifyToolSelfIntegrity(toolRoot = null, targetRoot = null, options = {}) {
  const defaultToolRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const resolvedTool = path.resolve(toolRoot || defaultToolRoot);
  const resolvedTarget = targetRoot ? path.resolve(targetRoot) : null;

  let isSelfAudit = false;
  if (resolvedTarget) {
    const isIdentical = resolvedTool === resolvedTarget;
    const isToolInsideTarget = resolvedTool.startsWith(resolvedTarget + path.sep);
    const isTargetInsideTool = resolvedTarget.startsWith(resolvedTool + path.sep);

    if (isIdentical) {
      return {
        valid: false,
        status: 'TCB_ISOLATION_ERROR',
        error: `TCB_ISOLATION_ERROR: Tool root (${resolvedTool}) and target root (${resolvedTarget}) cannot be identical.`
      };
    }

    if (isToolInsideTarget || isTargetInsideTool) {
      if (options.allowSelfAudit || options.selfAudit) {
        isSelfAudit = true;
      } else {
        return {
          valid: false,
          status: 'TCB_OVERLAP',
          error: `TCB_OVERLAP: Tool root (${resolvedTool}) and target root (${resolvedTarget}) overlap. Target repository can mutate audit tools. Specify allowSelfAudit: true for self-dogfood audit.`
        };
      }
    }
  }

  // 2. Authoritative script integrity verification against release manifest
  const scriptHashes = {};
  for (const rel of REQUIRED_CRITICAL_SCRIPTS) {
    const fullPath = path.resolve(resolvedTool, rel);
    if (fs.existsSync(fullPath)) {
      const content = fs.readFileSync(fullPath, 'utf8').replace(/\r\n/g, '\n');
      const hash = crypto.createHash('sha256').update(content, 'utf8').digest('hex');
      scriptHashes[rel] = hash;
    }
  }

  // 2. Authoritative script integrity verification against release manifest
  const manifestPath = path.resolve(resolvedTool, 'tool-integrity-manifest.json');
  let manifest = null;
  if (fs.existsSync(manifestPath)) {
    try {
      manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    } catch (err) {
      return {
        valid: false,
        status: 'INTEGRITY_VIOLATION',
        error: `Failed to parse tool-integrity-manifest.json: ${err.message}`
      };
    }
  }

  if (!manifest) {
    return {
      valid: false,
      status: 'TOOL_INTEGRITY_UNKNOWN',
      toolRoot: resolvedTool,
      targetRoot: resolvedTarget,
      isSelfAudit,
      verifiedScriptsCount: 0,
      scriptHashes,
      warning: 'No trusted tool-integrity-manifest.json found; unable to verify script digests against release manifest.'
    };
  }

  // R6-P1-01: Metadata and Schema validation
  if (!manifest.schemaVersion || !manifest.toolVersion || typeof manifest.criticalScripts !== 'object' || !manifest.criticalScripts) {
    return {
      valid: false,
      status: 'INTEGRITY_VIOLATION',
      toolRoot: resolvedTool,
      targetRoot: resolvedTarget,
      error: 'Tool integrity manifest missing schemaVersion, toolVersion, or criticalScripts object.'
    };
  }

  // R6-P1-01: Manifest Completeness Check — MUST contain exactly REQUIRED_CRITICAL_SCRIPTS
  const manifestScriptKeys = Object.keys(manifest.criticalScripts).sort();
  const missingInManifest = REQUIRED_CRITICAL_SCRIPTS.filter(s => typeof manifest.criticalScripts[s] !== 'string' || manifest.criticalScripts[s].length !== 64);
  const unexpectedInManifest = manifestScriptKeys.filter(s => !REQUIRED_CRITICAL_SCRIPTS.includes(s));

  if (missingInManifest.length > 0 || unexpectedInManifest.length > 0) {
    return {
      valid: false,
      status: 'INTEGRITY_VIOLATION',
      toolRoot: resolvedTool,
      targetRoot: resolvedTarget,
      error: `TCB manifest incomplete or corrupted. Missing: [${missingInManifest.join(', ')}]; Unexpected: [${unexpectedInManifest.join(', ')}]`,
      missingInManifest,
      unexpectedInManifest
    };
  }

  // R6-P1-01: Canonical manifestDigest verification
  const sortedDigests = {};
  for (const rel of REQUIRED_CRITICAL_SCRIPTS) {
    sortedDigests[rel] = manifest.criticalScripts[rel];
  }
  const expectedManifestDigest = crypto.createHash('sha256').update(JSON.stringify(sortedDigests), 'utf8').digest('hex');

  if (!manifest.manifestDigest || manifest.manifestDigest !== expectedManifestDigest) {
    return {
      valid: false,
      status: 'INTEGRITY_VIOLATION',
      toolRoot: resolvedTool,
      targetRoot: resolvedTarget,
      error: `TCB manifestDigest mismatch: claimed ${manifest.manifestDigest}, recomputed ${expectedManifestDigest}`,
      claimedDigest: manifest.manifestDigest,
      expectedDigest: expectedManifestDigest
    };
  }

  // R6-P1-01: Verify each critical script against physical on-disk file hash
  let hasMismatch = false;
  const verificationDetails = {};
  for (const rel of REQUIRED_CRITICAL_SCRIPTS) {
    const expectedDigest = manifest.criticalScripts[rel];
    const currentDigest = scriptHashes[rel];
    if (!currentDigest || currentDigest !== expectedDigest) {
      hasMismatch = true;
      verificationDetails[rel] = { expected: expectedDigest, actual: currentDigest || null, match: false };
    } else {
      verificationDetails[rel] = { expected: expectedDigest, actual: currentDigest, match: true };
    }
  }

  if (hasMismatch) {
    return {
      valid: false,
      status: 'INTEGRITY_VIOLATION',
      toolRoot: resolvedTool,
      targetRoot: resolvedTarget,
      error: 'Tool script integrity mismatch detected: critical audit scripts have diverged from trusted release manifest.',
      verificationDetails
    };
  }

  const toolProv = getToolProvenance(resolvedTool);
  return {
    valid: true,
    status: isSelfAudit ? 'SELF_AUDIT_MODE' : 'CONFORMANT',
    toolRoot: resolvedTool,
    targetRoot: resolvedTarget,
    isSelfAudit,
    verifiedScriptsCount: REQUIRED_CRITICAL_SCRIPTS.length,
    scriptHashes,
    manifestDigest: manifest.manifestDigest,
    toolVersion: manifest.toolVersion || TOOL_VERSION,
    toolRevision: toolProv.toolRevision,
    toolIntegrityDigest: manifest.manifestDigest,
    isDirty: toolProv.toolDirty
  };
}

/**
 * Runs deterministic finalizer disposition canaries (R4-P2-03 / R5-P1-02).
 * Verifies that the verifier panel and disposition derivation logic cleanly map:
 * - SAFE_CONTROL -> SUPPRESSED
 * - KNOWN_POSITIVE -> REPORTABLE
 * - AMBIGUOUS -> DEFERRED
 */
export function runDispositionCanaries(repoRoot = process.cwd()) {
  const safeCandidate = {
    id: 'CANARY-SAFE',
    ruleId: 'CWE-89',
    title: 'Canary Safe Control',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const safeVotes = [
    {
      findingId: 'CANARY-SAFE',
      lens: 'DEFENSES',
      decision: 'REFUTES',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'guard' }],
      mitigationProofLine: 'skills/3lens/scripts/safe-git.mjs:1'
    },
    {
      findingId: 'CANARY-SAFE',
      lens: 'REACHABILITY',
      decision: 'REFUTES',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'guard' }]
    },
    {
      findingId: 'CANARY-SAFE',
      lens: 'IMPACT',
      decision: 'REFUTES',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'guard' }]
    }
  ];
  const safeDisp = deriveFinalDisposition(safeCandidate, safeVotes, { score: 0.9 }, repoRoot);
  if (safeDisp.disposition !== 'SUPPRESSED') {
    return {
      pass: false,
      error: `FINALIZER_CALIBRATION_FAILURE: SAFE_CONTROL canary mapped to ${safeDisp.disposition} (expected SUPPRESSED)`
    };
  }

  const positiveCandidate = {
    id: 'CANARY-POS',
    ruleId: 'CWE-89',
    title: 'Canary Known Positive',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const positiveVotes = [
    {
      findingId: 'CANARY-POS',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'entrypoint' }]
    },
    {
      findingId: 'CANARY-POS',
      lens: 'DEFENSES',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'guard' }]
    },
    {
      findingId: 'CANARY-POS',
      lens: 'IMPACT',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'sink' }]
    }
  ];
  const positiveDisp = deriveFinalDisposition(positiveCandidate, positiveVotes, { score: 0.9 }, repoRoot);
  if (positiveDisp.disposition !== 'REPORTABLE') {
    return {
      pass: false,
      error: `FINALIZER_CALIBRATION_FAILURE: KNOWN_POSITIVE canary mapped to ${positiveDisp.disposition} (expected REPORTABLE)`
    };
  }

  const ambiguousCandidate = {
    id: 'CANARY-AMB',
    ruleId: 'CWE-89',
    title: 'Canary Ambiguous',
    location: { uri: 'skills/3lens/scripts/safe-git.mjs', startLine: 1 }
  };
  const ambiguousVotes = [
    {
      findingId: 'CANARY-AMB',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ path: 'skills/3lens/scripts/safe-git.mjs', line: 1, role: 'entrypoint' }]
    }
  ];
  const ambDisp = deriveFinalDisposition(ambiguousCandidate, ambiguousVotes, { score: 0.5 }, repoRoot);
  if (ambDisp.disposition !== 'DEFERRED') {
    return {
      pass: false,
      error: `FINALIZER_CALIBRATION_FAILURE: AMBIGUOUS canary mapped to ${ambDisp.disposition} (expected DEFERRED)`
    };
  }

  return {
    pass: true,
    status: 'FINALIZER_CALIBRATED',
    canariesChecked: 3
  };
}

/**
 * Backward compatibility alias for runDispositionCanaries (R5-P1-02).
 */
export function runCalibrationCanaries(repoRoot = process.cwd()) {
  const res = runDispositionCanaries(repoRoot);
  return {
    ...res,
    status: res.status === 'FINALIZER_CALIBRATED' ? 'CALIBRATED' : res.status
  };
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
/**
 * Loads and aggregates verifier votes from a file or directory (supports nested subdirectories).
 * Supports optional nonce filtering via options.expectedNonces (R1-P1-05).
 */
export function loadVotes(votesPath, options = {}) {
  if (!votesPath || !fs.existsSync(votesPath)) return [];
  try {
    let rawVotes = [];
    const stat = fs.statSync(votesPath);
    if (stat.isDirectory()) {
      const files = fs.readdirSync(votesPath, { recursive: true });
      for (const file of files) {
        const filePath = typeof file === 'string' ? file : file.name;
        if (filePath.endsWith('.json')) {
          try {
            const content = JSON.parse(fs.readFileSync(path.join(votesPath, filePath), 'utf8'));
            if (Array.isArray(content)) {
              rawVotes.push(...content);
            } else if (content && typeof content === 'object') {
              rawVotes.push(content);
            }
          } catch {}
        }
      }
    } else {
      const content = JSON.parse(fs.readFileSync(votesPath, 'utf8'));
      rawVotes = Array.isArray(content) ? content : [content];
    }

    if (options && options.expectedNonces) {
      const nonceMap = options.expectedNonces instanceof Map
        ? options.expectedNonces
        : new Map(Object.entries(options.expectedNonces));
      return rawVotes.filter(v => {
        if (!v || !v.findingId) return false;
        const expected = nonceMap.get(v.findingId);
        return expected !== undefined && v.nonce === expected;
      });
    }

    return rawVotes;
  } catch {
    return [];
  }
}


// -----------------------------------------------------------------------------
// Cloudflare Producer Adapter Loader
// -----------------------------------------------------------------------------
/**
 * Loads the Cloudflare adapter dynamically for producer ingestion.
 * Strictly bound to tool-controlled TCB path; never loads from audited repoRoot.
 */
export async function loadCloudflareAdapter(_repoRoot = null) {
  const adapterUrl = new URL('./adapters/cloudflare-adapter.mjs', import.meta.url);
  return await import(adapterUrl.href);
}

// -----------------------------------------------------------------------------
// CLI Dispatch
// -----------------------------------------------------------------------------
const isDirectExecution = process.argv[1] && process.argv[1].endsWith('finalize-scan.mjs');

if (isDirectExecution) {
  const args = process.argv.slice(2);
  function getArg(name) {
    const idx = args.indexOf(name);
    if (idx !== -1 && idx + 1 < args.length) {
      return args[idx + 1];
    }
    return null;
  }

  const inputPath = getArg('--candidates') || getArg('--input');
  const importCloudflareFindingsArg = getArg('--import-cloudflare-findings');
  const importCloudflareCoverageArg = getArg('--import-cloudflare-coverage');
  const votesPath = getArg('--votes');
  const manifestPath = getArg('--manifest');
  const matrixPath = getArg('--matrix') || getArg('--discovery-matrix');
  const threatModelPathArg = getArg('--threat-model');
  const attestationPathArg = getArg('--execution-attestation');
  const executedStagesArg = getArg('--executed-stages');
  const externalSarifPath = getArg('--external-sarif');
  const repoRootArg = getArg('--repo-root') || process.cwd();
  const intentArg = getArg('--intent') || getArg('--audit-intent') || 'DISCOVERY';
  const scanRunIdArg = getArg('--run-id') || getArg('--scan-run-id');
  const nonceArg = getArg('--nonce') || getArg('--task-correlation-nonce');
  const isCompactedSessionArg = args.includes('--compacted-session') || args.includes('--is-compacted');
  const compactContentPathArg = getArg('--compact-content');
  const compactEnvelopePathArg = getArg('--compact-envelope');
  const preCompactionStatePathArg = getArg('--pre-compaction-state');
  const requireCompactSignatureArg = args.includes('--require-compact-signature');
  const requireCompactEnvelopeArg = args.includes('--require-compact-envelope');
  const compactVerifierKeyArg = getArg('--compact-verifier-key');
  const outputJsonPath = getArg('--output') || getArg('--output-json');
  const outputSarifPath = getArg('--output-sarif');
  const outputMdPath = getArg('--output-md');
  const outputCoveragePath = getArg('--output-coverage');
  const outputManifestPath = getArg('--output-manifest') || manifestPath || (fs.existsSync(path.resolve(repoRootArg, 'scratch/scan-manifest.json')) ? path.resolve(repoRootArg, 'scratch/scan-manifest.json') : null);
  const allowSelfAudit = args.includes('--self-audit');
  const showHelp = args.includes('--help') || args.includes('-h');

  if (showHelp) {
    console.log('Usage: node skills/3lens/scripts/finalize-scan.mjs [options]');
    console.log('');
    console.log('Options:');
    console.log('  --candidates <path>           Candidate findings JSON file');
    console.log('  --import-cloudflare-findings <path> Ingest Cloudflare findings JSON via producer adapter');
    console.log('  --import-cloudflare-coverage <path> Ingest Cloudflare coverage ledger JSON via producer adapter');
    console.log('  --votes <path>                Directory or JSON file with verifier votes');
    console.log('  --manifest <path>             Directory manifest JSON');
    console.log('  --matrix <path>               Discovery matrix JSON');
    console.log('  --threat-model <path>         Threat model JSON file (e.g. scratch/threat-model.json)');
    console.log('  --execution-attestation <path> Execution attestation JSON file');
    console.log('  --executed-stages <stages>    Comma-separated list of executed audit stages');
    console.log('  --repo-root <path>            Repository root path (default: current directory)');
    console.log('  --intent <DISCOVERY|...>      Audit intent');
    console.log('  --run-id <id>                 Audit run ID to bind manifest and SARIF');
    console.log('  --nonce <nonce>               Task-correlation nonce to bind manifest and SARIF');
    console.log('  --self-audit                  Allow self-audit mode (TCB overlap permit)');
    console.log('  --external-sarif <path>       Ingest and display external scanner SARIF report');
    console.log('  --output <path>               Write canonical findings JSON');
    console.log('  --output-sarif <path>         Write finalized SARIF report');
    console.log('  --output-md <path>            Write finalized Markdown report');
    console.log('  --output-manifest <path>      Write updated scan manifest JSON');
    console.log('  --output-coverage <path>      Write coverage accounting JSON');
    console.log('  --help                        Show this help message');
    process.exit(0);
  }

  if (externalSarifPath && !inputPath && !importCloudflareFindingsArg && !importCloudflareCoverageArg) {
    try {
      const repoRoot = path.resolve(repoRootArg);
      const ingested = ingestExternalEvidence(externalSarifPath, repoRoot);
      console.log(`\n=== External Evidence Ingestion: ${externalSarifPath} ===`);
      console.log(`Success:                   ${ingested.success}`);
      console.log(`Parsed Findings Count:     ${ingested.parsedCount}`);
      console.log(`Canonical Findings Count:  ${ingested.canonicalCount}`);
      console.log(`Bound Findings Count:      ${ingested.boundCount}`);
      console.log(`Unbound Findings Count:    ${ingested.unboundCount}`);
      console.log(`Generated Duplicates:      ${ingested.duplicateGeneratedCount}`);
      if (ingested.findings && ingested.findings.length > 0) {
        console.log('\nIngested Findings Sample:');
        ingested.findings.slice(0, 15).forEach((f, idx) => {
          const locStr = f.location ? `${f.location.uri}:${f.location.startLine}` : 'unknown';
          const toolStr = f.tool ? ` [${f.tool}]` : '';
          const bindingStr = f.evidenceBinding ? ` [${f.evidenceBinding}]` : '';
          console.log(`  [${idx + 1}] ${f.ruleId || 'N/A'}${toolStr} -> ${locStr}${bindingStr}`);
          if (f.evidenceHash) {
            console.log(`      Evidence Hash: ${f.evidenceHash.slice(0, 16)}...`);
          }
        });
        if (ingested.findings.length > 15) {
          console.log(`  ... and ${ingested.findings.length - 15} more findings`);
        }
      }
    } catch (err) {
      console.error('Error ingesting external SARIF:', err.message);
      process.exit(1);
    }
  } else if (inputPath || importCloudflareFindingsArg || importCloudflareCoverageArg) {
    try {
      const repoRoot = path.resolve(repoRootArg);
      let candidates = [];
      if (inputPath && fs.existsSync(inputPath)) {
        const rawData = fs.readFileSync(inputPath, 'utf8');
        const parsed = JSON.parse(rawData);
        candidates = Array.isArray(parsed) ? parsed : (Array.isArray(parsed?.candidates) ? parsed.candidates : []);
      }

      let cloudflareCoverage = null;
      if (importCloudflareCoverageArg && fs.existsSync(importCloudflareCoverageArg)) {
        const adapter = await loadCloudflareAdapter();
        cloudflareCoverage = adapter.ingestCoverageLedger(importCloudflareCoverageArg);
        console.log(`✔ Ingested Cloudflare coverage ledger: ${importCloudflareCoverageArg} (Status: ${cloudflareCoverage.coverageStatus})`);
      }

      if (importCloudflareFindingsArg && fs.existsSync(importCloudflareFindingsArg)) {
        const adapter = await loadCloudflareAdapter();
        const cfCandidateSet = adapter.toCandidateSet(importCloudflareFindingsArg, {
          coverageLedgerResult: cloudflareCoverage
        });
        candidates = [...candidates, ...(cfCandidateSet.candidates || [])];
        console.log(`✔ Ingested ${cfCandidateSet.candidates?.length || 0} Cloudflare candidate findings from ${importCloudflareFindingsArg}`);
      }

      let manifest = null;
      if (manifestPath && fs.existsSync(manifestPath)) {
        manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
      } else if (fs.existsSync(path.resolve(repoRoot, 'scratch/scan-manifest.json'))) {
        try {
          manifest = JSON.parse(fs.readFileSync(path.resolve(repoRoot, 'scratch/scan-manifest.json'), 'utf8'));
        } catch {}
      }

      let discoveryMatrix = [];
      if (matrixPath && fs.existsSync(matrixPath)) {
        discoveryMatrix = JSON.parse(fs.readFileSync(matrixPath, 'utf8'));
      } else if (fs.existsSync(path.resolve(repoRoot, 'scratch/discovery-matrix.json'))) {
        try {
          discoveryMatrix = JSON.parse(fs.readFileSync(path.resolve(repoRoot, 'scratch/discovery-matrix.json'), 'utf8'));
        } catch {}
      }

      let executionAttestation = null;
      if (attestationPathArg && fs.existsSync(attestationPathArg)) {
        try {
          executionAttestation = JSON.parse(fs.readFileSync(attestationPathArg, 'utf8'));
        } catch (err) {
          console.error(`[EXECUTION-ATTESTATION] Error parsing attestation from ${attestationPathArg}: ${err.message}`);
        }
      }

      const votes = loadVotes(votesPath);
      if (candidates.length > 0 && votes.length === 0) {
        console.warn('[DEFAULT-DENY] No verifier votes provided via --votes. All candidates will be derived as DEFERRED under Default-Deny.');
      }

      // R10-P0-01: Load and validate threat model from CLI arg or canonical scratch path
      let threatModel = null;
      if (threatModelPathArg && fs.existsSync(threatModelPathArg)) {
        try {
          const parsedTm = JSON.parse(fs.readFileSync(threatModelPathArg, 'utf8'));
          const tmVal = validateThreatModel(parsedTm, repoRoot);
          if (!tmVal.valid) {
            console.error(`[THREAT-MODEL] Error: Threat model failed validation under Default-Deny: ${tmVal.errors.join(', ')}`);
            threatModel = null;
          } else {
            threatModel = parsedTm;
          }
        } catch (err) {
          console.error(`[THREAT-MODEL] Error: Could not parse threat model from ${threatModelPathArg}: ${err.message}`);
          threatModel = null;
        }
      } else if (fs.existsSync(path.resolve(repoRoot, 'scratch/threat-model.json'))) {
        try {
          const autoPath = path.resolve(repoRoot, 'scratch/threat-model.json');
          const parsedTm = JSON.parse(fs.readFileSync(autoPath, 'utf8'));
          const tmVal = validateThreatModel(parsedTm, repoRoot);
          if (tmVal.valid) {
            threatModel = parsedTm;
          } else {
            console.warn(`[THREAT-MODEL] Warning: scratch/threat-model.json failed validation: ${tmVal.errors.join(', ')}`);
          }
        } catch {}
      }

      let executedStages = null;
      if (executedStagesArg) {
        executedStages = executedStagesArg.split(',').map(s => s.trim()).filter(Boolean);
      }

      let compactedAuditContent = null;
      if (compactContentPathArg && fs.existsSync(compactContentPathArg)) {
        compactedAuditContent = fs.readFileSync(compactContentPathArg, 'utf8');
      }

      let compactedAuditEnvelope = null;
      if (compactEnvelopePathArg) {
        if (!fs.existsSync(compactEnvelopePathArg)) {
          console.error(`[COMPACT-GUARD] Specified --compact-envelope file does not exist: ${compactEnvelopePathArg}`);
          process.exit(1);
        }
        try {
          compactedAuditEnvelope = JSON.parse(fs.readFileSync(compactEnvelopePathArg, 'utf8'));
        } catch (err) {
          console.error(`[COMPACT-GUARD] Specified --compact-envelope failed to parse as JSON: ${err.message}`);
          process.exit(1);
        }
      } else if (fs.existsSync(path.resolve(repoRoot, 'scratch/compacted-audit-envelope.json'))) {
        try {
          compactedAuditEnvelope = JSON.parse(fs.readFileSync(path.resolve(repoRoot, 'scratch/compacted-audit-envelope.json'), 'utf8'));
        } catch (err) {
          console.error(`[COMPACT-GUARD] Scratch compacted-audit-envelope.json failed to parse as JSON: ${err.message}`);
          process.exit(1);
        }
      }

      let preCompactionState = null;
      if (preCompactionStatePathArg) {
        if (!fs.existsSync(preCompactionStatePathArg)) {
          console.error(`[COMPACT-GUARD] Specified --pre-compaction-state file does not exist: ${preCompactionStatePathArg}`);
          process.exit(1);
        }
        try {
          preCompactionState = JSON.parse(fs.readFileSync(preCompactionStatePathArg, 'utf8'));
        } catch (err) {
          console.error(`[COMPACT-GUARD] Specified --pre-compaction-state failed to parse as JSON: ${err.message}`);
          process.exit(1);
        }
      } else if (fs.existsSync(path.resolve(repoRoot, 'scratch/pre-compaction-state.json'))) {
        try {
          preCompactionState = JSON.parse(fs.readFileSync(path.resolve(repoRoot, 'scratch/pre-compaction-state.json'), 'utf8'));
        } catch (err) {
          console.error(`[COMPACT-GUARD] Scratch pre-compaction-state.json failed to parse as JSON: ${err.message}`);
          process.exit(1);
        }
      }

      let compactVerifierPublicKey = null;
      if (compactVerifierKeyArg) {
        if (fs.existsSync(compactVerifierKeyArg)) {
          compactVerifierPublicKey = fs.readFileSync(compactVerifierKeyArg, 'utf8');
        } else {
          compactVerifierPublicKey = compactVerifierKeyArg;
        }
      }

      const finalization = finalizeScan({
        candidates,
        manifest,
        repoRoot,
        votes,
        auditIntent: intentArg,
        discoveryMatrix,
        threatModel,
        executedStages,
        allowSelfAudit,
        executionAttestation,
        scanRunId: scanRunIdArg,
        nonce: nonceArg,
        cloudflareCoverage,
        compactedAuditEnvelope,
        compactedAuditContent,
        preCompactionState,
        isCompactedSession: isCompactedSessionArg,
        compactOptions: {
          requireSignature: requireCompactSignatureArg,
          requireCompactEnvelope: requireCompactEnvelopeArg,
          verifierPublicKey: compactVerifierPublicKey
        }
      });

      if (outputJsonPath) {
        fs.mkdirSync(path.dirname(outputJsonPath), { recursive: true });
        fs.writeFileSync(outputJsonPath, JSON.stringify(finalization.canonicalFindings, null, 2), 'utf8');
        console.log(`✔ Generated Canonical Findings JSON: ${outputJsonPath}`);
      }

      if (outputManifestPath && finalization.manifest) {
        try {
          fs.mkdirSync(path.dirname(outputManifestPath), { recursive: true });
          fs.writeFileSync(outputManifestPath, JSON.stringify(finalization.manifest, null, 2), 'utf8');
          console.log(`✔ Updated Scan Manifest: ${outputManifestPath}`);
        } catch {}
      }

      let sarif = null;
      if (outputSarifPath) {
        sarif = renderSarifFromCanonical({
          canonicalFindings: finalization.canonicalFindings,
          manifest: finalization.manifest,
          coverageStatus: finalization.coverageStatus,
          provenance: finalization.provenance,
          repoRoot,
          auditIntent: finalization.auditIntent,
          canDeclareClean: finalization.summary.canDeclareClean,
          assuranceLevel: finalization.summary.assuranceLabel,
          findingCounts: finalization.summary.findingCounts,
          scanRunId: finalization.manifest?.scanRunId,
          nonce: finalization.manifest?.nonce,
          projectId: finalization.manifest?.projectId,
          executionAttestation: finalization.summary.execution,
          toolProvenance: finalization.summary.toolProvenance
        });
        fs.mkdirSync(path.dirname(outputSarifPath), { recursive: true });
        fs.writeFileSync(outputSarifPath, JSON.stringify(sarif, null, 2), 'utf8');
        console.log(`✔ Generated SARIF report: ${outputSarifPath}`);
      }

      let md = null;
      if (outputMdPath) {
        md = renderMarkdownFromCanonical({
          canonicalFindings: finalization.canonicalFindings,
          manifest: finalization.manifest,
          coverageStatus: finalization.coverageStatus,
          provenance: finalization.provenance,
          repoRoot,
          auditIntent: finalization.auditIntent,
          canDeclareClean: finalization.summary.canDeclareClean,
          assuranceLevel: finalization.summary.assuranceLabel,
          scanRunId: finalization.manifest?.scanRunId,
          nonce: finalization.manifest?.nonce,
          projectId: finalization.manifest?.projectId,
          findingCounts: finalization.summary.findingCounts,
          toolProvenance: finalization.summary.toolProvenance
        });
        fs.mkdirSync(path.dirname(outputMdPath), { recursive: true });
        fs.writeFileSync(outputMdPath, md, 'utf8');
        console.log(`✔ Generated Markdown report: ${outputMdPath}`);
      }

      let coveragePayload = null;
      if (outputCoveragePath) {
        coveragePayload = {
          schemaVersion: '1',
          coverageStatus: finalization.coverageStatus,
          canDeclareClean: finalization.summary.canDeclareClean,
          coverageMode: manifest?.mode || (manifest?.reviewInventory ? 'review' : (cloudflareCoverage ? 'cloudflare' : 'scan')),
          manifest: finalization.manifest,
          provenance: finalization.provenance
        };
        fs.mkdirSync(path.dirname(outputCoveragePath), { recursive: true });
        fs.writeFileSync(outputCoveragePath, JSON.stringify(coveragePayload, null, 2), 'utf8');
        console.log(`✔ Generated Coverage JSON: ${outputCoveragePath}`);
      }

      // R10-P0-02: Mandatory cross-format parity validation on production CLI path
      if (outputSarifPath && outputMdPath) {
        const parityResult = validateCrossFormatParity({
          sarif,
          markdown: md,
          scanManifest: finalization.manifest,
          coverage: coveragePayload,
          sarifPath: outputSarifPath,
          markdownPath: outputMdPath,
          manifestPath,
          canonicalPath: outputJsonPath
        });
        if (!parityResult.valid) {
          console.error(`[CRITICAL] Mandatory cross-format parity validation failed:\n  - ${(parityResult.errors || []).join('\n  - ')}`);
          process.exit(1);
        }
        console.log('✔ Cross-format parity validated successfully across SARIF, Markdown, and Manifest.');
      }

      // R10-P0-02: Compute canonical artifact hashes for release provenance
      const artifactHashes = computeCanonicalArtifactHashes({
        canonicalResult: finalization.canonicalFindings,
        markdownText: md,
        sarifJson: sarif,
        coverageJson: coveragePayload,
        threatModelJson: threatModel,
        directoryManifestJson: finalization.manifest,
        canonicalPath: outputJsonPath,
        sarifPath: outputSarifPath,
        markdownPath: outputMdPath,
        coveragePath: outputCoveragePath,
        threatModelPath: threatModelPathArg || (fs.existsSync(path.resolve(repoRoot, 'scratch/threat-model.json')) ? path.resolve(repoRoot, 'scratch/threat-model.json') : null),
        directoryManifestPath: manifestPath
      });
      console.log(`✔ Canonical Artifact Authority Hash (SHA-256): ${artifactHashes.canonicalResultHash || 'N/A'}`);
    } catch (err) {
      console.error('Error in finalize-scan:', err.message);
      process.exit(1);
    }
  } else {
    console.log('finalize-scan: missing required --candidates, --import-cloudflare-findings, --import-cloudflare-coverage, or --external-sarif argument.');
    console.log('Run with --help for usage instructions.');
  }
}


