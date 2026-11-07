#!/usr/bin/env node
/**
 * skills/3lens/scripts/compact-guard.mjs
 * Milestone 5.4 Phase 2 (RFC 0005 Workstream 4):
 * Fail-Closed /compact Session Context Contract & State Preservation Guard.
 *
 * Requirements:
 * 1. Compacted Audit State Envelope (CASE) Schema:
 *    - Preserves scanRunId, executionNonce, toolManifestDigest, repoRootFingerprint across /compact operations.
 * 2. Uncompressible Cryptographic Invariants:
 *    - Validates stateDigest and optional Ed25519 supervisor signature.
 * 3. Fail-Closed Tamper and Truncation Detection:
 *    - Rejects missing, malformed, or altered envelopes; defaults to UNCHECKABLE under Default-Deny.
 * 4. Deterministic Text Extraction:
 *    - Delimited markdown/JSON comment fences that resist conversational summarization loss.
 *
 * Zero external npm dependencies.
 */

import crypto from 'node:crypto';

export const COMPACT_SCHEMA_VERSION = '1.0.0';
export const COMPACT_ENVELOPE_TYPE = 'COMPACTED_AUDIT_STATE_ENVELOPE';

export const COMPACT_HEADER_DELIMITER_START = '<!-- THREE_LENS_COMPACT_STATE_START -->';
export const COMPACT_HEADER_DELIMITER_END = '<!-- THREE_LENS_COMPACT_STATE_END -->';

/**
 * Computes deterministic SHA-256 hex digest of string or buffer.
 */
export function sha256Digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic JSON serialization for canonical hashing.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (obj instanceof Date) {
    return JSON.stringify(obj.toISOString());
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => item === undefined ? 'null' : canonicalJsonStringify(item)).join(',') + ']';
  }
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

/**
 * Creates a Compacted Audit State Envelope (CASE) capturing critical TCB invariants.
 *
 * @param {object} state - Audit state to preserve
 * @param {string} state.scanRunId - Unique scan run identifier
 * @param {string} state.executionNonce - Cryptographic execution nonce
 * @param {string} [state.toolManifestDigest] - SHA-256 of tool-integrity-manifest.json
 * @param {string} [state.repoRootFingerprint] - Hash of repo root path or head commit
 * @param {object} [state.persistedState={}] - Additional intermediate state (ballots, counts)
 * @param {object} [options={}] - Creation options
 * @param {KeyObject|string} [options.signerPrivateKey] - Optional Ed25519 private key for signing
 * @param {string} [options.signerKeyId] - Key ID of signer
 * @returns {object} Canonical CASE object
 */
export function createCompactedStateEnvelope(state, options = {}) {
  if (!state || typeof state !== 'object') {
    throw new Error('Audit state must be a non-null object');
  }

  if (!state.scanRunId || typeof state.scanRunId !== 'string' || !state.scanRunId.trim()) {
    throw new Error('Missing or empty scanRunId in audit state');
  }

  if (!state.executionNonce || typeof state.executionNonce !== 'string' || !state.executionNonce.trim()) {
    throw new Error('Missing or empty executionNonce in audit state');
  }

  const persistedState = state.persistedState && typeof state.persistedState === 'object'
    ? state.persistedState
    : {};
  const persistedStateDigest = sha256Digest(canonicalJsonStringify(persistedState));

  const statePayload = {
    scanRunId: state.scanRunId.trim(),
    executionNonce: state.executionNonce.trim(),
    toolManifestDigest: (state.toolManifestDigest || '').trim(),
    repoRootFingerprint: (state.repoRootFingerprint || '').trim(),
    persistedStateDigest,
    persistedState
  };

  const stateDigest = sha256Digest(canonicalJsonStringify(statePayload));
  const timestamp = options.timestamp || new Date().toISOString();

  const envelope = {
    schemaVersion: COMPACT_SCHEMA_VERSION,
    envelopeType: COMPACT_ENVELOPE_TYPE,
    timestamp,
    ...statePayload,
    stateDigest
  };

  if (options.signerPrivateKey) {
    const signedBy = options.signerKeyId || 'SUPERVISOR_ROOT';
    const signPayload = Buffer.from(`${envelope.scanRunId}:${envelope.executionNonce}:${envelope.stateDigest}:${envelope.persistedStateDigest}:${signedBy}`, 'utf8');
    envelope.signature = crypto.sign(null, signPayload, options.signerPrivateKey).toString('hex');
    envelope.signedBy = signedBy;
  }

  return envelope;
}

/**
 * Serializes CASE envelope into a fenced Markdown comment header.
 *
 * @param {object} envelope - CASE envelope
 * @returns {string} Fenced Markdown block
 */
export function serializeCompactedAuditHeader(envelope) {
  if (!envelope || envelope.envelopeType !== COMPACT_ENVELOPE_TYPE) {
    throw new Error('Invalid envelope passed to serializeCompactedAuditHeader');
  }

  const jsonStr = JSON.stringify(envelope, null, 2);

  return [
    COMPACT_HEADER_DELIMITER_START,
    '<!-- CRITICAL INVARIANT: DO NOT REMOVE, SUMMARIZE, OR MODIFY THIS COMPACTED AUDIT STATE ENVELOPE -->',
    '```json',
    jsonStr,
    '```',
    COMPACT_HEADER_DELIMITER_END
  ].join('\n');
}

/**
 * Extracts and parses a CASE envelope from text content (e.g. compacted conversation).
 *
 * @param {string} text - Content containing the delimiter block
 * @param {object} [options={}] - Extraction options
 * @returns {{ valid: boolean, envelope: object|null, error: string|null }}
 */
export function extractCompactedAuditHeader(text, options = {}) {
  if (typeof text !== 'string' || !text.includes(COMPACT_HEADER_DELIMITER_START)) {
    const error = 'Missing COMPACT_HEADER_DELIMITER_START in content';
    if (options.failClosed) throw new Error(error);
    return { valid: false, envelope: null, error };
  }

  const startIdx = text.indexOf(COMPACT_HEADER_DELIMITER_START);
  const endIdx = text.indexOf(COMPACT_HEADER_DELIMITER_END, startIdx);

  if (endIdx === -1) {
    const error = 'Missing or truncated COMPACT_HEADER_DELIMITER_END in content';
    if (options.failClosed) throw new Error(error);
    return { valid: false, envelope: null, error };
  }

  const block = text.slice(startIdx + COMPACT_HEADER_DELIMITER_START.length, endIdx);

  // Extract JSON from ```json ... ``` code fence (greedy match to avoid truncation by code fences in embedded strings)
  const fenceMatch = block.match(/```(?:json)?\s*([\s\S]*)\s*```/);
  if (!fenceMatch || !fenceMatch[1]) {
    const error = 'Malformed code fence in compacted audit header';
    if (options.failClosed) throw new Error(error);
    return { valid: false, envelope: null, error };
  }

  try {
    const parsed = JSON.parse(fenceMatch[1]);
    const validation = validateCompactedStateEnvelope(parsed, {}, options);
    if (!validation.valid) {
      if (options.failClosed) throw new Error(validation.error);
      return { valid: false, envelope: null, error: validation.error };
    }
    return { valid: true, envelope: parsed, error: null };
  } catch (err) {
    const error = `Failed to parse compacted audit envelope: ${err.message}`;
    if (options.failClosed) throw new Error(error);
    return { valid: false, envelope: null, error };
  }
}

/**
 * Validates the schema, cryptographic digest, and expected context of a CASE envelope.
 *
 * @param {object} envelope
 * @param {object} [expectedContext={}]
 * @param {object} [options={}]
 * @returns {{ valid: boolean, error: string|null }}
 */
export function validateCompactedStateEnvelope(envelope, expectedContext = {}, options = {}) {
  if (!envelope || typeof envelope !== 'object') {
    return { valid: false, error: 'Envelope must be a non-null object' };
  }

  if (envelope.schemaVersion !== COMPACT_SCHEMA_VERSION) {
    return { valid: false, error: `Unsupported schemaVersion: ${envelope.schemaVersion}` };
  }

  if (envelope.envelopeType !== COMPACT_ENVELOPE_TYPE) {
    return { valid: false, error: `Invalid envelopeType: ${envelope.envelopeType}` };
  }

  if (!envelope.scanRunId || typeof envelope.scanRunId !== 'string') {
    return { valid: false, error: 'Missing or invalid scanRunId' };
  }

  if (!envelope.executionNonce || typeof envelope.executionNonce !== 'string') {
    return { valid: false, error: 'Missing or invalid executionNonce' };
  }

  // F05: persistedStateDigest is mandatory
  if (!envelope.persistedStateDigest || typeof envelope.persistedStateDigest !== 'string') {
    return { valid: false, error: 'Missing or invalid persistedStateDigest' };
  }

  // Verify internal state digest
  const statePayload = {
    scanRunId: envelope.scanRunId,
    executionNonce: envelope.executionNonce,
    toolManifestDigest: envelope.toolManifestDigest || '',
    repoRootFingerprint: envelope.repoRootFingerprint || '',
    persistedStateDigest: envelope.persistedStateDigest,
    persistedState: envelope.persistedState || {}
  };

  const computedDigest = sha256Digest(canonicalJsonStringify(statePayload));
  if (computedDigest !== envelope.stateDigest) {
    return {
      valid: false,
      error: `Tamper detected: computed stateDigest ${computedDigest} does not match ${envelope.stateDigest}`
    };
  }

  // F05: Verify internal persistedState digest
  const computedPersistedDigest = sha256Digest(canonicalJsonStringify(envelope.persistedState || {}));
  if (computedPersistedDigest !== envelope.persistedStateDigest) {
    return {
      valid: false,
      error: `Tamper detected: computed persistedStateDigest ${computedPersistedDigest} does not match ${envelope.persistedStateDigest}`
    };
  }

  // F05: Deep immutable comparison against expected persistedState
  if (expectedContext.persistedState !== undefined) {
    const expectedCanonical = canonicalJsonStringify(expectedContext.persistedState || {});
    const actualCanonical = canonicalJsonStringify(envelope.persistedState || {});
    if (expectedCanonical !== actualCanonical) {
      return {
        valid: false,
        error: `persistedState deep immutable comparison failed: state was mutated across compaction`
      };
    }
  }

  // Contextual binding checks if expectedContext supplied
  if (expectedContext.scanRunId && envelope.scanRunId !== expectedContext.scanRunId) {
    return {
      valid: false,
      error: `Context mismatch: scanRunId (${envelope.scanRunId}) != expected (${expectedContext.scanRunId})`
    };
  }

  if (expectedContext.executionNonce && envelope.executionNonce !== expectedContext.executionNonce) {
    return {
      valid: false,
      error: `Nonce mismatch: executionNonce (${envelope.executionNonce}) != expected (${expectedContext.executionNonce})`
    };
  }

  // R04-B04: toolManifestDigest is mandatory on all envelopes unless explicitly excused
  if (options.requireToolManifest !== false) {
    if (!envelope.toolManifestDigest || typeof envelope.toolManifestDigest !== 'string' || !envelope.toolManifestDigest.trim()) {
      return {
        valid: false,
        error: 'Tool manifest mismatch: Compacted state envelope missing mandatory toolManifestDigest (F06 / R04-B04)'
      };
    }
  }

  if (expectedContext.toolManifestDigest) {
    if (!envelope.toolManifestDigest || envelope.toolManifestDigest !== expectedContext.toolManifestDigest) {
      return {
        valid: false,
        error: `Tool manifest mismatch: envelope has '${envelope.toolManifestDigest || 'EMPTY'}', expected '${expectedContext.toolManifestDigest}'`
      };
    }
  }

  if (expectedContext.repoRootFingerprint) {
    if (!envelope.repoRootFingerprint || envelope.repoRootFingerprint !== expectedContext.repoRootFingerprint) {
      return {
        valid: false,
        error: `Repo root fingerprint mismatch: ${envelope.repoRootFingerprint || 'EMPTY'} != expected ${expectedContext.repoRootFingerprint}`
      };
    }
  }

  // F05: Mandatory signature enforcement if required
  if (options.requireSignature || options.signatureRequired) {
    if (!envelope.signature) {
      return {
        valid: false,
        error: 'Compacted state envelope missing required cryptographic signature (F05)'
      };
    }
    if (!options.verifierPublicKey) {
      return {
        valid: false,
        error: 'options.verifierPublicKey is required when requireSignature is enabled (F05)'
      };
    }
  }

  // Cryptographic signature verification (F05 / R04-B04: signature cannot be unverified)
  if (envelope.signature) {
    if (!options.verifierPublicKey) {
      return {
        valid: false,
        error: 'Signature present on envelope but options.verifierPublicKey was not provided for verification (F05 / R04-B04)'
      };
    }
    const signedBy = envelope.signedBy || 'SUPERVISOR_ROOT';
    const signPayload = Buffer.from(
      `${envelope.scanRunId}:${envelope.executionNonce}:${envelope.stateDigest}:${envelope.persistedStateDigest}:${signedBy}`,
      'utf8'
    );
    const isValidSig = crypto.verify(
      null,
      signPayload,
      options.verifierPublicKey,
      Buffer.from(envelope.signature, 'hex')
    );
    if (!isValidSig) {
      return { valid: false, error: 'Cryptographic signature verification failed' };
    }
  }

  return { valid: true, error: null, signatureValid: !!envelope.signature };
}

/**
 * Asserts that session context compaction preserved all non-negotiable invariants.
 * Resolves M54-P2-F05: Enforces deep immutable comparison and tamper detection.
 *
 * @param {object} preCompactionState - Pre-compaction state object
 * @param {string} postCompactionContent - Compacted transcript or prompt string
 * @param {object} [options={}] - Verification options
 * @returns {{ safe: boolean, error: string|null, envelope: object|null }}
 */
export function assertCompactSafe(preCompactionState, postCompactionContent, options = {}) {
  const extracted = extractCompactedAuditHeader(postCompactionContent, { ...options, failClosed: false });

  if (!extracted.valid || !extracted.envelope) {
    return {
      safe: false,
      error: `Compaction stripped audit state envelope: ${extracted.error}`,
      envelope: null
    };
  }

  // F05: Deep immutable comparison of persistedState before and after compaction
  const preCanonical = canonicalJsonStringify(preCompactionState.persistedState || {});
  const postCanonical = canonicalJsonStringify(extracted.envelope.persistedState || {});
  if (preCanonical !== postCanonical) {
    return {
      safe: false,
      error: `persistedState tamper detected across compaction: pre-compaction state does not match post-compaction state`,
      envelope: extracted.envelope
    };
  }

  const validation = validateCompactedStateEnvelope(
    extracted.envelope,
    {
      scanRunId: preCompactionState.scanRunId,
      executionNonce: preCompactionState.executionNonce,
      toolManifestDigest: preCompactionState.toolManifestDigest,
      repoRootFingerprint: preCompactionState.repoRootFingerprint,
      persistedState: preCompactionState.persistedState
    },
    options
  );

  if (!validation.valid) {
    return {
      safe: false,
      error: `Compaction invariant violation: ${validation.error}`,
      envelope: extracted.envelope
    };
  }

  return {
    safe: true,
    error: null,
    envelope: extracted.envelope
  };
}
