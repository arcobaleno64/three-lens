#!/usr/bin/env node
/**
 * scripts/adapters/acp-adapter.mjs
 * Milestone 5.5 (RFC 0006 Workstream 3):
 * Agent Client Protocol (ACP) Inline Streaming Diagnostics Adapter.
 *
 * Provides bidirectional translation between 3-Lens verified security findings
 * and standardized JSON-RPC 2.0 ACP / LSP diagnostic notification streams.
 *
 * Boundaries:
 * - ACP serves as the live editor/IDE transport (stdio JSON-RPC 2.0).
 * - SARIF 2.1.0 serves as the formal compliance interchange format.
 * - Zero external npm dependencies.
 * - R01-F04 Hardening: Default-Deny Authority Invariant strictly enforced:
 *   Only findings with 3-Lens verified disposition (CONFIRMED / REPORTABLE)
 *   can escalate to ACP Diagnostic Severity Error/Warning. Unverified candidates
 *   are strictly clamped to Hint/Information.
 */

import path from 'node:path';
import crypto from 'node:crypto';
import { DEFAULT_SUPERVISOR_PUBLIC_PEM } from './plugin-data-adapter.mjs';

export { DEFAULT_SUPERVISOR_PUBLIC_PEM };

// R11 Fix: Official uncompromised production supervisor root public key
export const ACP_SUPERVISOR_PUBLIC_PEM = DEFAULT_SUPERVISOR_PUBLIC_PEM;

// R11-F02 Defense: Cryptographic SPKI DER SHA-256 fingerprints for normalized key identity comparison.
// Independent of PEM whitespace, formatting, or line wrapping.
export const SUPERVISOR_ROOT_FINGERPRINT =
  '49b267dd3d8824319e0264d4fe66c2efed32dd7ead65e5154552f9da7d2ba36b';
export const REVOKED_TEST_KEY_FINGERPRINT =
  'ffd048f234ad15a085701c5920ce73143bbf4bd367386c3f568e7eef3dfa0cbc';

// R11 Defense: Revoked test key whose private key was previously exposed in git history.
// Unconditionally rejected by ACP authority verification under all circumstances.
export const REVOKED_TEST_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAfhd+MMkWEh9qzeo1qUR/dcX6hf8ggaf1z6B52Ltp15k=\n-----END PUBLIC KEY-----\n';

/**
 * Computes deterministic 64-char lowercase hex SHA-256 digest of normalized SPKI DER bytes.
 * Robust against arbitrary PEM formatting, whitespace, line lengths, and CRLF differences.
 * @param {string|crypto.KeyObject} keyInput
 * @returns {string} 64-character hex digest, or empty string on error
 */
export function computePublicKeyFingerprint(keyInput) {
  if (!keyInput) return '';
  try {
    const keyObj = typeof keyInput === 'string'
      ? crypto.createPublicKey(keyInput)
      : (keyInput instanceof crypto.KeyObject ? keyInput : crypto.createPublicKey(keyInput));
    const spkiDer = keyObj.export({ type: 'spki', format: 'der' });
    return crypto.createHash('sha256').update(spkiDer).digest('hex');
  } catch {
    return '';
  }
}

/**
 * Standard LSP / ACP Diagnostic Severity ratings:
 * 1 = Error
 * 2 = Warning
 * 3 = Information
 * 4 = Hint
 */
export const ACP_DIAGNOSTIC_SEVERITY = Object.freeze({
  ERROR: 1,
  WARNING: 2,
  INFORMATION: 3,
  HINT: 4
});

/**
 * Computes a deterministic SHA-256 digest binding all critical properties of a finding (R07-F01 & R08-F01):
 * version, id, ruleId, cwe, severity, disposition, title, description, location, lineageId,
 * securityProperty, findingType, proofKind, remediation, and ballots.
 * Tampering with ANY of these fields breaks the cryptographic signature binding.
 * @param {object} finding
 * @returns {string} 64-character lowercase hex SHA-256 digest
 */
export function computeFindingDigest(finding) {
  if (!finding || typeof finding !== 'object') return '';
  const normLocation = finding.location ? {
    uri: String(finding.location.uri || '').trim(),
    startLine: Number(finding.location.startLine || 0),
    endLine: Number(finding.location.endLine || 0),
    startColumn: Number(finding.location.startColumn || 0),
    endColumn: Number(finding.location.endColumn || 0)
  } : null;

  const normBallots = Array.isArray(finding.ballots)
    ? finding.ballots.map(b => ({
        lens: String(b?.lens || '').toUpperCase().trim(),
        decision: String(b?.decision || '').toUpperCase().trim(),
        evidence: Array.isArray(b?.evidence) ? b.evidence : (b?.evidence ? [b.evidence] : [])
      })).sort((a, b) => a.lens.localeCompare(b.lens))
    : [];

  // R08-F01 Defense: Versioned canonical signed payload binding ALL fields rendered into ACP diagnostic output
  const canonicalObj = {
    version: 1,
    id: String(finding.id || '').trim(),
    ruleId: String(finding.ruleId || '').trim(),
    cwe: finding.cwe ? String(finding.cwe).trim() : null,
    severity: String(finding.severity || '').toUpperCase().trim(),
    disposition: String(finding.disposition || '').toUpperCase().trim(),
    title: String(finding.title || '').trim(),
    description: finding.description ? String(finding.description).trim() : null,
    location: normLocation,
    lineageId: finding.lineageId ? String(finding.lineageId).trim() : null,
    securityProperty: finding.securityProperty ? String(finding.securityProperty).trim() : null,
    findingType: finding.findingType ? String(finding.findingType).trim() : null,
    proofKind: finding.proofKind ? String(finding.proofKind).trim() : null,
    remediation: finding.remediation ? (typeof finding.remediation === 'object' ? JSON.stringify(finding.remediation) : String(finding.remediation).trim()) : null,
    ballots: normBallots
  };

  return crypto.createHash('sha256').update(JSON.stringify(canonicalObj), 'utf8').digest('hex');
}

/**
 * Checks whether a finding has passed 3-lens consensus and achieved authoritative reportable status.
 * Under Default-Deny (R06-F01, R07-F01 & R08-F02), mere field presence or unverified consensus/proof cannot claim authority.
 * Full versioned finding digest is cryptographically bound to the supervisor digital signature.
 * Untrusted caller options CANNOT override the supervisor root public key (R08-F02 / R11-F01).
 * Leaked/revoked test key is permanently rejected by normalized SPKI DER fingerprint (R11-F02).
 * @param {object} finding
 * @returns {boolean}
 */
export function assertFindingDispositionAuthority(finding) {
  if (!finding || typeof finding !== 'object') return false;
  const disp = String(finding.disposition || '').toUpperCase().trim();
  const isReportableDisp = disp === 'CONFIRMED' || disp === 'REPORTABLE';
  if (!isReportableDisp) return false;

  // R06-F01 & R07-F01 Defense: Under Default-Deny, authorityConfirmed CANNOT be granted by mere ballots,
  // lineageId, or self-asserted consensus. ONLY authentic cryptographic proof signed by
  // the trusted supervisor root key can confer authority. Ballots alone strictly fail closed.
  if (!finding.authorityProof || typeof finding.authorityProof !== 'object') {
    return false;
  }

  const ap = finding.authorityProof;
  // R12-F05 Defense: Strict 128-character hex validation for 64-byte Ed25519 signature
  if (
    ap.finalizerAttestation !== true ||
    typeof ap.signature !== 'string' ||
    !/^[0-9a-fA-F]{128}$/.test(ap.signature)
  ) {
    return false;
  }

  // If ballots are attached, any refutation decisively vetoes promotion
  if (Array.isArray(finding.ballots)) {
    for (const b of finding.ballots) {
      if (!b || typeof b !== 'object') continue;
      const dec = String(b.decision || '').toUpperCase().trim();
      if (dec === 'REFUTES' || dec === 'FALSE_POSITIVE') {
        return false;
      }
    }
  }

  try {
    // R11-F01 & R11-F02 Defense: Verify key identity against cryptographic fingerprints
    if (ap.verifierPublicKey) {
      const verifierFp = computePublicKeyFingerprint(ap.verifierPublicKey);
      // R11-F02: Unconditionally reject the compromised test key regardless of PEM formatting
      if (verifierFp === REVOKED_TEST_KEY_FINGERPRINT) {
        return false;
      }
      // Must match official supervisor root fingerprint
      if (verifierFp !== SUPERVISOR_ROOT_FINGERPRINT) {
        return false;
      }
    }

    // R07-F01 & R08-F01: Bind entire versioned finding digest into signature payload
    const digest = computeFindingDigest(finding);
    const payload = Buffer.from(`${digest}:${ap.signedBy || 'SUPERVISOR_ROOT'}`, 'utf8');
    const sigBuf = Buffer.from(ap.signature, 'hex');
    const isValid = crypto.verify(null, payload, ACP_SUPERVISOR_PUBLIC_PEM, sigBuf);
    return isValid === true;
  } catch {
    return false;
  }
}

/**
 * Verifies the cryptographic signature binding of a finding against a supplied public key.
 * Used for low-level cryptographic verification, algorithm correctness, and tamper-evidence testing.
 * NOTE: Does NOT confer ACP diagnostic authority or grant Error/Warning escalation (only assertFindingDispositionAuthority does).
 * Rejects compromised test key by SPKI DER fingerprint (R11-F02).
 * @param {object} finding
 * @param {string|crypto.KeyObject} publicKey
 * @returns {boolean}
 */
export function verifyFindingSignature(finding, publicKey) {
  if (
    !finding?.authorityProof ||
    typeof finding.authorityProof.signature !== 'string' ||
    !/^[0-9a-fA-F]{128}$/.test(finding.authorityProof.signature) ||
    !publicKey
  ) {
    return false;
  }
  try {
    const keyFp = computePublicKeyFingerprint(publicKey);
    if (keyFp === REVOKED_TEST_KEY_FINGERPRINT) {
      return false; // Compromised key is permanently revoked even from signature verification
    }
    const digest = computeFindingDigest(finding);
    const payload = Buffer.from(`${digest}:${finding.authorityProof.signedBy || 'SUPERVISOR_ROOT'}`, 'utf8');
    const sigBuf = Buffer.from(finding.authorityProof.signature, 'hex');
    return crypto.verify(null, payload, publicKey, sigBuf) === true;
  } catch {
    return false;
  }
}

/**
 * Signs an authority proof for an authoritative finding using a trusted private key.
 * Cryptographically binds the full canonical digest of the finding (R07-F01).
 * @param {object} finding
 * @param {KeyObject|string} privateKey
 * @param {string} [signedBy='SUPERVISOR_ROOT']
 * @param {string} [verifierPublicKey=DEFAULT_SUPERVISOR_PUBLIC_PEM]
 * @returns {object}
 */
export function signFindingAuthorityProof(
  finding,
  privateKey,
  signedBy = 'SUPERVISOR_ROOT',
  verifierPublicKey = DEFAULT_SUPERVISOR_PUBLIC_PEM
) {
  const digest = computeFindingDigest(finding);
  const payload = Buffer.from(`${digest}:${signedBy}`, 'utf8');
  const signature = crypto.sign(null, payload, privateKey).toString('hex');
  return {
    finalizerAttestation: true,
    signedBy,
    signature,
    verifierPublicKey
  };
}

/**
 * Maps 3-Lens / CVSS severity levels to standard ACP DiagnosticSeverity numbers.
 * Under Default-Deny (R01-F04 / R02-03), unverified candidates cannot escalate to Error or Warning.
 * @param {string} severity
 * @param {string} [disposition='UNVERIFIED']
 * @returns {number}
 */
export function mapSeverityToAcpDiagnostic(severity, disposition = 'UNVERIFIED') {
  const isAuthorityConfirmed = String(disposition || '').toUpperCase().trim() === 'CONFIRMED'
    || String(disposition || '').toUpperCase().trim() === 'REPORTABLE';

  if (!isAuthorityConfirmed) {
    // Unverified candidates are strictly clamped to Hint under Default-Deny
    return ACP_DIAGNOSTIC_SEVERITY.HINT;
  }

  const norm = String(severity || '').toUpperCase().trim();
  switch (norm) {
    case 'CRITICAL':
    case 'HIGH':
      return ACP_DIAGNOSTIC_SEVERITY.ERROR;
    case 'MEDIUM':
      return ACP_DIAGNOSTIC_SEVERITY.WARNING;
    case 'LOW':
      return ACP_DIAGNOSTIC_SEVERITY.INFORMATION;
    case 'INFO':
    case 'NONE':
    default:
      return ACP_DIAGNOSTIC_SEVERITY.HINT;
  }
}

/**
 * Clamps input to safe non-negative integer.
 * @param {any} val
 * @param {number} fallback
 * @returns {number}
 */
function safeNonNegativeInteger(val, fallback = 0) {
  if (typeof val !== 'number' || !Number.isFinite(val) || Number.isNaN(val) || !Number.isSafeInteger(Math.floor(val))) {
    return fallback;
  }
  return Math.max(0, Math.floor(val));
}

/**
 * Normalizes document URIs by converting Windows backslashes, resolving relative path prefixes,
 * and stripping file:// scheme or trailing slashes for canonical equivalence (R12-F01).
 * @param {string} rawUri
 * @returns {string}
 */
export function normalizeDocumentUri(rawUri) {
  if (!rawUri || typeof rawUri !== 'string') return '';
  let norm = rawUri.trim().replace(/\\/g, '/');
  if (norm.startsWith('file:///')) {
    norm = norm.slice(7);
  } else if (norm.startsWith('file://')) {
    norm = norm.slice(6);
  }
  if (/^\/[a-zA-Z]:/.test(norm)) {
    norm = norm.slice(1);
  }
  return norm.replace(/\/+$/, '');
}

/**
 * Formats a single 3-Lens candidate/verified finding into an ACP-compliant Diagnostic object.
 * Under Default-Deny, authority is strictly validated against the immutable supervisor root key.
 * R12-F01 Defense: When expectedDocumentUri is supplied (e.g. from publishDiagnostics notification or emitter),
 * the signed finding location URI must canonically match the target publication URI.
 * Mismatched or missing location URI strictly suppresses authority status for that document.
 * Zero caller override options (R11-F01).
 * @param {object} finding
 * @param {string|null} [expectedDocumentUri=null] Target publication document URI
 * @returns {object}
 */
export function formatAcpDiagnostic(finding, expectedDocumentUri = null) {
  if (!finding || typeof finding !== 'object') {
    throw new TypeError('Finding must be a non-null object');
  }

  const rawStartLine = finding.location?.startLine ?? 1;
  const rawEndLine = finding.location?.endLine ?? rawStartLine;
  const rawStartCol = finding.location?.startColumn ?? 1;
  const rawEndCol = finding.location?.endColumn ?? 80;

  const startLine = safeNonNegativeInteger(rawStartLine - 1, 0);
  const endLine = safeNonNegativeInteger(rawEndLine - 1, startLine);
  const startChar = safeNonNegativeInteger(rawStartCol - 1, 0);
  const endChar = safeNonNegativeInteger(rawEndCol - 1, startChar);

  const disposition = finding.disposition ? String(finding.disposition).toUpperCase().trim() : 'UNVERIFIED';
  let isConfirmed = assertFindingDispositionAuthority(finding);

  // R12-F01 Defense: Canonical URI binding check
  if (isConfirmed && expectedDocumentUri && typeof expectedDocumentUri === 'string') {
    const findingUri = normalizeDocumentUri(finding.location?.uri);
    const targetUri = normalizeDocumentUri(expectedDocumentUri);
    if (!findingUri || !targetUri || (findingUri !== targetUri && !targetUri.endsWith('/' + findingUri) && !findingUri.endsWith('/' + targetUri))) {
      isConfirmed = false;
    }
  }

  // R03-F03 Defense: If not confirmed via consensus, force disposition to UNVERIFIED for severity calculation
  const effectiveDisp = isConfirmed ? disposition : 'UNVERIFIED';
  const severityNum = mapSeverityToAcpDiagnostic(finding.severity, effectiveDisp);

  const rawMsg = finding.title || finding.description || 'Security vulnerability detected';
  const sanitizedMsg = String(rawMsg).replace(/[\r\n]+/g, ' ').slice(0, 2048);
  const displayMsg = isConfirmed ? sanitizedMsg : `[UNVERIFIED CANDIDATE] ${sanitizedMsg}`;

  const diag = {
    range: {
      start: { line: startLine, character: startChar },
      end: { line: Math.max(startLine, endLine), character: Math.max(startChar, endChar) }
    },
    severity: severityNum,
    code: finding.ruleId || finding.cwe || 'SEC-001',
    source: 'Three-Lens',
    message: displayMsg,
    data: {
      id: finding.id || null,
      lineageId: finding.lineageId || null,
      securityProperty: finding.securityProperty || null,
      findingType: finding.findingType || 'VULNERABILITY',
      proofKind: finding.proofKind || 'STATIC_TRACE',
      disposition: effectiveDisp,
      authorityConfirmed: isConfirmed
    }
  };

  if (finding.remediation) {
    diag.data.remediation = finding.remediation;
  }

  return diag;
}

/**
 * Serializes an ACP JSON-RPC 2.0 notification.
 * @param {string} method
 * @param {object} params
 * @returns {string} Single-line JSON string ending with LF
 */
export function serializeJsonRpcNotification(method, params) {
  if (!method || typeof method !== 'string') {
    throw new TypeError('Method must be a non-empty string');
  }
  const payload = {
    jsonrpc: '2.0',
    method,
    params
  };
  return JSON.stringify(payload) + '\n';
}

/**
 * Formats a full `textDocument/publishDiagnostics` notification for an array of findings in a file.
 * R12-F01 Defense: Canonical publication URI is bound into each diagnostic to prevent cross-file misattribution.
 * @param {string} uri Target document URI or file path
 * @param {Array<object>} findings
 * @returns {string} JSON-RPC 2.0 notification line
 */
export function formatPublishDiagnosticsNotification(uri, findings = []) {
  if (!uri || typeof uri !== 'string') {
    throw new TypeError('Document URI must be a non-empty string');
  }

  // R12-F01 Defense: Pass uri to formatAcpDiagnostic to enforce signed URI binding
  const diagnostics = (Array.isArray(findings) ? findings : []).map(f => formatAcpDiagnostic(f, uri));
  return serializeJsonRpcNotification('textDocument/publishDiagnostics', {
    uri,
    diagnostics
  });
}

/**
 * Formats an ACP ballot progress notification (window/logMessage).
 * @param {string} candidateId
 * @param {string} lens
 * @param {string} vote
 * @param {string} [details='']
 * @returns {string} JSON-RPC 2.0 notification line
 */
export function formatBallotProgressNotification(candidateId, lens, vote, details = '') {
  const msg = `[3-Lens Ballot] Candidate ${candidateId} - Lens ${lens}: ${vote}${details ? ' - ' + details : ''}`;
  return serializeJsonRpcNotification('window/logMessage', {
    type: 3, // Info
    message: msg
  });
}

/**
 * Handles ACP / LSP initialize request handshake.
 * Complies with native ACP handshake contract in `validateAcpHandshake()`,
 * declaring vendor metadata for the LSP-over-ACP streaming diagnostic bridge.
 * @param {object} request
 * @returns {object} JSON-RPC 2.0 response object
 */
export function handleInitialize(request = {}) {
  const reqId = request && request.id !== undefined ? request.id : 1;
  return {
    jsonrpc: '2.0',
    id: reqId,
    result: {
      protocolVersion: 1,
      agentInfo: {
        name: 'three-lens-acp-adapter',
        version: '1.13.0'
      },
      agentCapabilities: {
        promptCapabilities: {
          streamingDiagnostics: true
        },
        sessionCapabilities: {
          diagnosticProvider: true,
          progressProvider: true
        }
      },
      _meta: {
        protocolBridge: 'LSP_OVER_ACP_V1',
        vendorCapabilities: {
          streamingDiagnostics: true,
          sessionUpdate: true,
          ballotProgress: true,
          defaultDenyClamping: true
        },
        supportedNotifications: [
          'textDocument/publishDiagnostics',
          'session/update',
          'window/logMessage',
          'session/cancel',
          '$/cancelRequest',
          'shutdown'
        ]
      },
      capabilities: {
        diagnosticProvider: true,
        progressProvider: true
      },
      serverInfo: {
        name: 'three-lens-acp-adapter',
        version: '1.13.0'
      }
    }
  };
}

/**
 * Parses an incoming ACP JSON-RPC message safely.
 * @param {string} raw
 * @returns {object|null}
 */
export function parseJsonRpcMessage(raw) {
  if (!raw || typeof raw !== 'string') return null;
  const trimmed = raw.trim();
  if (!trimmed) return null;

  try {
    const parsed = JSON.parse(trimmed);
    if (parsed.jsonrpc !== '2.0') {
      return { error: 'INVALID_JSONRPC_VERSION', raw: trimmed };
    }
    return parsed;
  } catch (err) {
    return { error: 'PARSE_ERROR', message: err.message, raw: trimmed };
  }
}

/**
 * Factory for streaming diagnostic emitter to stdio or custom stream.
 * @param {object} stream Writable stream (defaults to process.stdout)
 */
export function createAcpDiagnosticEmitter(stream = process.stdout) {
  const cancelledSessions = new Set();
  const cancelledRequests = new Set();
  const MAX_CANCELLED_REQUESTS = 500;
  const sessionTurns = new Map(); // sessionId -> currentTurnId (monotonically increasing)
  const sessionStates = new Map(); // sessionId -> 'IDLE' | 'PROCESSING_PROMPT' | 'COMPLETED' | 'CANCELLED'
  const cancelledTurns = new Set(); // Set of `${sessionId}:${turnId}`
  const pendingPromptRequests = new Map(); // R09-F02 & R10-F02: sessionId -> { id, turnId }
  let isShutdown = false;

  function trackCancelledRequest(reqId) {
    if (reqId === undefined || reqId === null) return;
    if (cancelledRequests.size >= MAX_CANCELLED_REQUESTS) {
      const oldest = cancelledRequests.values().next().value;
      cancelledRequests.delete(oldest);
    }
    cancelledRequests.add(reqId);
  }

  function isEmissionAllowed(sessionId, turnId, requestId) {
    if (isShutdown) return false;
    if (!sessionId || typeof sessionId !== 'string') return false;
    if (!sessionTurns.has(sessionId)) return false; // Unknown or uninitialized session strictly fails closed
    if (cancelledSessions.has(sessionId)) return false;
    // R09-F05 Defense: Explicit check prevents falsy numerical requestId === 0 from bypassing cancellation
    if (requestId !== undefined && requestId !== null && cancelledRequests.has(requestId)) {
      return false;
    }

    // R08-F04 Defense: Mandatory Generation Token Handle.
    // ALL asynchronous emissions MUST provide an explicit, valid turnId.
    // Omitting turnId (or null/undefined) strictly fails closed under Default-Deny.
    if (turnId === undefined || turnId === null) {
      return false;
    }

    const numTurn = Number(turnId);
    const currentTurn = sessionTurns.get(sessionId);
    if (!Number.isSafeInteger(numTurn) || numTurn !== currentTurn) {
      return false; // Stale (< current) or fabricated future (> current) token strictly rejected
    }

    if (cancelledTurns.has(`${sessionId}:${numTurn}`)) {
      return false;
    }

    return true;
  }

  function formatAcpUpdatePayload(update) {
    const textContent = typeof update?.content === 'string'
      ? update.content
      : (update?.text || update?.message || (typeof update?.content?.text === 'string' ? update.content.text : ''));

    // R07-F03 Defense: Strict ACP v1 agent_message_chunk payload.
    // Caller cannot corrupt or overwrite the canonical content structure.
    return {
      sessionUpdate: 'agent_message_chunk',
      content: {
        type: 'text',
        text: String(textContent || '')
      }
    };
  }

  return {
    createSession(sessionId) {
      let sid = sessionId;
      if (sid && sessionTurns.has(sid)) {
        throw new Error(`Session '${sid}' already exists and cannot be overwritten`);
      }
      if (!sid) {
        sid = `sess-${crypto.randomUUID ? crypto.randomUUID() : Date.now() + '-' + crypto.randomBytes(4).toString('hex')}`;
      }
      sessionTurns.set(sid, 1);
      sessionStates.set(sid, 'IDLE');
      cancelledSessions.delete(sid);
      return sid;
    },
    isCancelled(sessionId, turnId) {
      if (!sessionId || !sessionTurns.has(sessionId)) return true;
      if (cancelledSessions.has(sessionId)) return true;
      if (turnId !== undefined && turnId !== null) {
        return cancelledTurns.has(`${sessionId}:${Number(turnId)}`);
      }
      const curTurn = sessionTurns.get(sessionId);
      return curTurn ? cancelledTurns.has(`${sessionId}:${curTurn}`) : true;
    },
    getSessionState(sessionId) {
      return sessionStates.get(sessionId) || 'UNKNOWN';
    },
    getCurrentTurnId(sessionId) {
      return sessionTurns.get(sessionId) || null;
    },
    isShutdown() {
      return isShutdown;
    },
    resetSession(sessionId) {
      if (!sessionId || !sessionTurns.has(sessionId)) return false;
      cancelledSessions.delete(sessionId);
      if (pendingPromptRequests.has(sessionId)) {
        const pending = pendingPromptRequests.get(sessionId);
        pendingPromptRequests.delete(sessionId);
        const cancelResp = {
          jsonrpc: '2.0',
          id: pending.id,
          result: {
            status: 'cancelled',
            sessionId,
            turnId: pending.turnId,
            stopReason: 'cancelled'
          }
        };
        stream.write(JSON.stringify(cancelResp) + '\n');
      }
      sessionStates.set(sessionId, 'IDLE');
      return true;
    },
    startPromptTurn(sessionId, promptRequestId = null) {
      if (!sessionId || !sessionTurns.has(sessionId)) {
        throw new Error(`Cannot start prompt turn for unknown session '${sessionId}'`);
      }
      const nextTurn = (sessionTurns.get(sessionId) || 0) + 1;
      sessionTurns.set(sessionId, nextTurn);
      sessionStates.set(sessionId, 'PROCESSING_PROMPT');
      cancelledSessions.delete(sessionId);
      if (promptRequestId !== null && promptRequestId !== undefined) {
        pendingPromptRequests.set(sessionId, { id: promptRequestId, turnId: nextTurn });
      }
      return nextTurn;
    },
    completePromptTurn(sessionId, stopReason = 'end_turn') {
      if (!sessionId || !sessionTurns.has(sessionId)) return null;
      // R10-F02 Defense: Cancelled session CANNOT transition to COMPLETED!
      if (sessionStates.get(sessionId) === 'CANCELLED') {
        return null;
      }
      // R10-F02 Defense: completePromptTurn without active pending prompt does not change state or emit
      const pending = pendingPromptRequests.get(sessionId);
      if (!pending) {
        return null;
      }
      pendingPromptRequests.delete(sessionId);
      sessionStates.set(sessionId, 'COMPLETED');
      const response = {
        jsonrpc: '2.0',
        id: pending.id,
        result: {
          status: 'completed',
          sessionId,
          turnId: pending.turnId,
          stopReason
        }
      };
      stream.write(JSON.stringify(response) + '\n');
      return response;
    },
    getPendingPrompt(sessionId) {
      return pendingPromptRequests.get(sessionId) || null;
    },
    isPromptPending(sessionId) {
      return pendingPromptRequests.has(sessionId);
    },
    emitDiagnostic(uri, finding, options = {}) {
      const sid = options.sessionId;
      if (!isEmissionAllowed(sid, options.turnId, options.requestId)) return null;
      const line = formatPublishDiagnosticsNotification(uri, [finding]);
      stream.write(line);
      return line;
    },
    emitBatch(uri, findings, options = {}) {
      const sid = options.sessionId;
      if (!isEmissionAllowed(sid, options.turnId, options.requestId)) return null;
      const line = formatPublishDiagnosticsNotification(uri, findings);
      stream.write(line);
      return line;
    },
    emitBallotProgress(candidateId, lens, vote, details = '', options = {}) {
      const sid = options.sessionId;
      if (!isEmissionAllowed(sid, options.turnId, options.requestId)) return null;
      const line = formatBallotProgressNotification(candidateId, lens, vote, details);
      stream.write(line);
      return line;
    },
    emitSessionUpdate(sessionId, update = {}, options = {}) {
      const sid = sessionId;
      if (!isEmissionAllowed(sid, options.turnId, options.requestId)) return null;
      // R05-F02, R06-F02 & R07-F03: Official ACP v1 format with valid content structure
      const notif = {
        jsonrpc: '2.0',
        method: 'session/update',
        params: {
          sessionId: sid,
          update: formatAcpUpdatePayload(update)
        }
      };
      const line = JSON.stringify(notif) + '\n';
      stream.write(line);
      return line;
    },
    handleMessage(raw) {
      const parsed = parseJsonRpcMessage(raw);
      if (!parsed || parsed.error) return null;
      if (parsed.method === 'initialize') {
        const response = handleInitialize(parsed);
        const respLine = JSON.stringify(response) + '\n';
        stream.write(respLine);
        return response;
      }
      if (parsed.method === 'session/new') {
        const reqSid = parsed.params?.sessionId;
        // R08-F03: If caller provides a sessionId that already exists, reject state overwrite
        if (reqSid && sessionTurns.has(reqSid)) {
          if (parsed.id !== undefined && parsed.id !== null) {
            const errResp = {
              jsonrpc: '2.0',
              id: parsed.id,
              error: { code: -32600, message: `Session '${reqSid}' already exists and cannot be overwritten` }
            };
            stream.write(JSON.stringify(errResp) + '\n');
            return errResp;
          }
          return null;
        }
        const sid = reqSid || `sess-${crypto.randomUUID ? crypto.randomUUID() : Date.now() + '-' + crypto.randomBytes(4).toString('hex')}`;
        sessionTurns.set(sid, 1);
        sessionStates.set(sid, 'IDLE');
        cancelledSessions.delete(sid);
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: { sessionId: sid }
          };
          stream.write(JSON.stringify(response) + '\n');
          return response;
        }
        return { sessionId: sid };
      }
      if (parsed.method === 'session/prompt') {
        const sid = parsed.params?.sessionId;
        if (!sid || !sessionTurns.has(sid)) {
          if (parsed.id !== undefined && parsed.id !== null) {
            const errResp = {
              jsonrpc: '2.0',
              id: parsed.id,
              error: { code: -32602, message: `Invalid or unknown sessionId '${sid}'` }
            };
            stream.write(JSON.stringify(errResp) + '\n');
            return errResp;
          }
          return null;
        }
        // R10-F02 Defense: Reject concurrent prompts if an existing prompt is already pending on this session
        if (pendingPromptRequests.has(sid) || sessionStates.get(sid) === 'PROCESSING_PROMPT') {
          if (parsed.id !== undefined && parsed.id !== null) {
            const errResp = {
              jsonrpc: '2.0',
              id: parsed.id,
              error: {
                code: -32600,
                message: `Session '${sid}' already has an active pending prompt turn and cannot accept concurrent prompts`
              }
            };
            stream.write(JSON.stringify(errResp) + '\n');
            return errResp;
          }
          return null;
        }
        // R06-F03: Monotonically increment turn generation token
        const turnId = (sessionTurns.get(sid) || 0) + 1;
        sessionTurns.set(sid, turnId);
        sessionStates.set(sid, 'PROCESSING_PROMPT');
        cancelledSessions.delete(sid);
        if (parsed.id !== undefined && parsed.id !== null) {
          // R09-F02 Defense: Do NOT prematurely complete prompt turn on message ingress!
          // Hold the pending prompt request binding; response is emitted when analysis finishes (completePromptTurn) or is cancelled.
          pendingPromptRequests.set(sid, { id: parsed.id, turnId });
          return { status: 'processing', sessionId: sid, turnId, pending: true, id: parsed.id };
        }
        return { status: 'processing', sessionId: sid, turnId, pending: false };
      }
      if (parsed.method === 'session/cancel') {
        const sid = parsed.params?.sessionId;
        if (sid && sessionTurns.has(sid)) {
          const currentTurn = sessionTurns.get(sid);
          const targetTurn = parsed.params?.turnId || currentTurn;
          cancelledTurns.add(`${sid}:${targetTurn}`);
          cancelledSessions.add(sid);
          sessionStates.set(sid, 'CANCELLED');
          // R09-F02: If there was a pending prompt request for this session, resolve it as cancelled
          if (pendingPromptRequests.has(sid)) {
            const pending = pendingPromptRequests.get(sid);
            pendingPromptRequests.delete(sid);
            const cancelResp = {
              jsonrpc: '2.0',
              id: pending.id,
              result: {
                status: 'cancelled',
                sessionId: sid,
                turnId: pending.turnId,
                stopReason: 'cancelled'
              }
            };
            stream.write(JSON.stringify(cancelResp) + '\n');
          }
        }
        // R08-F03: In ACP v1, session/cancel is a notification. Never write response to stream for notification itself.
        return { cancelled: true, sessionId: sid };
      }
      if (parsed.method === '$/cancel_request' || parsed.method === '$/cancelRequest') {
        const reqId = parsed.params?.id ?? parsed.params?.requestId;
        if (reqId !== undefined && reqId !== null) {
          trackCancelledRequest(reqId);
          // R09-F02: If this request ID matches a pending prompt turn, cancel and resolve it
          for (const [sid, pending] of pendingPromptRequests.entries()) {
            if (pending.id === reqId) {
              pendingPromptRequests.delete(sid);
              cancelledSessions.add(sid);
              cancelledTurns.add(`${sid}:${pending.turnId}`);
              sessionStates.set(sid, 'CANCELLED');
              const cancelResp = {
                jsonrpc: '2.0',
                id: pending.id,
                result: {
                  status: 'cancelled',
                  sessionId: sid,
                  turnId: pending.turnId,
                  stopReason: 'cancelled'
                }
              };
              stream.write(JSON.stringify(cancelResp) + '\n');
              break;
            }
          }
        }
        const sid = parsed.params?.sessionId;
        if (sid && sessionTurns.has(sid)) {
          const currentTurn = sessionTurns.get(sid);
          cancelledTurns.add(`${sid}:${currentTurn}`);
          cancelledSessions.add(sid);
          sessionStates.set(sid, 'CANCELLED');
        }
        // R08-F03: $/cancel_request is a notification. Never write response to stream for notification itself.
        return { cancelled: true, requestId: reqId };
      }
      if (parsed.method === 'shutdown') {
        isShutdown = true;
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: null
          };
          const respLine = JSON.stringify(response) + '\n';
          stream.write(respLine);
          return response;
        }
        return { shutdown: true };
      }
      return null;
    }
  };
}
