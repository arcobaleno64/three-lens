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
 * Checks whether a finding has passed 3-lens consensus and achieved authoritative reportable status.
 * Under Default-Deny (R05-F01), mere field presence or unverified consensus/proof cannot claim authority.
 * @param {object} finding
 * @param {object} [options={}]
 * @returns {boolean}
 */
export function assertFindingDispositionAuthority(finding, options = {}) {
  if (!finding || typeof finding !== 'object') return false;
  const disp = String(finding.disposition || '').toUpperCase().trim();
  const isReportableDisp = disp === 'CONFIRMED' || disp === 'REPORTABLE';
  if (!isReportableDisp) return false;

  // R05-F01 Defense: Under Default-Deny, authorityConfirmed CANNOT be granted by mere field presence
  // or self-asserted consensus/lineage/ballots. Spoofed inputs must strictly fail closed.

  // 1. Genuine 3-Lens Ballot Panel
  // Must have at least 3 distinct canonical lenses (REACHABILITY, DEFENSES, IMPACT).
  // Two ballots with identical lens or unknown lens are strictly rejected.
  if (Array.isArray(finding.ballots)) {
    const requiredLenses = new Set(['REACHABILITY', 'DEFENSES', 'IMPACT']);
    const supportingLenses = new Set();
    let hasRefutation = false;

    for (const b of finding.ballots) {
      if (!b || typeof b !== 'object') continue;
      const lens = String(b.lens || '').toUpperCase().trim();
      const decision = String(b.decision || '').toUpperCase().trim();
      if (decision === 'REFUTES' || decision === 'FALSE_POSITIVE') {
        hasRefutation = true;
      }
      if (requiredLenses.has(lens) && (decision === 'SUPPORTS' || decision === 'CONFIRMED')) {
        const hasEvidence = Array.isArray(b.evidence) ? b.evidence.length > 0 : Boolean(b.evidence);
        if (hasEvidence) {
          supportingLenses.add(lens);
        }
      }
    }

    // Decisive refutation decisively suppresses candidate under Default-Deny
    if (hasRefutation) return false;

    // All 3 distinct lenses must affirmatively support with evidence
    if (supportingLenses.size >= 3) {
      const allPresent = Array.from(requiredLenses).every(l => supportingLenses.has(l));
      if (allPresent) return true;
    }
  }

  // 2. Cryptographic Authority Attestation
  // Must verify authentic digital signature against trusted supervisor public key.
  // Mere string length checks or self-supplied keys without verification are strictly rejected.
  if (finding.authorityProof && typeof finding.authorityProof === 'object') {
    const ap = finding.authorityProof;
    if (ap.finalizerAttestation === true && ap.signature) {
      try {
        const trustedKeyPem = (options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM).trim().replace(/\r\n/g, '\n');
        // Verify key identity: verifierPublicKey (if supplied) must match trusted root key
        if (ap.verifierPublicKey) {
          const suppliedKeyPem = String(ap.verifierPublicKey).trim().replace(/\r\n/g, '\n');
          if (suppliedKeyPem !== trustedKeyPem) {
            return false;
          }
        }
        const payload = Buffer.from(
          `${finding.id || ''}:${finding.ruleId || ''}:${finding.severity || ''}:${disp}:${ap.signedBy || 'SUPERVISOR_ROOT'}`,
          'utf8'
        );
        const sigBuf = Buffer.from(ap.signature, 'hex');
        const isValid = crypto.verify(null, payload, trustedKeyPem, sigBuf);
        if (isValid) return true;
      } catch {
        return false;
      }
    }
  }

  // Default-Deny: Any other input (including lone lineageId: 'x', empty objects, or unverified consensus) is rejected.
  return false;
}

/**
 * Signs an authority proof for an authoritative finding using a trusted private key.
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
  const disp = String(finding.disposition || '').toUpperCase().trim();
  const payload = Buffer.from(
    `${finding.id || ''}:${finding.ruleId || ''}:${finding.severity || ''}:${disp}:${signedBy}`,
    'utf8'
  );
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
  if (typeof val !== 'number' || !Number.isFinite(val) || Number.isNaN(val)) return fallback;
  return Math.max(0, Math.floor(val));
}

/**
 * Formats a single 3-Lens candidate/verified finding into an ACP-compliant Diagnostic object.
 * @param {object} finding
 * @returns {object}
 */
export function formatAcpDiagnostic(finding, options = {}) {
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
  const isConfirmed = assertFindingDispositionAuthority(finding, options);

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
 * @param {string} uri Target document URI or file path
 * @param {Array<object>} findings
 * @param {object} [options={}]
 * @returns {string} JSON-RPC 2.0 notification line
 */
export function formatPublishDiagnosticsNotification(uri, findings = [], options = {}) {
  if (!uri || typeof uri !== 'string') {
    throw new TypeError('Document URI must be a non-empty string');
  }

  const diagnostics = (Array.isArray(findings) ? findings : []).map(f => formatAcpDiagnostic(f, options));
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
  let isShutdown = false;

  return {
    isCancelled(sessionId = '__default__') {
      return cancelledSessions.has(sessionId);
    },
    isShutdown() {
      return isShutdown;
    },
    resetSession(sessionId = '__default__') {
      cancelledSessions.delete(sessionId);
    },
    startPromptTurn(sessionId = '__default__') {
      cancelledSessions.delete(sessionId);
    },
    emitDiagnostic(uri, finding, options = {}) {
      const sid = options.sessionId || '__default__';
      if (cancelledSessions.has(sid) || isShutdown) return null;
      const line = formatPublishDiagnosticsNotification(uri, [finding], options);
      stream.write(line);
      return line;
    },
    emitBatch(uri, findings, options = {}) {
      const sid = options.sessionId || '__default__';
      if (cancelledSessions.has(sid) || isShutdown) return null;
      const line = formatPublishDiagnosticsNotification(uri, findings, options);
      stream.write(line);
      return line;
    },
    emitBallotProgress(candidateId, lens, vote, details = '', options = {}) {
      const sid = options.sessionId || '__default__';
      if (cancelledSessions.has(sid) || isShutdown) return null;
      const line = formatBallotProgressNotification(candidateId, lens, vote, details);
      stream.write(line);
      return line;
    },
    emitSessionUpdate(sessionId, update = {}) {
      const sid = sessionId || '__default__';
      if (cancelledSessions.has(sid) || isShutdown) return null;
      // R05-F02: Official ACP v1 format: { sessionId, update: { sessionUpdate: ... } }
      const updatePayload = (update && typeof update === 'object' && update.sessionUpdate !== undefined)
        ? update
        : { sessionUpdate: 'agent_message_chunk', ...update };
      const notif = {
        jsonrpc: '2.0',
        method: 'session/update',
        params: {
          sessionId: sid,
          update: updatePayload
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
      if (parsed.method === 'session/prompt') {
        const sid = parsed.params?.sessionId || '__default__';
        // R05-F02: New prompt turn clears prior turn cancellation for this session
        cancelledSessions.delete(sid);
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: { status: 'acknowledged', sessionId: sid }
          };
          stream.write(JSON.stringify(response) + '\n');
          return response;
        }
        return { acknowledged: true, sessionId: sid };
      }
      if (parsed.method === 'session/cancel') {
        const sid = parsed.params?.sessionId || '__default__';
        // R05-F02: Session-scoped cancellation
        cancelledSessions.add(sid);
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: { cancelled: true, sessionId: sid, stopReason: 'cancelled' }
          };
          const respLine = JSON.stringify(response) + '\n';
          stream.write(respLine);
          return response;
        }
        return { cancelled: true, sessionId: sid };
      }
      if (parsed.method === '$/cancel_request' || parsed.method === '$/cancelRequest') {
        const reqId = parsed.params?.id ?? parsed.params?.requestId;
        if (reqId !== undefined && reqId !== null) {
          cancelledRequests.add(reqId);
        }
        cancelledSessions.add('__default__');
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: { cancelled: true, requestId: reqId }
          };
          const respLine = JSON.stringify(response) + '\n';
          stream.write(respLine);
          return response;
        }
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
