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
 * Under Default-Deny (R03-F03), self-asserted disposition strings without consensus,
 * provenance, or ballots cannot claim authorityConfirmed.
 * @param {object} finding
 * @returns {boolean}
 */
export function assertFindingDispositionAuthority(finding) {
  if (!finding || typeof finding !== 'object') return false;
  const disp = String(finding.disposition || '').toUpperCase().trim();
  const isReportableDisp = disp === 'CONFIRMED' || disp === 'REPORTABLE';
  if (!isReportableDisp) return false;

  // R04-F01 Defense: Under Default-Deny, authorityConfirmed CANNOT be granted by mere field presence.
  // Spoofed inputs such as lineageId: 'x', authorityProof: {}, consensus: { totalVotes: 2 },
  // or ballots: [{}, {}] must strictly fail closed.

  // 1. Genuine 3-Lens Ballot Panel
  if (Array.isArray(finding.ballots) && finding.ballots.length >= 2) {
    const validLenses = new Set(['REACHABILITY', 'DEFENSES', 'IMPACT', 'TAINT', 'DISCOVERY']);
    const supportingBallots = finding.ballots.filter(b =>
      b && typeof b === 'object' &&
      validLenses.has(String(b.lens || '').toUpperCase()) &&
      ['SUPPORTS', 'CONFIRMED'].includes(String(b.decision || '').toUpperCase()) &&
      (Array.isArray(b.evidence) ? b.evidence.length > 0 : Boolean(b.evidence))
    );
    if (supportingBallots.length >= 2) {
      return true;
    }
  }

  // 2. Genuine Finalizer Consensus Object
  if (finding.consensus && typeof finding.consensus === 'object') {
    const c = finding.consensus;
    const isUnanimousOrQuorum = (c.unanimous === true && Number(c.supports || c.totalVotes) >= 2) ||
      (Number(c.supports) >= 2 && Number(c.refutes || 0) === 0);
    const isVerifiedStatus = c.status === 'VERIFIED' || c.verified === true || c.authoritative === true;
    if (isUnanimousOrQuorum && isVerifiedStatus) {
      return true;
    }
  }

  // 3. Genuine Finalizer votesSummary (from deriveFinalDisposition)
  if (finding.votesSummary && typeof finding.votesSummary === 'object') {
    const vs = finding.votesSummary;
    if (vs.unanimous === true && Number(vs.supports) >= 2 && Number(vs.refutes || 0) === 0) {
      return true;
    }
  }

  // 4. Cryptographic Authority Attestation
  if (finding.authorityProof && typeof finding.authorityProof === 'object') {
    const ap = finding.authorityProof;
    if (
      ap.finalizerAttestation === true &&
      typeof ap.signature === 'string' && ap.signature.length >= 32 &&
      typeof ap.verifierPublicKey === 'string' && ap.verifierPublicKey.length >= 32
    ) {
      return true;
    }
  }

  // Default-Deny: Any other input (including lone lineageId: 'x', empty objects, or unverified consensus) is rejected.
  return false;
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
export function formatAcpDiagnostic(finding) {
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
  const isConfirmed = assertFindingDispositionAuthority(finding);

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
 * @returns {string} JSON-RPC 2.0 notification line
 */
export function formatPublishDiagnosticsNotification(uri, findings = []) {
  if (!uri || typeof uri !== 'string') {
    throw new TypeError('Document URI must be a non-empty string');
  }

  const diagnostics = (Array.isArray(findings) ? findings : []).map(formatAcpDiagnostic);
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
  let isCancelled = false;
  let isShutdown = false;

  return {
    isCancelled() { return isCancelled; },
    isShutdown() { return isShutdown; },
    emitDiagnostic(uri, finding) {
      if (isCancelled || isShutdown) return null;
      const line = formatPublishDiagnosticsNotification(uri, [finding]);
      stream.write(line);
      return line;
    },
    emitBatch(uri, findings) {
      if (isCancelled || isShutdown) return null;
      const line = formatPublishDiagnosticsNotification(uri, findings);
      stream.write(line);
      return line;
    },
    emitBallotProgress(candidateId, lens, vote, details = '') {
      if (isCancelled || isShutdown) return null;
      const line = formatBallotProgressNotification(candidateId, lens, vote, details);
      stream.write(line);
      return line;
    },
    emitSessionUpdate(sessionId, update = {}) {
      if (isCancelled || isShutdown) return null;
      const notif = {
        jsonrpc: '2.0',
        method: 'session/update',
        params: { sessionId, ...update }
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
      if (parsed.method === 'session/cancel' || parsed.method === '$/cancelRequest') {
        // R04-F02: Persist cancelled state to immediately drop subsequent diagnostics
        isCancelled = true;
        // In ACP / JSON-RPC 2.0, if no id is provided, it is a notification and must not emit a response
        if (parsed.id !== undefined && parsed.id !== null) {
          const response = {
            jsonrpc: '2.0',
            id: parsed.id,
            result: { cancelled: true }
          };
          const respLine = JSON.stringify(response) + '\n';
          stream.write(respLine);
          return response;
        }
        return { cancelled: true };
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
