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
 * @param {object} finding
 * @returns {boolean}
 */
export function assertFindingDispositionAuthority(finding) {
  if (!finding || typeof finding !== 'object') return false;
  const disp = String(finding.disposition || '').toUpperCase().trim();
  return disp === 'CONFIRMED' || disp === 'REPORTABLE';
}

/**
 * Maps 3-Lens / CVSS severity levels to standard ACP DiagnosticSeverity numbers.
 * Under Default-Deny (R01-F04), unverified candidates cannot escalate to Error or Warning.
 * @param {string} severity
 * @param {string} [disposition='REPORTABLE']
 * @returns {number}
 */
export function mapSeverityToAcpDiagnostic(severity, disposition = 'REPORTABLE') {
  const isAuthorityConfirmed = String(disposition || '').toUpperCase().trim() === 'CONFIRMED'
    || String(disposition || '').toUpperCase().trim() === 'REPORTABLE';

  if (!isAuthorityConfirmed) {
    // Unverified candidates are strictly clamped to Hint
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

  const disposition = String(finding.disposition || 'REPORTABLE').toUpperCase().trim();
  const severityNum = mapSeverityToAcpDiagnostic(finding.severity, disposition);

  const rawMsg = finding.title || finding.description || 'Security vulnerability detected';
  const sanitizedMsg = String(rawMsg).replace(/[\r\n]+/g, ' ').slice(0, 2048);

  const isConfirmed = assertFindingDispositionAuthority(finding);
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
      disposition: disposition,
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
 * @param {object} request
 * @returns {object} JSON-RPC 2.0 response object
 */
export function handleInitialize(request = {}) {
  const reqId = request && request.id !== undefined ? request.id : 1;
  return {
    jsonrpc: '2.0',
    id: reqId,
    result: {
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
  return {
    emitDiagnostic(uri, finding) {
      const line = formatPublishDiagnosticsNotification(uri, [finding]);
      stream.write(line);
      return line;
    },
    emitBatch(uri, findings) {
      const line = formatPublishDiagnosticsNotification(uri, findings);
      stream.write(line);
      return line;
    },
    emitBallotProgress(candidateId, lens, vote, details = '') {
      const line = formatBallotProgressNotification(candidateId, lens, vote, details);
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
      return null;
    }
  };
}
