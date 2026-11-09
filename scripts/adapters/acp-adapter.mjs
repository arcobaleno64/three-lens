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
 * Maps 3-Lens / CVSS severity levels to standard ACP DiagnosticSeverity numbers.
 * @param {string} severity
 * @returns {number}
 */
export function mapSeverityToAcpDiagnostic(severity) {
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
 * Formats a single 3-Lens candidate/verified finding into an ACP-compliant Diagnostic object.
 * @param {object} finding
 * @returns {object}
 */
export function formatAcpDiagnostic(finding) {
  if (!finding || typeof finding !== 'object') {
    throw new TypeError('Finding must be a non-null object');
  }

  const startLine = Math.max(0, (finding.location?.startLine || 1) - 1);
  const endLine = Math.max(startLine, (finding.location?.endLine || finding.location?.startLine || 1) - 1);
  const startChar = Math.max(0, (finding.location?.startColumn || 1) - 1);
  const endChar = Math.max(startChar, (finding.location?.endColumn || 80) - 1);

  const diag = {
    range: {
      start: { line: startLine, character: startChar },
      end: { line: endLine, character: endChar }
    },
    severity: mapSeverityToAcpDiagnostic(finding.severity),
    code: finding.ruleId || finding.cwe || 'SEC-001',
    source: 'Three-Lens',
    message: finding.title || finding.description || 'Security vulnerability detected',
    data: {
      id: finding.id || null,
      lineageId: finding.lineageId || null,
      securityProperty: finding.securityProperty || null,
      findingType: finding.findingType || 'VULNERABILITY',
      proofKind: finding.proofKind || 'STATIC_TRACE'
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
    }
  };
}
