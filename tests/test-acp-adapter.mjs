import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ACP_DIAGNOSTIC_SEVERITY,
  assertFindingDispositionAuthority,
  mapSeverityToAcpDiagnostic,
  formatAcpDiagnostic,
  serializeJsonRpcNotification,
  formatPublishDiagnosticsNotification,
  formatBallotProgressNotification,
  handleInitialize,
  parseJsonRpcMessage,
  createAcpDiagnosticEmitter
} from '../scripts/adapters/acp-adapter.mjs';
import { validateAcpHandshake } from '../scripts/adapters/acp-transport-adapter.mjs';

test('ACP Adapter: mapSeverityToAcpDiagnostic severity mapping and Default-Deny clamping', () => {
  // Confirmed reportable findings map to appropriate severity
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.ERROR);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', 'CONFIRMED'), ACP_DIAGNOSTIC_SEVERITY.ERROR);
  assert.equal(mapSeverityToAcpDiagnostic('MEDIUM', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.WARNING);
  assert.equal(mapSeverityToAcpDiagnostic('LOW', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.INFORMATION);
  assert.equal(mapSeverityToAcpDiagnostic('INFO', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('NONE', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('UNKNOWN', 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic(null, 'REPORTABLE'), ACP_DIAGNOSTIC_SEVERITY.HINT);

  // R01-F04 Invariant: Unverified candidates are strictly clamped to HINT (4), never ERROR (1)
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', 'UNVERIFIED'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', 'DEFERRED'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', 'CANDIDATE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', null), ACP_DIAGNOSTIC_SEVERITY.HINT);
});

test('ACP Adapter: formatAcpDiagnostic produces standard LSP range and metadata', () => {
  const finding = {
    id: 'FIND-001',
    ruleId: 'CWE-89',
    title: 'SQL Injection via query concatenation',
    severity: 'HIGH',
    disposition: 'REPORTABLE',
    location: {
      uri: 'src/db.js',
      startLine: 42,
      endLine: 45,
      startColumn: 5,
      endColumn: 30
    },
    lineageId: 'lin-abc-123',
    securityProperty: 'injection-prevention',
    findingType: 'VULNERABILITY',
    proofKind: 'STATIC_TRACE',
    remediation: 'Use parameterized queries'
  };

  const diag = formatAcpDiagnostic(finding);

  assert.equal(diag.code, 'CWE-89');
  assert.equal(diag.source, 'Three-Lens');
  assert.equal(diag.severity, 1);
  assert.equal(diag.message, 'SQL Injection via query concatenation');
  assert.deepEqual(diag.range, {
    start: { line: 41, character: 4 },
    end: { line: 44, character: 29 }
  });
  assert.equal(diag.data.id, 'FIND-001');
  assert.equal(diag.data.lineageId, 'lin-abc-123');
  assert.equal(diag.data.authorityConfirmed, true);
  assert.equal(diag.data.remediation, 'Use parameterized queries');
});

test('ACP Adapter: R03-F03 Self-asserted REPORTABLE without consensus strictly clamped to HINT under Default-Deny', () => {
  const spoofedCandidate = {
    id: 'SPOOF-001',
    ruleId: 'CWE-89',
    title: 'Self-asserted Critical finding without consensus or provenance',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE', // Self-asserted string
    // consensus, lineageId, authorityProof, ballots are all missing!
    location: { startLine: 10 }
  };

  const diag = formatAcpDiagnostic(spoofedCandidate);

  // Under Default-Deny (R03-F03), self-asserted string without consensus MUST NOT escalate to Error (1)
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT, 'Unproven self-assertion must clamp to HINT (4)');
  assert.equal(diag.data.authorityConfirmed, false, 'authorityConfirmed must be false');
  assert.equal(diag.data.disposition, 'UNVERIFIED', 'effective disposition must be forced to UNVERIFIED');
  assert.ok(diag.message.includes('[UNVERIFIED CANDIDATE]'), 'message must have unverified candidate banner');
});

test('ACP Adapter: R01-F04 / R02-03 Authority Gate strictly clamps candidate with missing disposition', () => {
  const missingDispCandidate = {
    id: 'CAND-NO-DISP',
    ruleId: 'CWE-1321',
    title: 'Prototype pollution candidate with omitted disposition',
    severity: 'CRITICAL',
    // disposition is intentionally omitted / undefined
    location: { startLine: 5 }
  };

  const diag = formatAcpDiagnostic(missingDispCandidate);

  // Under Default-Deny, missing disposition MUST NOT default to REPORTABLE/Error
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT, 'Missing disposition must clamp to HINT (4)');
  assert.equal(diag.data.authorityConfirmed, false, 'authorityConfirmed must be false');
  assert.equal(diag.data.disposition, 'UNVERIFIED', 'disposition data must record UNVERIFIED');
  assert.ok(diag.message.includes('[UNVERIFIED CANDIDATE]'), 'message must have [UNVERIFIED CANDIDATE] prefix');
});

test('ACP Adapter: R01-F04 Authority Gate clamps unverified candidate in formatAcpDiagnostic', () => {
  const candidate = {
    id: 'CAND-001',
    ruleId: 'CWE-918',
    title: 'Potential SSRF candidate',
    severity: 'CRITICAL',
    disposition: 'DEFERRED',
    location: { startLine: 12 }
  };

  const diag = formatAcpDiagnostic(candidate);

  // Must NOT be an Error (1) under Default-Deny
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(diag.data.authorityConfirmed, false);
  assert.ok(diag.message.includes('[UNVERIFIED CANDIDATE]'));
});

test('ACP Adapter: R01-F05 Safe integer clamping and boundary defense', () => {
  const weirdFinding = {
    id: 'F-WEIRD',
    ruleId: 'CWE-022',
    severity: 'HIGH',
    disposition: 'CONFIRMED',
    lineageId: 'lin-weird-01',
    location: {
      startLine: -10,
      endLine: NaN,
      startColumn: null,
      endColumn: Infinity
    }
  };

  const diag = formatAcpDiagnostic(weirdFinding);
  assert.equal(diag.range.start.line, 0);
  assert.equal(diag.range.end.line, 0);
  assert.equal(diag.range.start.character, 0);
  assert.equal(diag.range.end.character, 0);
});

test('ACP Adapter: serializeJsonRpcNotification single-line JSON with trailing LF', () => {
  const line = serializeJsonRpcNotification('test/method', { foo: 'bar' });
  assert.ok(line.endsWith('\n'), 'Must end with trailing LF');
  assert.ok(!line.slice(0, -1).includes('\n'), 'Must be a single line JSON');

  const obj = JSON.parse(line.trim());
  assert.equal(obj.jsonrpc, '2.0');
  assert.equal(obj.method, 'test/method');
  assert.deepEqual(obj.params, { foo: 'bar' });
});

test('ACP Adapter: formatPublishDiagnosticsNotification formats full notification', () => {
  const findings = [
    {
      id: 'F-1',
      ruleId: 'CWE-79',
      title: 'XSS flaw',
      severity: 'MEDIUM',
      disposition: 'CONFIRMED',
      lineageId: 'lin-f1-01',
      location: { startLine: 10 }
    }
  ];

  const raw = formatPublishDiagnosticsNotification('file:///path/to/app.js', findings);
  const parsed = JSON.parse(raw.trim());

  assert.equal(parsed.jsonrpc, '2.0');
  assert.equal(parsed.method, 'textDocument/publishDiagnostics');
  assert.equal(parsed.params.uri, 'file:///path/to/app.js');
  assert.equal(parsed.params.diagnostics.length, 1);
  assert.equal(parsed.params.diagnostics[0].code, 'CWE-79');
  assert.equal(parsed.params.diagnostics[0].severity, 2);
});

test('ACP Adapter: R01-F03 formatBallotProgressNotification emits window/logMessage', () => {
  const line = formatBallotProgressNotification('CAND-CWE-918-01', 'REACHABILITY', 'CONFIRMED', 'HTTP sink directly reachable');
  const parsed = JSON.parse(line.trim());

  assert.equal(parsed.jsonrpc, '2.0');
  assert.equal(parsed.method, 'window/logMessage');
  assert.equal(parsed.params.type, 3);
  assert.ok(parsed.params.message.includes('[3-Lens Ballot] Candidate CAND-CWE-918-01 - Lens REACHABILITY: CONFIRMED'));
});

test('ACP Adapter: R01-F03 / R02-02 handleInitialize aligns with validateAcpHandshake contract', () => {
  const resp = handleInitialize({ id: 42, method: 'initialize' });
  assert.equal(resp.jsonrpc, '2.0');
  assert.equal(resp.id, 42);
  assert.equal(resp.result.capabilities.diagnosticProvider, true);
  assert.equal(resp.result.capabilities.progressProvider, true);
  assert.equal(resp.result.serverInfo.name, 'three-lens-acp-adapter');

  // R02-02 Verification: Must pass validateAcpHandshake from acp-transport-adapter.mjs
  const handshakeResult = validateAcpHandshake(resp, { expectedId: 42 });
  assert.equal(handshakeResult.valid, true, `Handshake must be valid: ${handshakeResult.error}`);
  assert.equal(handshakeResult.agentInfo.name, 'three-lens-acp-adapter');
  assert.equal(handshakeResult.agentInfo.version, '1.13.0');
  assert.ok(handshakeResult.capabilities.promptCapabilities.streamingDiagnostics);
  assert.ok(handshakeResult.capabilities.sessionCapabilities.diagnosticProvider);

  // R03-F04: Vendor metadata for LSP-over-ACP bridge
  assert.equal(resp.result._meta.protocolBridge, 'LSP_OVER_ACP_V1');
  assert.ok(Array.isArray(resp.result._meta.supportedNotifications));
  assert.ok(resp.result._meta.supportedNotifications.includes('textDocument/publishDiagnostics'));
});

test('ACP Adapter: R03-F04 session cancellation and shutdown message handling', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);
  const cancelResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 101, "method": "session/cancel", "params": {}}\n');
  assert.equal(cancelResp.id, 101);
  assert.equal(cancelResp.result.cancelled, true);

  const shutdownResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 102, "method": "shutdown", "params": {}}\n');
  assert.equal(shutdownResp.id, 102);
  assert.equal(shutdownResp.result, null);
});

test('ACP Adapter: parseJsonRpcMessage validation and error handling', () => {
  assert.equal(parseJsonRpcMessage(''), null);
  assert.equal(parseJsonRpcMessage('   '), null);

  const valid = '{"jsonrpc": "2.0", "method": "initialize", "params": {}}\n';
  const parsedValid = parseJsonRpcMessage(valid);
  assert.equal(parsedValid.jsonrpc, '2.0');
  assert.equal(parsedValid.method, 'initialize');

  const invalidVersion = '{"jsonrpc": "1.0", "method": "test"}';
  const parsedInvalid = parseJsonRpcMessage(invalidVersion);
  assert.equal(parsedInvalid.error, 'INVALID_JSONRPC_VERSION');

  const malformed = '{"jsonrpc": "2.0", incomplete...';
  const parsedMalformed = parseJsonRpcMessage(malformed);
  assert.equal(parsedMalformed.error, 'PARSE_ERROR');
});

test('ACP Adapter: createAcpDiagnosticEmitter stream writing and ballot emitting', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);
  emitter.emitDiagnostic('src/index.js', {
    id: 'F-1',
    ruleId: 'CWE-22',
    severity: 'CRITICAL',
    disposition: 'CONFIRMED',
    lineageId: 'lin-f1-crit',
    location: { startLine: 1 }
  });

  emitter.emitBallotProgress('CAND-01', 'DEFENSES', 'REFUTES', 'Sanitizer active');

  assert.equal(chunks.length, 2);
  const diagParsed = JSON.parse(chunks[0].trim());
  assert.equal(diagParsed.method, 'textDocument/publishDiagnostics');
  assert.equal(diagParsed.params.diagnostics[0].code, 'CWE-22');
  assert.equal(diagParsed.params.diagnostics[0].severity, 1);

  const ballotParsed = JSON.parse(chunks[1].trim());
  assert.equal(ballotParsed.method, 'window/logMessage');
  assert.ok(ballotParsed.params.message.includes('DEFENSES: REFUTES'));
});
