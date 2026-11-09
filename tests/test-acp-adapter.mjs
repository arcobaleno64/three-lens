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
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 42 }] },
      { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 42 }] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 42 }] }
    ],
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

test('ACP Adapter: R04-F01 Spoofed authority claims (lineageId, empty authorityProof, mock consensus) strictly fail closed to HINT', () => {
  // 1. ChatGPT explicit mandate: REPORTABLE + CRITICAL + lineageId: 'x'
  const spoofedLineage = {
    id: 'SPOOF-001',
    ruleId: 'CWE-89',
    title: 'Candidate with mock lineageId only',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    lineageId: 'x',
    location: { startLine: 10 }
  };
  const diagLineage = formatAcpDiagnostic(spoofedLineage);
  assert.equal(diagLineage.severity, ACP_DIAGNOSTIC_SEVERITY.HINT, 'lineageId alone must not grant authority');
  assert.equal(diagLineage.data.authorityConfirmed, false);
  assert.equal(diagLineage.data.disposition, 'UNVERIFIED');

  // 2. Empty authorityProof: {}
  const spoofedProof = {
    id: 'SPOOF-002',
    ruleId: 'CWE-89',
    title: 'Candidate with empty authorityProof object',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    authorityProof: {},
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedProof).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedProof).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 3. Unverified consensus: { totalVotes: 2 }
  const spoofedConsensus = {
    id: 'SPOOF-003',
    ruleId: 'CWE-89',
    title: 'Candidate with unverified consensus count',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    consensus: { totalVotes: 2 },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedConsensus).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedConsensus).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 4. Empty ballots: [{}, {}]
  const spoofedBallots = {
    id: 'SPOOF-004',
    ruleId: 'CWE-89',
    title: 'Candidate with empty ballot objects',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [{}, {}],
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedBallots).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedBallots).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 5. Positive counterpart: Cryptographic authorityProof with valid attestation passes
  const validProofCandidate = {
    id: 'VALID-001',
    ruleId: 'CWE-89',
    title: 'Authenticated finding with cryptographic attestation',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    authorityProof: {
      finalizerAttestation: true,
      signature: '3045022100a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00220',
      verifierPublicKey: '04a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6'
    },
    location: { startLine: 10 }
  };
  const diagValid = formatAcpDiagnostic(validProofCandidate);
  assert.equal(diagValid.data.authorityConfirmed, true);
  assert.equal(diagValid.severity, ACP_DIAGNOSTIC_SEVERITY.ERROR);
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
      consensus: {
        status: 'VERIFIED',
        unanimous: true,
        supports: 3
      },
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

test('ACP Adapter: R03-F04 / R04-F02 session cancellation, notification handling and stream suppression', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);

  // 1. Notification (no id) must NOT write response to stream
  const notifCancel = emitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {}}\n');
  assert.equal(notifCancel.cancelled, true);
  assert.equal(chunks.length, 0, 'Notification without id must not write a response to stream');
  assert.equal(emitter.isCancelled(), true);

  // 2. Cancellation strictly drops subsequent emitDiagnostic and emitSessionUpdate calls
  const droppedDiag = emitter.emitDiagnostic('src/index.js', { id: 'F-DROPPED', severity: 'HIGH' });
  assert.equal(droppedDiag, null);
  const droppedUpdate = emitter.emitSessionUpdate('sess-1', { progress: 0.5 });
  assert.equal(droppedUpdate, null);
  assert.equal(chunks.length, 0, 'Cancelled emitter must not write any diagnostic or update');

  // 3. Request (with id) writes standard JSON-RPC response
  const freshChunks = [];
  const freshStream = { write(c) { freshChunks.push(c); } };
  const freshEmitter = createAcpDiagnosticEmitter(freshStream);
  const cancelResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "id": 101, "method": "session/cancel", "params": {}}\n');
  assert.equal(cancelResp.id, 101);
  assert.equal(cancelResp.result.cancelled, true);
  assert.equal(freshChunks.length, 1);
  const respObj = JSON.parse(freshChunks[0].trim());
  assert.equal(respObj.id, 101);
  assert.equal(respObj.result.cancelled, true);

  // 4. Shutdown request handling
  const shutdownResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "id": 102, "method": "shutdown", "params": {}}\n');
  assert.equal(shutdownResp.id, 102);
  assert.equal(shutdownResp.result, null);
  assert.equal(freshEmitter.isShutdown(), true);
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
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] },
      { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] }
    ],
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
