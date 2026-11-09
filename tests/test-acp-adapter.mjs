import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
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
  createAcpDiagnosticEmitter,
  signFindingAuthorityProof
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
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

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
  finding.authorityProof = signFindingAuthorityProof(finding, keyPair.privateKey, 'SUPERVISOR_ROOT', pubPem);

  const diag = formatAcpDiagnostic(finding, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem });

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

test('ACP Adapter: R04-F01 / R05-F01 / R06-F01 Spoofed authority claims strictly fail closed to HINT', () => {
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

  // 3. Unverified consensus: { totalVotes: 2, supports: 2, unanimous: true, status: 'VERIFIED' } (R05-F01)
  const spoofedConsensus = {
    id: 'SPOOF-003',
    ruleId: 'CWE-89',
    title: 'Candidate with unverified consensus count',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    consensus: { totalVotes: 3, supports: 3, unanimous: true, status: 'VERIFIED' },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedConsensus).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedConsensus).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 4. Unverified votesSummary: { unanimous: true, supports: 3, refutes: 0 } (R05-F01)
  const spoofedVotesSummary = {
    id: 'SPOOF-004',
    ruleId: 'CWE-89',
    title: 'Candidate with unverified votesSummary',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    votesSummary: { unanimous: true, supports: 3, refutes: 0 },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedVotesSummary).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedVotesSummary).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 5. Two identical lens ballots (e.g. 2x REACHABILITY) (R05-F01)
  const duplicateLensBallots = {
    id: 'SPOOF-005',
    ruleId: 'CWE-89',
    title: 'Candidate with duplicate lens ballots',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['trace 1'] },
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['trace 2'] }
    ],
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(duplicateLensBallots).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(duplicateLensBallots).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 6. Refutation ballot present (Default-Deny veto)
  const refutedCandidate = {
    id: 'SPOOF-006',
    ruleId: 'CWE-89',
    title: 'Candidate with refutation veto',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['trace 1'] },
      { lens: 'DEFENSES', decision: 'REFUTES', evidence: ['sanitizer active'] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: ['payload'] }
    ],
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(refutedCandidate).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(refutedCandidate).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 7. R06-F01 MANDATORY NEGATIVE TEST: Three complete, valid SUPPORTS ballots without cryptographic authorityProof MUST FAIL CLOSED
  const unproven3Ballots = {
    id: 'SPOOF-007-UNPROVEN-BALLOTS',
    ruleId: 'CWE-89',
    title: 'Candidate with 3 complete SUPPORTS ballots but no cryptographic authorityProof',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['http sink reachable'] },
      { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: ['no escaping applied'] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: ['database compromise possible'] }
    ],
    location: { startLine: 10 }
  };
  assert.equal(
    formatAcpDiagnostic(unproven3Ballots).data.authorityConfirmed,
    false,
    'R06-F01 Invariant: Ballots alone without cryptographic authorityProof MUST NEVER confer authority'
  );
  assert.equal(
    formatAcpDiagnostic(unproven3Ballots).severity,
    ACP_DIAGNOSTIC_SEVERITY.HINT,
    'Unproven candidate with ballots must clamp to HINT (4)'
  );

  // 8. Forged 32-char signature length string without real crypto verification (R05-F01)
  const forgedSigCandidate = {
    id: 'SPOOF-008',
    ruleId: 'CWE-89',
    title: 'Candidate with mock 32-char string signature',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    authorityProof: {
      finalizerAttestation: true,
      signature: '3045022100a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f00220',
      verifierPublicKey: '04a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6'
    },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(forgedSigCandidate).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(forgedSigCandidate).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 9. Positive counterpart: Authentic cryptographic Ed25519 signature verified
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });
  const validCryptoCandidate = {
    id: 'VALID-CRYPTO-001',
    ruleId: 'CWE-89',
    title: 'Authenticated finding with cryptographic attestation',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    location: { startLine: 10 }
  };
  validCryptoCandidate.authorityProof = signFindingAuthorityProof(
    validCryptoCandidate,
    keyPair.privateKey,
    'SUPERVISOR_ROOT',
    pubPem
  );
  const diagCrypto = formatAcpDiagnostic(validCryptoCandidate, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem });
  assert.equal(diagCrypto.data.authorityConfirmed, true);
  assert.equal(diagCrypto.severity, ACP_DIAGNOSTIC_SEVERITY.ERROR);

  // 10. R07-F01 Defense: Tampering with ANY field breaks cryptographic signature binding
  const tamperedSeverity = {
    ...validCryptoCandidate,
    severity: 'LOW' // Modified field breaks signature!
  };
  assert.equal(
    formatAcpDiagnostic(tamperedSeverity, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem }).data.authorityConfirmed,
    false,
    'Tampered severity must fail signature verification'
  );

  const tamperedTitle = {
    ...validCryptoCandidate,
    title: 'Tampered malicious SQL injection title'
  };
  assert.equal(
    formatAcpDiagnostic(tamperedTitle, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem }).data.authorityConfirmed,
    false,
    'Tampered title must fail signature verification'
  );

  const tamperedLocation = {
    ...validCryptoCandidate,
    location: { startLine: 999 }
  };
  assert.equal(
    formatAcpDiagnostic(tamperedLocation, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem }).data.authorityConfirmed,
    false,
    'Tampered location must fail signature verification'
  );

  const tamperedBallots = {
    ...validCryptoCandidate,
    ballots: [{ lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['tampered'] }]
  };
  assert.equal(
    formatAcpDiagnostic(tamperedBallots, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem }).data.authorityConfirmed,
    false,
    'Tampered ballots must fail signature verification'
  );

  // 11. R07-F02 Defense: Caller cannot override trusted root without allowConfiguredRoot: true
  assert.equal(
    formatAcpDiagnostic(validCryptoCandidate, { trustedRootPublicKeyPem: pubPem }).data.authorityConfirmed,
    false,
    'Untrusted caller root override without allowConfiguredRoot must be rejected'
  );
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
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const findings = [
    {
      id: 'F-1',
      ruleId: 'CWE-79',
      title: 'XSS flaw',
      severity: 'MEDIUM',
      disposition: 'CONFIRMED',
      ballots: [
        { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['trace'] },
        { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: ['none'] },
        { lens: 'IMPACT', decision: 'SUPPORTS', evidence: ['script execution'] }
      ],
      lineageId: 'lin-f1-01',
      location: { startLine: 10 }
    }
  ];
  findings[0].authorityProof = signFindingAuthorityProof(findings[0], keyPair.privateKey, 'SUPERVISOR_ROOT', pubPem);

  const raw = formatPublishDiagnosticsNotification('file:///path/to/app.js', findings, { allowConfiguredRoot: true, trustedRootPublicKeyPem: pubPem });
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

test('ACP Adapter: R03-F04 / R04-F02 / R05-F02 / R06-F02 / R06-F03 session cancellation, turn isolation, and ACP v1 payload', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);

  // 1. Session-scoped cancellation: cancel sess-1 turn 1
  const notifCancel = emitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "sess-1", "turnId": 1}}\n');
  assert.equal(notifCancel.cancelled, true);
  assert.equal(notifCancel.sessionId, 'sess-1');
  assert.equal(notifCancel.turnId, 1);
  assert.equal(notifCancel.stopReason, 'cancelled');
  assert.equal(chunks.length, 0, 'Notification without id must not write a response to stream');
  assert.equal(emitter.isCancelled('sess-1'), true);
  assert.equal(emitter.isCancelled('sess-2'), false, 'sess-2 must remain uncancelled');

  // 2. Cancellation strictly drops subsequent emitDiagnostic and emitSessionUpdate calls for sess-1
  const droppedDiag = emitter.emitDiagnostic('src/index.js', { id: 'F-DROPPED', severity: 'HIGH' }, { sessionId: 'sess-1', turnId: 1 });
  assert.equal(droppedDiag, null);
  const droppedUpdate = emitter.emitSessionUpdate('sess-1', { progress: 0.5 }, { turnId: 1 });
  assert.equal(droppedUpdate, null);
  assert.equal(chunks.length, 0, 'Cancelled session must not write any diagnostic or update');

  // 3. Uncancelled session sess-2 continues to emit and conforms to ACP v1 { sessionId, update: { sessionUpdate, content } }
  const liveUpdate = emitter.emitSessionUpdate('sess-2', { message: 'analyzing workspace' });
  assert.ok(liveUpdate !== null);
  assert.equal(chunks.length, 1);
  const updateObj = JSON.parse(chunks[0].trim());
  assert.equal(updateObj.jsonrpc, '2.0');
  assert.equal(updateObj.method, 'session/update');
  assert.equal(updateObj.params.sessionId, 'sess-2');
  assert.equal(updateObj.params.update.sessionUpdate, 'agent_message_chunk');
  assert.deepEqual(updateObj.params.update.content, { type: 'text', text: 'analyzing workspace' });

  // 4. New prompt turn for sess-1 increments turn generation and resets cancellation state (R05-F02 & R06-F03)
  const promptResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 201, "method": "session/prompt", "params": {"sessionId": "sess-1"}}\n');
  assert.equal(promptResp.result.status, 'completed');
  assert.equal(promptResp.result.stopReason, 'end_turn');
  assert.equal(promptResp.result.turnId, 2, 'New prompt must advance to turn generation 2');
  assert.equal(emitter.isCancelled('sess-1'), false, 'session/prompt must clear prior session cancellation');

  // R06-F03 Invariant: Stale emission from old generation turn 1 is rejected, while current turn 2 is allowed
  const staleTurnEmission = emitter.emitSessionUpdate('sess-1', { progress: 0.1 }, { turnId: 1 });
  assert.equal(staleTurnEmission, null, 'Stale turn 1 emission must be rejected under Generation Token invariant');
  const restoredUpdate = emitter.emitSessionUpdate('sess-1', { progress: 0.2 }, { turnId: 2 });
  assert.ok(restoredUpdate !== null, 'Current generation turn 2 emission must be allowed');

  // R07-F04 Invariant: Fabricated future turnId (e.g. 999) must be rejected fail-closed
  const futureTurnEmission = emitter.emitSessionUpdate('sess-1', { progress: 0.3 }, { turnId: 999 });
  assert.equal(futureTurnEmission, null, 'Fabricated future turnId must be strictly rejected');

  // R07-F03 Invariant: session/new initializes session with turn 1 and returns sessionId
  const sessionNewResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 301, "method": "session/new", "params": {"sessionId": "sess-new-1"}}\n');
  assert.equal(sessionNewResp.id, 301);
  assert.equal(sessionNewResp.result.sessionId, 'sess-new-1');
  assert.equal(emitter.getCurrentTurnId('sess-new-1'), 1);

  // R07-F03 Invariant: Caller attempting to overwrite content structure with invalid object
  const spoofedContentUpdate = emitter.emitSessionUpdate('sess-new-1', { content: { type: 'malicious', rawHtml: '<script>' } });
  assert.ok(spoofedContentUpdate !== null);
  const spoofedParsed = JSON.parse(spoofedContentUpdate.trim());
  assert.equal(spoofedParsed.params.update.sessionUpdate, 'agent_message_chunk');
  assert.deepEqual(spoofedParsed.params.update.content, { type: 'text', text: '' });

  // 5. Request (with id) writes standard JSON-RPC response with stopReason: 'cancelled'
  const freshChunks = [];
  const freshStream = { write(c) { freshChunks.push(c); } };
  const freshEmitter = createAcpDiagnosticEmitter(freshStream);
  const cancelResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "id": 101, "method": "session/cancel", "params": {"sessionId": "sess-101", "turnId": 1}}\n');
  assert.equal(cancelResp.id, 101);
  assert.equal(cancelResp.result.cancelled, true);
  assert.equal(cancelResp.result.stopReason, 'cancelled');
  assert.equal(freshChunks.length, 1);
  const respObj = JSON.parse(freshChunks[0].trim());
  assert.equal(respObj.id, 101);
  assert.equal(respObj.result.cancelled, true);
  assert.equal(respObj.result.stopReason, 'cancelled');

  // 6. $/cancel_request notification and request handling with requestId and stopReason
  freshEmitter.handleMessage('{"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": "req-99"}}\n');
  assert.equal(freshChunks.length, 1, 'Notification $/cancel_request must not write to stream');
  const cancelReqResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "id": 103, "method": "$/cancel_request", "params": {"requestId": "req-103"}}\n');
  assert.equal(cancelReqResp.id, 103);
  assert.equal(cancelReqResp.result.cancelled, true);
  assert.equal(cancelReqResp.result.stopReason, 'cancelled');

  // 7. Shutdown request handling
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
  const keyPair = crypto.generateKeyPairSync('ed25519');
  const pubPem = keyPair.publicKey.export({ type: 'spki', format: 'pem' });

  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);
  const finding = {
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
  };
  finding.authorityProof = signFindingAuthorityProof(finding, keyPair.privateKey, 'SUPERVISOR_ROOT', pubPem);

  emitter.emitDiagnostic('src/index.js', finding, { trustedRootPublicKeyPem: pubPem, allowConfiguredRoot: true });
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
