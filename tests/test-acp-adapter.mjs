import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as acpModule from '../scripts/adapters/acp-adapter.mjs';
import {
  ACP_DIAGNOSTIC_SEVERITY,
  ACP_SUPERVISOR_PUBLIC_PEM,
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
import { parseGitRemoteOriginUrl, getCanonicalRealPath } from '../scripts/fetch-upstream-oss-fixture.mjs';
import { extractEntry } from '../evals/oss-corpus/post-fix/07-adm-zip-path-traversal.js';

// Load authenticated test supervisor private key corresponding to ACP_SUPERVISOR_PUBLIC_PEM
const privKeyPem = fs.readFileSync(new URL('fixtures/acp-supervisor-test-key.pem', import.meta.url), 'utf8');
const testSupervisorPrivateKey = crypto.createPrivateKey(privKeyPem);
const pubPem = ACP_SUPERVISOR_PUBLIC_PEM;

test('ACP Adapter Capability Isolation (R09-F01 & R10-F01): Zero root override backdoor in public or internal modules', () => {
  // withTestSupervisorRootKey and testKeyStorage are completely ELIMINATED
  assert.equal(typeof acpModule.withTestSupervisorRootKey, 'undefined', 'withTestSupervisorRootKey must not exist');
  assert.equal(typeof acpModule.testKeyStorage, 'undefined', 'testKeyStorage must not exist');
  assert.equal(
    fs.existsSync(new URL('../scripts/adapters/internal/test-root-capability.mjs', import.meta.url)),
    false,
    'internal/test-root-capability.mjs must be completely removed'
  );

  // Attacker cannot forge findings with arbitrary keys
  const attackerKeyPair = crypto.generateKeyPairSync('ed25519');
  const attackerFinding = {
    id: 'ATTACKER-001',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    location: { startLine: 1 }
  };
  attackerFinding.authorityProof = signFindingAuthorityProof(
    attackerFinding,
    attackerKeyPair.privateKey,
    'SUPERVISOR_ROOT',
    attackerKeyPair.publicKey.export({ type: 'spki', format: 'pem' })
  );

  assert.equal(assertFindingDispositionAuthority(attackerFinding), false);
  assert.equal(formatAcpDiagnostic(attackerFinding).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(attackerFinding).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);
});

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

  // Default-Deny Clamping: Unverified candidates clamped to Hint
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', 'UNVERIFIED'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('CRITICAL', 'DEFERRED'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', 'UNCHECKABLE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', 'FALSE_POSITIVE'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', 'SUPPRESSED'), ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(mapSeverityToAcpDiagnostic('HIGH', ''), ACP_DIAGNOSTIC_SEVERITY.HINT);
});

test('ACP Adapter: formatAcpDiagnostic produces standard LSP range and metadata', () => {
  const finding = {
    id: 'FIND-001',
    ruleId: 'CWE-89',
    cwe: 'CWE-89',
    title: 'SQL Injection via query concatenation',
    description: 'Detailed description of SQL injection',
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
  finding.authorityProof = signFindingAuthorityProof(finding, testSupervisorPrivateKey, 'SUPERVISOR_ROOT', pubPem);

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

test('ACP Adapter: R04-F01 / R05-F01 / R06-F01 Spoofed authority claims strictly fail closed to HINT', () => {
  // 1. ChatGPT explicit mandate: REPORTABLE + CRITICAL + lineageId: 'x'
  const spoofedLineage = {
    id: 'SPOOF-01',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    lineageId: 'x',
    location: { startLine: 10 }
  };
  const diagLineage = formatAcpDiagnostic(spoofedLineage);
  assert.equal(diagLineage.data.authorityConfirmed, false);
  assert.equal(diagLineage.severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 2. Empty authorityProof: {}
  const spoofedProof = {
    id: 'SPOOF-02',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    authorityProof: {},
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedProof).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedProof).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 3. Fake consensus: { reached: true }
  const spoofedConsensus = {
    id: 'SPOOF-03',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    consensus: { reached: true },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedConsensus).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedConsensus).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 4. Fake votes summary: { supports: 3 } without ballots array
  const spoofedVotesSummary = {
    id: 'SPOOF-04',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    votes: { supports: 3 },
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(spoofedVotesSummary).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(spoofedVotesSummary).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 5. Ballots with duplicate lenses (Sybil attack / ballot packing)
  const duplicateLensBallots = {
    id: 'SPOOF-05',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS' },
      { lens: 'REACHABILITY', decision: 'SUPPORTS' },
      { lens: 'REACHABILITY', decision: 'SUPPORTS' }
    ],
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(duplicateLensBallots).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(duplicateLensBallots).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 6. Ballots containing explicit refutation must fail closed
  const refutedCandidate = {
    id: 'REFUTED-01',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS' },
      { lens: 'DEFENSES', decision: 'REFUTES' },
      { lens: 'IMPACT', decision: 'SUPPORTS' }
    ],
    location: { startLine: 10 }
  };
  assert.equal(formatAcpDiagnostic(refutedCandidate).data.authorityConfirmed, false);
  assert.equal(formatAcpDiagnostic(refutedCandidate).severity, ACP_DIAGNOSTIC_SEVERITY.HINT);

  // 7. R06-F01 MANDATORY NEGATIVE TEST: Three complete, valid SUPPORTS ballots without cryptographic authorityProof MUST FAIL CLOSED
  const unproven3Ballots = {
    id: 'UNPROVEN-3BALLOTS-01',
    ruleId: 'CWE-89',
    cwe: 'CWE-89',
    title: 'Candidate with 3 complete SUPPORTS ballots but no cryptographic authorityProof',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 10 }] },
      { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 10 }] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'src/db.js', line: 10 }] }
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
    'R06-F01 Invariant: Unproven candidate with 3 ballots must be strictly clamped to HINT'
  );

  // 8. Spoofed signature with invalid cryptographic bytes fails verification
  const forgedSigCandidate = {
    id: 'FORGED-SIG-01',
    ruleId: 'CWE-89',
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

  // 9. Authentic cryptographic Ed25519 signature verified against pinned root
  const validCryptoCandidate = {
    id: 'VALID-CRYPTO-001',
    ruleId: 'CWE-89',
    cwe: 'CWE-89',
    title: 'Authenticated finding with cryptographic attestation',
    description: 'Detailed description of SQL injection',
    severity: 'CRITICAL',
    disposition: 'REPORTABLE',
    securityProperty: 'INTEGRITY',
    findingType: 'VULNERABILITY',
    proofKind: 'STATIC_TRACE',
    remediation: 'Use parameterized queries',
    location: { startLine: 10 }
  };
  validCryptoCandidate.authorityProof = signFindingAuthorityProof(
    validCryptoCandidate,
    testSupervisorPrivateKey,
    'SUPERVISOR_ROOT',
    pubPem
  );

  const diagCrypto = formatAcpDiagnostic(validCryptoCandidate);
  assert.equal(diagCrypto.data.authorityConfirmed, true);
  assert.equal(diagCrypto.severity, ACP_DIAGNOSTIC_SEVERITY.ERROR);

  // 10. R07-F01 & R08-F01 Defense: Tampering with ANY field breaks cryptographic signature binding
  const fieldsToTamper = [
    { field: 'severity', value: 'LOW' },
    { field: 'title', value: 'Tampered title' },
    { field: 'description', value: 'Tampered description' },
    { field: 'cwe', value: 'CWE-79' },
    { field: 'location', value: { startLine: 999 } },
    { field: 'securityProperty', value: 'CONFIDENTIALITY' },
    { field: 'findingType', value: 'DEFECT' },
    { field: 'proofKind', value: 'FUZZING' },
    { field: 'remediation', value: 'Malicious attacker suggestion' },
    { field: 'ballots', value: [{ lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['tampered'] }] }
  ];

  for (const { field, value } of fieldsToTamper) {
    const tamperedCandidate = {
      ...validCryptoCandidate,
      [field]: value
    };
    assert.equal(
      formatAcpDiagnostic(tamperedCandidate).data.authorityConfirmed,
      false,
      `Tampering with field '${field}' must invalidate cryptographic signature`
    );
    assert.equal(
      formatAcpDiagnostic(tamperedCandidate).severity,
      ACP_DIAGNOSTIC_SEVERITY.HINT,
      `Tampering with field '${field}' must clamp severity to HINT`
    );
  }
});

test('ACP Adapter: R03-F03 Self-asserted REPORTABLE without consensus strictly clamped to HINT under Default-Deny', () => {
  const spoofedCandidate = {
    id: 'CAND-001',
    ruleId: 'CWE-89',
    severity: 'HIGH',
    disposition: 'REPORTABLE',
    location: { uri: 'src/db.js', startLine: 10, endLine: 15 }
  };

  const diag = formatAcpDiagnostic(spoofedCandidate);
  assert.equal(diag.data.authorityConfirmed, false);
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT);
});

test('ACP Adapter: R01-F04 / R02-03 Authority Gate strictly clamps candidate with missing disposition', () => {
  const missingDispCandidate = {
    id: 'CAND-002',
    ruleId: 'CWE-89',
    severity: 'CRITICAL',
    location: { uri: 'src/db.js', startLine: 10, endLine: 15 }
  };

  const diag = formatAcpDiagnostic(missingDispCandidate);
  assert.equal(diag.data.authorityConfirmed, false);
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT);
});

test('ACP Adapter: R01-F04 Authority Gate clamps unverified candidate in formatAcpDiagnostic', () => {
  const candidate = {
    id: 'CAND-CWE-89-01',
    ruleId: 'CWE-89',
    title: 'Candidate SQL Injection',
    severity: 'CRITICAL',
    disposition: 'UNVERIFIED',
    location: {
      uri: 'src/app.js',
      startLine: 10,
      endLine: 12,
      startColumn: 1,
      endColumn: 20
    }
  };

  const diag = formatAcpDiagnostic(candidate);

  assert.equal(diag.code, 'CWE-89');
  assert.equal(diag.source, 'Three-Lens');
  assert.equal(diag.severity, ACP_DIAGNOSTIC_SEVERITY.HINT);
  assert.equal(diag.data.authorityConfirmed, false);
});

test('ACP Adapter: R01-F05 Safe integer clamping and boundary defense', () => {
  const weirdFinding = {
    id: 'WEIRD-01',
    ruleId: 'CWE-22',
    severity: 'LOW',
    location: {
      uri: 'src/weird.js',
      startLine: -5,
      endLine: 'invalid',
      startColumn: NaN,
      endColumn: 999999999999999999999
    }
  };

  const diag = formatAcpDiagnostic(weirdFinding);

  assert.equal(diag.range.start.line, 0);
  assert.equal(diag.range.start.character, 0);
  assert.equal(diag.range.end.line, 0);
  assert.equal(diag.range.end.character, 0);
});

test('ACP Adapter: serializeJsonRpcNotification single-line JSON with trailing LF', () => {
  const line = serializeJsonRpcNotification('custom/notify', { key: 'value' });
  assert.ok(line.endsWith('\n'));
  assert.ok(!line.slice(0, -1).includes('\n'));

  const parsed = JSON.parse(line.trim());
  assert.equal(parsed.jsonrpc, '2.0');
  assert.equal(parsed.method, 'custom/notify');
  assert.deepEqual(parsed.params, { key: 'value' });
});

test('ACP Adapter: formatPublishDiagnosticsNotification formats full notification', () => {
  const findings = [
    {
      id: 'F1',
      ruleId: 'CWE-79',
      cwe: 'CWE-79',
      title: 'XSS flaw',
      description: 'XSS flaw description',
      severity: 'MEDIUM',
      disposition: 'REPORTABLE',
      securityProperty: 'INTEGRITY',
      findingType: 'VULNERABILITY',
      proofKind: 'STATIC_TRACE',
      remediation: 'Sanitize HTML output',
      ballots: [
        { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: ['trace'] },
        { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: ['none'] },
        { lens: 'IMPACT', decision: 'SUPPORTS', evidence: ['script execution'] }
      ],
      lineageId: 'lin-f1-01',
      location: { startLine: 10 }
    }
  ];
  findings[0].authorityProof = signFindingAuthorityProof(findings[0], testSupervisorPrivateKey, 'SUPERVISOR_ROOT', pubPem);

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
  assert.ok(parsed.params.message.includes('CAND-CWE-918-01'));
  assert.ok(parsed.params.message.includes('REACHABILITY: CONFIRMED'));
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
});

test('ACP Adapter: R03-F04 / R04-F02 / R05-F02 / R06-F02 / R06-F03 session cancellation, turn isolation, and ACP v1 payload', () => {
  const chunks = [];
  const mockStream = {
    write(chunk) {
      chunks.push(chunk);
    }
  };

  const emitter = createAcpDiagnosticEmitter(mockStream);
  emitter.createSession('sess-1');
  emitter.createSession('sess-2');

  // 1. Session-scoped cancellation: cancel sess-1 turn 1
  const notifCancel = emitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "sess-1", "turnId": 1}}\n');
  assert.equal(notifCancel.cancelled, true);
  assert.equal(notifCancel.sessionId, 'sess-1');
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
  const liveUpdate = emitter.emitSessionUpdate('sess-2', { message: 'analyzing workspace' }, { turnId: 1 });
  assert.ok(liveUpdate !== null);
  assert.equal(chunks.length, 1);
  const updateObj = JSON.parse(chunks[0].trim());
  assert.equal(updateObj.jsonrpc, '2.0');
  assert.equal(updateObj.method, 'session/update');
  assert.equal(updateObj.params.sessionId, 'sess-2');
  assert.equal(updateObj.params.update.sessionUpdate, 'agent_message_chunk');
  assert.deepEqual(updateObj.params.update.content, { type: 'text', text: 'analyzing workspace' });

  // 4. New prompt turn for sess-1 increments turn generation, marks pending, and resets cancellation state (R05-F02, R06-F03 & R09-F02)
  const promptResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 201, "method": "session/prompt", "params": {"sessionId": "sess-1"}}\n');
  assert.equal(promptResp.status, 'processing');
  assert.equal(promptResp.pending, true);
  assert.equal(promptResp.turnId, 2, 'New prompt must advance to turn generation 2');
  assert.equal(emitter.isCancelled('sess-1'), false, 'session/prompt must clear prior session cancellation');
  assert.equal(emitter.isPromptPending('sess-1'), true);

  // R06-F03 & R08-F04 Invariant: Stale emission from old generation turn 1 is rejected, while current turn 2 is allowed
  const staleTurnEmission = emitter.emitSessionUpdate('sess-1', { progress: 0.1 }, { turnId: 1 });
  assert.equal(staleTurnEmission, null, 'Stale turn 1 emission must be rejected under Generation Token invariant');
  const restoredUpdate = emitter.emitSessionUpdate('sess-1', { progress: 0.2 }, { turnId: 2 });
  assert.ok(restoredUpdate !== null, 'Current generation turn 2 emission must be allowed');

  // R09-F02 Defense: Prompt completion binds to pending request ID 201 and emits completion response to stream
  const completionResp = emitter.completePromptTurn('sess-1');
  assert.equal(completionResp.id, 201);
  assert.equal(completionResp.result.status, 'completed');
  assert.equal(completionResp.result.stopReason, 'end_turn');
  assert.equal(completionResp.result.turnId, 2);
  assert.equal(emitter.isPromptPending('sess-1'), false);
  assert.equal(emitter.getSessionState('sess-1'), 'COMPLETED');

  // R08-F04 Invariant: Mandatory Generation Handle - omitting turnId MUST fail closed
  const missingTurnEmission = emitter.emitSessionUpdate('sess-1', { progress: 0.25 });
  assert.equal(missingTurnEmission, null, 'Emissions omitting turnId MUST be rejected fail-closed (R08-F04)');

  // R07-F04 Invariant: Fabricated future turnId (e.g. 999) must be rejected fail-closed
  const futureTurnEmission = emitter.emitSessionUpdate('sess-1', { progress: 0.3 }, { turnId: 999 });
  assert.equal(futureTurnEmission, null, 'Fabricated future turnId must be strictly rejected');

  // R07-F03 & R08-F03 Invariant: session/new initializes session with turn 1 and returns sessionId
  const sessionNewResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 301, "method": "session/new", "params": {"sessionId": "sess-new-1"}}\n');
  assert.equal(sessionNewResp.id, 301);
  assert.equal(sessionNewResp.result.sessionId, 'sess-new-1');
  assert.equal(emitter.getCurrentTurnId('sess-new-1'), 1);

  // R08-F03 Invariant: session/new with duplicate sessionId MUST be rejected
  const duplicateNewResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 302, "method": "session/new", "params": {"sessionId": "sess-new-1"}}\n');
  assert.equal(duplicateNewResp.error.code, -32600);

  // R07-F03 Invariant: Caller attempting to overwrite content structure with invalid object
  const spoofedContentUpdate = emitter.emitSessionUpdate('sess-new-1', { content: { type: 'malicious', rawHtml: '<script>' } }, { turnId: 1 });
  assert.ok(spoofedContentUpdate !== null);
  const spoofedParsed = JSON.parse(spoofedContentUpdate.trim());
  assert.equal(spoofedParsed.params.update.sessionUpdate, 'agent_message_chunk');
  assert.deepEqual(spoofedParsed.params.update.content, { type: 'text', text: '' });

  // 5. In ACP v1, session/cancel is a notification and must not write response to stream
  const freshChunks = [];
  const freshStream = { write(c) { freshChunks.push(c); } };
  const freshEmitter = createAcpDiagnosticEmitter(freshStream);
  freshEmitter.createSession('sess-101');
  const cancelResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "sess-101", "turnId": 1}}\n');
  assert.equal(cancelResp.cancelled, true);
  assert.equal(freshChunks.length, 0, 'Notification session/cancel must not write response to stream (R08-F03)');

  // 6. $/cancel_request notification handling
  freshEmitter.handleMessage('{"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": "req-99"}}\n');
  assert.equal(freshChunks.length, 0, 'Notification $/cancel_request must not write to stream');

  // 7. Shutdown request handling
  const shutdownResp = freshEmitter.handleMessage('{"jsonrpc": "2.0", "id": 102, "method": "shutdown", "params": {}}\n');
  assert.equal(shutdownResp.id, 102);
  assert.equal(shutdownResp.result, null);
  assert.equal(freshEmitter.isShutdown(), true);
});

test('ACP Adapter Lifecycle (R10-F02): concurrent prompt rejection and cancelled turn protection', () => {
  const chunks = [];
  const emitter = createAcpDiagnosticEmitter({ write(c) { chunks.push(c); } });
  emitter.createSession('sess-concurrent');

  // First prompt is registered and kept pending
  const p1 = emitter.handleMessage('{"jsonrpc": "2.0", "id": 101, "method": "session/prompt", "params": {"sessionId": "sess-concurrent"}}\n');
  assert.equal(p1.pending, true);
  assert.equal(p1.id, 101);

  // Second prompt on same session while first is active MUST be rejected with -32600
  const p2 = emitter.handleMessage('{"jsonrpc": "2.0", "id": 102, "method": "session/prompt", "params": {"sessionId": "sess-concurrent"}}\n');
  assert.equal(p2.error.code, -32600);
  assert.ok(p2.error.message.includes('already has an active pending prompt turn'));

  // First prompt remains unresolved and intact
  assert.equal(emitter.getPendingPrompt('sess-concurrent').id, 101);

  // Completing the turn resolves request 101
  const comp = emitter.completePromptTurn('sess-concurrent');
  assert.equal(comp.id, 101);
  assert.equal(emitter.getSessionState('sess-concurrent'), 'COMPLETED');

  // Extra completePromptTurn without active pending prompt returns null
  assert.equal(emitter.completePromptTurn('sess-concurrent'), null);

  // Cancelled session cannot transition to COMPLETED
  emitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "sess-concurrent"}}\n');
  assert.equal(emitter.getSessionState('sess-concurrent'), 'CANCELLED');
  assert.equal(emitter.completePromptTurn('sess-concurrent'), null);
  assert.equal(emitter.getSessionState('sess-concurrent'), 'CANCELLED');
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
  const sid = emitter.createSession('sess-stream-test');

  const finding = {
    id: 'F-1',
    ruleId: 'CWE-22',
    cwe: 'CWE-22',
    title: 'Path traversal flaw',
    description: 'Path traversal flaw description',
    severity: 'CRITICAL',
    disposition: 'CONFIRMED',
    securityProperty: 'INTEGRITY',
    findingType: 'VULNERABILITY',
    proofKind: 'STATIC_TRACE',
    remediation: 'Sanitize target paths',
    ballots: [
      { lens: 'REACHABILITY', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] },
      { lens: 'DEFENSES', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] },
      { lens: 'IMPACT', decision: 'SUPPORTS', evidence: [{ path: 'src/index.js', line: 1 }] }
    ],
    lineageId: 'lin-f1-crit',
    location: { startLine: 1 }
  };
  finding.authorityProof = signFindingAuthorityProof(finding, testSupervisorPrivateKey, 'SUPERVISOR_ROOT', pubPem);

  // Emitting without turnId or with unknown session must fail closed
  assert.equal(emitter.emitDiagnostic('src/index.js', finding, { sessionId: sid }), null);
  assert.equal(emitter.emitDiagnostic('src/index.js', finding, { sessionId: 'unknown-sess', turnId: 1 }), null);

  // Authenticated finding emits with valid turnId
  emitter.emitDiagnostic('src/index.js', finding, { sessionId: sid, turnId: 1 });
  emitter.emitBallotProgress('CAND-01', 'DEFENSES', 'REFUTES', 'Sanitizer active', { sessionId: sid, turnId: 1 });

  assert.equal(chunks.length, 2);
  const diagParsed = JSON.parse(chunks[0].trim());
  assert.equal(diagParsed.method, 'textDocument/publishDiagnostics');
  assert.equal(diagParsed.params.diagnostics[0].code, 'CWE-22');
  assert.equal(diagParsed.params.diagnostics[0].severity, 1);

  const ballotParsed = JSON.parse(chunks[1].trim());
  assert.equal(ballotParsed.method, 'window/logMessage');
  assert.ok(ballotParsed.params.message.includes('DEFENSES: REFUTES'));
});

test('Harness Governance (R08-F07, R09-F04 & R10-F04): parseGitRemoteOriginUrl strictly respects case-sensitive remote subsections', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'git-config-case-'));
  try {
    const configPath = path.join(tmpDir, 'config');

    // 1. Config containing [remote "Origin"] (capital O) first, then [remote "origin"] (lowercase o)
    const mixedCaseConfig = `
[core]
  repositoryformatversion = 0
[remote "Origin"]
  url = https://example.invalid/decoy.git
[remote "origin"]
  url = https://github.com/cthackers/adm-zip.git
`;
    fs.writeFileSync(configPath, mixedCaseConfig, 'utf8');

    // R10-F04: Must match exact case: 'origin' must return the lowercase origin URL, NOT decoy!
    assert.equal(parseGitRemoteOriginUrl(configPath, 'origin'), 'https://github.com/cthackers/adm-zip.git');
    // 'Origin' must return the capital Origin URL
    assert.equal(parseGitRemoteOriginUrl(configPath, 'Origin'), 'https://example.invalid/decoy.git');
    // Non-matching case returns null
    assert.equal(parseGitRemoteOriginUrl(configPath, 'ORIGIN'), null);

    // 2. Config without origin returns null
    const noOriginConfig = `
[core]
  repositoryformatversion = 0
[remote "upstream"]
  url = https://github.com/upstream/repo.git
`;
    fs.writeFileSync(configPath, noOriginConfig, 'utf8');
    assert.equal(parseGitRemoteOriginUrl(configPath), null);
    assert.equal(parseGitRemoteOriginUrl(configPath, 'upstream'), 'https://github.com/upstream/repo.git');

    // 3. Nonexistent config returns null
    assert.equal(parseGitRemoteOriginUrl(path.join(tmpDir, 'nonexistent')), null);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('Harness Governance (R08-F05, R08-F06, R09-F03 & R10-F03): getCanonicalRealPath and adm-zip path containment defense', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'admzip-test-'));
  try {
    const sandboxDir = path.join(tmpDir, 'target');
    fs.mkdirSync(sandboxDir, { recursive: true });

    // 1. Traversal attempt out of sandbox throws INVALID_FILENAME
    assert.throws(
      () => extractEntry(sandboxDir, '../escape.txt', 'malicious'),
      /INVALID_FILENAME/
    );

    // 2. Normal extraction creates file safely via staging and non-replacing placement
    const created = extractEntry(sandboxDir, 'subdir/normal.txt', 'hello world');
    assert.ok(fs.existsSync(created));
    assert.equal(fs.readFileSync(created, 'utf8'), 'hello world');

    // 3. Dangling symlink inside sandbox is detected and rejected
    const danglingSymlink = path.join(sandboxDir, 'dangling-link');
    try {
      fs.symlinkSync(path.join(tmpDir, 'nonexistent-target'), danglingSymlink, 'file');
      assert.throws(
        () => extractEntry(sandboxDir, 'dangling-link/traversal.txt', 'payload'),
        /SECURITY_ERROR/
      );
    } catch (symlinkErr) {
      if (symlinkErr.code !== 'EPERM') throw symlinkErr;
    }

    // 4. Ancestor directory symlink redirection is detected and rejected (R09-F03)
    const ancestorSubdir = path.join(sandboxDir, 'ancestor-test');
    fs.mkdirSync(ancestorSubdir, { recursive: true });
    const externalDir = path.join(tmpDir, 'external-escaped');
    fs.mkdirSync(externalDir, { recursive: true });
    try {
      const symlinkAncestor = path.join(ancestorSubdir, 'symlink-parent');
      fs.symlinkSync(externalDir, symlinkAncestor, 'dir');
      assert.throws(
        () => extractEntry(sandboxDir, 'ancestor-test/symlink-parent/escape.txt', 'payload'),
        /SECURITY_ERROR/
      );
    } catch (symlinkErr) {
      if (symlinkErr.code !== 'EPERM') throw symlinkErr;
    }

    // 5. R10-F03 Defense: Pre-existing destination file is NEVER overwritten or deleted
    const preExistingFile = path.join(sandboxDir, 'subdir', 'pre-existing.txt');
    fs.mkdirSync(path.dirname(preExistingFile), { recursive: true });
    fs.writeFileSync(preExistingFile, 'ORIGINAL_SACROSANCT_CONTENT', 'utf8');
    assert.throws(
      () => extractEntry(sandboxDir, 'subdir/pre-existing.txt', 'MALICIOUS_OVERWRITE_PAYLOAD'),
      /SECURITY_ERROR/
    );
    // Crucial: Original content MUST survive uncorrupted!
    assert.equal(fs.readFileSync(preExistingFile, 'utf8'), 'ORIGINAL_SACROSANCT_CONTENT');
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('ACP Adapter Emission Gate (R09-F05 & R10-F05): numerical requestId 0 and bounded tracking', () => {
  const chunks = [];
  const emitter = createAcpDiagnosticEmitter({ write(c) { chunks.push(c); } });
  emitter.createSession('sess-req0');

  // Cancel request with numerical requestId: 0
  emitter.handleMessage('{"jsonrpc": "2.0", "method": "$/cancel_request", "params": {"requestId": 0}}\n');

  // Emission with requestId: 0 MUST be blocked fail-closed
  const blockedEmission = emitter.emitSessionUpdate('sess-req0', { message: 'test' }, { turnId: 1, requestId: 0 });
  assert.equal(blockedEmission, null, 'requestId: 0 must not bypass cancellation check (R09-F05)');

  // Emission with another uncancelled requestId is allowed
  const allowedEmission = emitter.emitSessionUpdate('sess-req0', { message: 'allowed' }, { turnId: 1, requestId: 1 });
  assert.ok(allowedEmission !== null);
});

test('ACP Adapter Lifecycle (R09-F02): pending session/prompt request is cancelled with bound ID when session/cancel is received', () => {
  const chunks = [];
  const emitter = createAcpDiagnosticEmitter({ write(c) { chunks.push(c); } });
  emitter.createSession('sess-cancel-prompt');

  // Receive prompt request
  const promptResp = emitter.handleMessage('{"jsonrpc": "2.0", "id": 555, "method": "session/prompt", "params": {"sessionId": "sess-cancel-prompt"}}\n');
  assert.equal(promptResp.pending, true);
  assert.equal(promptResp.id, 555);
  assert.equal(chunks.length, 0, 'No completion written before analysis completes');

  // Receive session/cancel notification while prompt is pending
  emitter.handleMessage('{"jsonrpc": "2.0", "method": "session/cancel", "params": {"sessionId": "sess-cancel-prompt"}}\n');
  assert.equal(chunks.length, 1, 'Cancellation response emitted for pending prompt request');
  const cancelResp = JSON.parse(chunks[0].trim());
  assert.equal(cancelResp.id, 555);
  assert.equal(cancelResp.result.status, 'cancelled');
  assert.equal(cancelResp.result.stopReason, 'cancelled');
  assert.equal(emitter.isPromptPending('sess-cancel-prompt'), false);
  assert.equal(emitter.getSessionState('sess-cancel-prompt'), 'CANCELLED');
});
