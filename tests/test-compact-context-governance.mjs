import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import {
  createCompactedStateEnvelope,
  serializeCompactedAuditHeader,
  extractCompactedAuditHeader,
  validateCompactedStateEnvelope,
  assertCompactSafe,
  sha256Digest,
  canonicalJsonStringify,
  COMPACT_SCHEMA_VERSION,
  COMPACT_ENVELOPE_TYPE,
  COMPACT_HEADER_DELIMITER_START,
  COMPACT_HEADER_DELIMITER_END
} from '../skills/3lens/scripts/compact-guard.mjs';
import { finalizeScan } from '../skills/3lens/scripts/finalize-scan.mjs';

const VALID_SAMPLE_STATE = Object.freeze({
  scanRunId: 'scan-run-20261107-1530-abc',
  executionNonce: 'NONCE-SEC-777-XYZ-888',
  toolManifestDigest: '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95',
  repoRootFingerprint: 'repo-sha256-112233445566',
  persistedState: {
    targetDirectories: ['src', 'lib', 'packages'],
    scannedFilesCount: 42,
    activeCandidates: ['VULN-001', 'VULN-002']
  }
});

test('Compact Governance: createCompactedStateEnvelope builds canonical envelope with valid stateDigest', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);

  assert.equal(env.schemaVersion, COMPACT_SCHEMA_VERSION);
  assert.equal(env.envelopeType, COMPACT_ENVELOPE_TYPE);
  assert.equal(env.scanRunId, VALID_SAMPLE_STATE.scanRunId);
  assert.equal(env.executionNonce, VALID_SAMPLE_STATE.executionNonce);
  assert.equal(env.toolManifestDigest, VALID_SAMPLE_STATE.toolManifestDigest);
  assert.ok(typeof env.stateDigest === 'string' && env.stateDigest.length === 64);

  const validation = validateCompactedStateEnvelope(env);
  assert.equal(validation.valid, true);
  assert.equal(validation.error, null);
});

test('Compact Governance: Missing scanRunId or executionNonce strictly throws error', () => {
  assert.throws(
    () => createCompactedStateEnvelope({ executionNonce: 'NONCE-123' }),
    /Missing or empty scanRunId/
  );

  assert.throws(
    () => createCompactedStateEnvelope({ scanRunId: 'RUN-123' }),
    /Missing or empty executionNonce/
  );
});

test('Compact Governance: Serialization and extraction preserves exact cryptographic fidelity', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  assert.ok(serialized.includes(COMPACT_HEADER_DELIMITER_START));
  assert.ok(serialized.includes(COMPACT_HEADER_DELIMITER_END));

  const surroundingChatTranscript = [
    'User requested full security audit of repository.',
    'Inventory generated: 42 files discovered.',
    serialized,
    'Threat model built: 3 trust boundaries identified.',
    'Awaiting verifier ballots.'
  ].join('\n\n');

  const extracted = extractCompactedAuditHeader(surroundingChatTranscript);
  assert.equal(extracted.valid, true);
  assert.equal(extracted.error, null);
  assert.equal(extracted.envelope.scanRunId, VALID_SAMPLE_STATE.scanRunId);
  assert.equal(extracted.envelope.executionNonce, VALID_SAMPLE_STATE.executionNonce);
  assert.equal(extracted.envelope.stateDigest, env.stateDigest);
});

test('Compact Governance: Tampering with state fields in extracted envelope fails closed', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  // Tamper executionNonce inside serialized text
  const tamperedText = serialized.replace(VALID_SAMPLE_STATE.executionNonce, 'TAMPERED-NONCE-999');

  const extracted = extractCompactedAuditHeader(tamperedText);
  assert.equal(extracted.valid, false);
  assert.ok(extracted.error.includes('Tamper detected') || extracted.error.includes('stateDigest'));
});

test('Compact Governance: Truncated delimiter block fails closed', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  // Remove end delimiter to simulate truncation
  const truncatedText = serialized.replace(COMPACT_HEADER_DELIMITER_END, '');

  const extracted = extractCompactedAuditHeader(truncatedText);
  assert.equal(extracted.valid, false);
  assert.ok(extracted.error.includes('Missing or truncated'));
});

test('Compact Governance: Ed25519 cryptographic signing and verification', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE, {
    signerPrivateKey: privateKey,
    signerKeyId: 'ED25519-SUPERVISOR-ROOT-TEST'
  });

  assert.equal(env.signedBy, 'ED25519-SUPERVISOR-ROOT-TEST');
  assert.ok(typeof env.signature === 'string' && env.signature.length > 0);

  // Verification with valid public key
  const validCheck = validateCompactedStateEnvelope(env, {}, { verifierPublicKey: publicKey });
  assert.equal(validCheck.valid, true);

  // Verification with wrong public key fails closed
  const { publicKey: wrongKey } = crypto.generateKeyPairSync('ed25519');
  const wrongCheck = validateCompactedStateEnvelope(env, {}, { verifierPublicKey: wrongKey });
  assert.equal(wrongCheck.valid, false);
  assert.ok(wrongCheck.error.includes('signature verification failed'));
});

test('Compact Governance: assertCompactSafe verifies uncompromised compaction transition', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE);
  const serialized = serializeCompactedAuditHeader(env);

  const compactedTranscript = [
    '### Conversation History Compacted by /compact',
    'Previous analysis concluded inventory mapping.',
    serialized,
    'Continuing to 3-lens verifier consensus.'
  ].join('\n\n');

  const result = assertCompactSafe(VALID_SAMPLE_STATE, compactedTranscript);
  assert.equal(result.safe, true);
  assert.equal(result.error, null);
  assert.equal(result.envelope.scanRunId, VALID_SAMPLE_STATE.scanRunId);
});

test('Compact Governance: assertCompactSafe rejects when compaction strips envelope', () => {
  const strippedTranscript = [
    '### Conversation History Compacted by /compact',
    'All details summarized: audit in progress.',
    'Continuing to 3-lens verifier consensus.'
  ].join('\n\n');

  const result = assertCompactSafe(VALID_SAMPLE_STATE, strippedTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('Compaction stripped audit state envelope'));
});

test('Compact Governance: assertCompactSafe rejects executionNonce replay divergence', () => {
  const olderState = {
    ...VALID_SAMPLE_STATE,
    executionNonce: 'REPLAY-OLD-NONCE-111'
  };
  const env = createCompactedStateEnvelope(olderState);
  const serialized = serializeCompactedAuditHeader(env);

  const replayTranscript = [
    '### Conversation History Compacted',
    serialized
  ].join('\n\n');

  // Verify against current expected state
  const result = assertCompactSafe(VALID_SAMPLE_STATE, replayTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('Nonce mismatch') || result.error.includes('invariant violation'));
});

test('Compact Governance: F05 - assertCompactSafe catches mutated persistedState via deep comparison', () => {
  const originalState = {
    ...VALID_SAMPLE_STATE,
    persistedState: {
      candidatesReviewed: 5,
      ballotCounts: { pass: 5, fail: 0 }
    }
  };
  const env = createCompactedStateEnvelope(originalState);

  // Attacker crafts transcript with altered persistedState and recomputed stateDigest
  const tamperedEnv = JSON.parse(JSON.stringify(env));
  tamperedEnv.persistedState.ballotCounts.pass = 99; // Forged votes
  tamperedEnv.persistedStateDigest = sha256Digest(canonicalJsonStringify(tamperedEnv.persistedState));
  const tamperedPayload = {
    scanRunId: tamperedEnv.scanRunId,
    executionNonce: tamperedEnv.executionNonce,
    toolManifestDigest: tamperedEnv.toolManifestDigest,
    repoRootFingerprint: tamperedEnv.repoRootFingerprint,
    persistedStateDigest: tamperedEnv.persistedStateDigest,
    persistedState: tamperedEnv.persistedState
  };
  tamperedEnv.stateDigest = sha256Digest(canonicalJsonStringify(tamperedPayload));

  const serializedTampered = serializeCompactedAuditHeader(tamperedEnv);

  const compactedTranscript = [
    '### Conversation History Compacted by /compact',
    serializedTampered,
    'Proceeding to report.'
  ].join('\n\n');

  const result = assertCompactSafe(originalState, compactedTranscript);
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('persistedState tamper detected') || result.error.includes('deep immutable comparison failed'));
});

test('Compact Governance: F05 - Mandatory signature enforcement fails closed when unsigned', () => {
  const env = createCompactedStateEnvelope(VALID_SAMPLE_STATE); // unsigned
  const serialized = serializeCompactedAuditHeader(env);
  const transcript = `### History\n${serialized}\nDone.`;

  const result = assertCompactSafe(VALID_SAMPLE_STATE, transcript, { requireSignature: true });
  assert.equal(result.safe, false);
  assert.ok(result.error.includes('missing required cryptographic signature'));
});

test('Compact Governance: F06 - finalizeScan wires CASE guard and fails closed to UNCHECKABLE on corrupted envelope', () => {
  const corruptedContent = '<!-- THREE_LENS_COMPACT_STATE_START -->\n```json\n{"invalid":"data"}\n```\n<!-- THREE_LENS_COMPACT_STATE_END -->';

  const res = finalizeScan({
    repoRoot: process.cwd(),
    compactedAuditContent: corruptedContent
  });

  assert.equal(res.coverageStatus, 'UNCHECKABLE');
  assert.equal(res.summary.assuranceLabel, 'UNCHECKABLE');
  assert.equal(res.summary.canDeclareClean, false);
  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.equal(res.compactGuard.status, 'UNCHECKABLE');
});

test('Compact Governance: F06 - finalizeScan accepts valid CASE envelope', () => {
  const scanRunId = 'scan-run-valid-999';
  const executionNonce = 'NONCE-LEGAL-777';
  const toolManifestDigest = '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95';
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const verifierPublicKey = publicKey.export({ type: 'spki', format: 'pem' });

  // 1. Unsigned envelope -> UNAUTHENTICATED
  const unsignedEnvelope = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest,
    repoRootFingerprint: ''
  });

  const resUnsigned = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    toolProvenance: { toolIntegrityDigest: toolManifestDigest },
    compactedAuditEnvelope: unsignedEnvelope,
    preCompactionState: {
      scanRunId,
      executionNonce,
      toolManifestDigest
    }
  });

  // R08-B06: In compacted session, UNAUTHENTICATED envelope fails compactGate under Default-Deny
  assert.equal(resUnsigned.summary.gates.compactGate, false);
  assert.equal(resUnsigned.compactGuard.valid, true);
  assert.equal(resUnsigned.compactGuard.status, 'UNAUTHENTICATED');

  // 2. Cryptographically signed envelope -> VERIFIED
  const signedEnvelope = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest,
    repoRootFingerprint: ''
  }, {
    signerPrivateKey: privateKey,
    signerKeyId: 'KEY-SUPERVISOR-TEST'
  });

  const resSigned = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    toolProvenance: { toolIntegrityDigest: toolManifestDigest },
    compactOptions: { verifierPublicKey },
    compactedAuditEnvelope: signedEnvelope,
    preCompactionState: {
      scanRunId,
      executionNonce,
      toolManifestDigest
    }
  });

  assert.equal(resSigned.summary.gates.compactGate, true);
  assert.equal(resSigned.compactGuard.valid, true);
  assert.equal(resSigned.compactGuard.status, 'VERIFIED');
});

test('Compact Governance: F05 - requireSignature fails closed when verifierPublicKey is omitted', () => {
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const signedEnv = createCompactedStateEnvelope(VALID_SAMPLE_STATE, {
    signerPrivateKey: privateKey,
    signerKeyId: 'KEY-TEST'
  });

  const res = validateCompactedStateEnvelope(signedEnv, {}, { requireSignature: true });
  assert.equal(res.valid, false);
  assert.ok(res.error.includes('options.verifierPublicKey is required when requireSignature is enabled'));
});

test('Compact Governance: F06 - finalizeScan fails closed when isCompactedSession is true and envelope is missing', () => {
  const res = finalizeScan({
    repoRoot: process.cwd(),
    isCompactedSession: true
  });

  assert.equal(res.coverageStatus, 'UNCHECKABLE');
  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.ok(res.compactGuard.error.includes('Mandatory compacted audit state envelope missing'));
});

test('Compact Governance: F06 - finalizeScan detects preCompactionState tampering across compaction', () => {
  const originalState = {
    ...VALID_SAMPLE_STATE,
    persistedState: { targetDirectories: ['src'], scannedFilesCount: 10 }
  };
  const env = createCompactedStateEnvelope(originalState);
  const tamperedEnv = JSON.parse(JSON.stringify(env));
  tamperedEnv.persistedState.scannedFilesCount = 999;
  tamperedEnv.persistedStateDigest = sha256Digest(canonicalJsonStringify(tamperedEnv.persistedState));
  const payload = {
    scanRunId: tamperedEnv.scanRunId,
    executionNonce: tamperedEnv.executionNonce,
    toolManifestDigest: tamperedEnv.toolManifestDigest,
    repoRootFingerprint: tamperedEnv.repoRootFingerprint,
    persistedStateDigest: tamperedEnv.persistedStateDigest,
    persistedState: tamperedEnv.persistedState
  };
  tamperedEnv.stateDigest = sha256Digest(canonicalJsonStringify(payload));

  const res = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId: originalState.scanRunId,
    nonce: originalState.executionNonce,
    toolProvenance: { toolIntegrityDigest: originalState.toolManifestDigest },
    preCompactionState: originalState,
    compactedAuditEnvelope: tamperedEnv
  });

  assert.equal(res.coverageStatus, 'UNCHECKABLE');
  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.ok(res.compactGuard.error.includes('persistedState tamper detected') || res.compactGuard.error.includes('deep immutable comparison failed'));
});

test('Compact Governance: R03-B06 - validateCompactedStateEnvelope fails closed if expected toolManifestDigest is missing in envelope', () => {
  const envWithoutDigest = createCompactedStateEnvelope({
    scanRunId: 'scan-run-123',
    executionNonce: 'NONCE-123',
    toolManifestDigest: '',
    repoRootFingerprint: ''
  });

  const res = validateCompactedStateEnvelope(envWithoutDigest, {
    toolManifestDigest: '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95'
  });

  assert.equal(res.valid, false);
  assert.ok(res.error.includes('Tool manifest digest mismatch') || res.error.includes('Tool manifest mismatch'));
});

test('Compact Governance: R03-B06 - extractCompactedAuditHeader handles JSON containing embedded code fences', () => {
  const stateWithFence = {
    scanRunId: 'scan-run-fenced',
    executionNonce: 'NONCE-FENCED',
    toolManifestDigest: 'abc',
    repoRootFingerprint: 'xyz',
    persistedState: {
      embeddedSnippet: '```javascript\nconsole.log("hello");\n```'
    }
  };
  const env = createCompactedStateEnvelope(stateWithFence);
  const serialized = serializeCompactedAuditHeader(env);
  const text = `Pre-context\n${serialized}\nPost-context`;

  const extracted = extractCompactedAuditHeader(text);
  assert.equal(extracted.valid, true);
  assert.equal(extracted.envelope.scanRunId, 'scan-run-fenced');
  assert.equal(extracted.envelope.persistedState.embeddedSnippet, '```javascript\nconsole.log("hello");\n```');
});

test('Compact Governance: R05-B05 - finalizeScan strictly fails closed to UNCHECKABLE without preCompactionState or verified signature', () => {
  const scanRunId = 'scan-run-unanchored';
  const executionNonce = 'NONCE-UNANCHORED';
  const probe = finalizeScan({ repoRoot: process.cwd() });
  const effectiveDigest = probe.modelProvenance?.toolIntegrityDigest || '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95';

  const unanchoredEnvelope = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest: effectiveDigest,
    repoRootFingerprint: ''
  });

  // Calling finalizeScan with envelope but omitting preCompactionState and verifier signature
  const res = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    compactedAuditEnvelope: unanchoredEnvelope,
    isCompactedSession: true
  });

  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.equal(res.compactGuard.status, 'UNCHECKABLE');
  assert.ok(res.compactGuard.error.includes('authoritative integrity basis') || res.compactGuard.error.includes('R05-B05'));
});

test('Compact Governance: R07 F-02 - finalizeScan rejects preCompactionState attempting to forge toolManifestDigest', () => {
  const scanRunId = 'scan-run-f02';
  const executionNonce = 'NONCE-F02';
  const trustedDigest = '4181b74228073574f7368da52bacc3db859c4de81d9d257f59c8da9133960db9';
  const forgedDigest = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef';

  const envelope = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest: forgedDigest,
    repoRootFingerprint: ''
  });

  const res = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    toolProvenance: { toolIntegrityDigest: trustedDigest },
    compactedAuditEnvelope: envelope,
    preCompactionState: {
      scanRunId,
      executionNonce,
      toolManifestDigest: forgedDigest
    }
  });

  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.equal(res.compactGuard.status, 'UNCHECKABLE');
  assert.ok(res.compactGuard.error.includes('does not match trusted runtime tool provenance'));
});

test('Compact Governance: R07 F-06 - CASE signature payload binds signedBy and rejects tampered signedBy', () => {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const verifierPublicKey = publicKey.export({ type: 'spki', format: 'pem' });

  const signedEnv = createCompactedStateEnvelope(VALID_SAMPLE_STATE, {
    signerPrivateKey: privateKey,
    signerKeyId: 'KEY-ORIGINAL-SIGNER'
  });

  // 1. Valid signature passes
  const validRes = validateCompactedStateEnvelope(signedEnv, {}, { verifierPublicKey });
  assert.equal(validRes.valid, true);
  assert.equal(validRes.signatureValid, true);

  // 2. Tampering with signedBy breaks signature verification
  const tamperedSignedByEnv = {
    ...signedEnv,
    signedBy: 'KEY-FORGED-SIGNER'
  };
  const tamperedRes = validateCompactedStateEnvelope(tamperedSignedByEnv, {}, { verifierPublicKey });
  assert.equal(tamperedRes.valid, false);
  assert.ok(tamperedRes.error.includes('Cryptographic signature verification failed'));
});

test('Compact Governance: R08-B03 - finalizeScan rejects conflict between caller expectedToolManifestDigest and authoritative runtime provenance', () => {
  const scanRunId = 'scan-run-r08-b03';
  const executionNonce = 'NONCE-LEGAL-R08';
  const runtimeDigest = '0e8304a3977f26417792906eb4e34edfbad60b4832ba4832311f986fd7e35f95';
  const conflictingCallerDigest = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const verifierPublicKey = publicKey.export({ type: 'spki', format: 'pem' });

  const signedEnv = createCompactedStateEnvelope({
    scanRunId,
    executionNonce,
    toolManifestDigest: runtimeDigest,
    repoRootFingerprint: ''
  }, {
    signerPrivateKey: privateKey,
    signerKeyId: 'KEY-SUPERVISOR-TEST'
  });

  const res = finalizeScan({
    repoRoot: process.cwd(),
    scanRunId,
    nonce: executionNonce,
    toolProvenance: { toolIntegrityDigest: runtimeDigest },
    compactOptions: {
      verifierPublicKey,
      expectedToolManifestDigest: conflictingCallerDigest
    },
    compactedAuditEnvelope: signedEnv,
    preCompactionState: {
      scanRunId,
      executionNonce,
      toolManifestDigest: runtimeDigest
    }
  });

  assert.equal(res.summary.gates.compactGate, false);
  assert.equal(res.compactGuard.valid, false);
  assert.equal(res.compactGuard.status, 'UNCHECKABLE');
  assert.ok(res.compactGuard.error.includes('[TOOL_DIGEST_AUTHORITY_CONFLICT]'));
});
