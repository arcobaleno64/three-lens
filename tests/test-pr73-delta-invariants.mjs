import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');

const { scanForSecrets } = await import(`file:///${path.join(repoRoot, 'hooks/pre-invocation-secret-guard.mjs').replace(/\\/g, '/')}`);
const {
  verifyToolSelfIntegrity,
  generateToolIntegrityManifest,
  redactSecrets,
  tokenizeSecretsForContext,
  validateVoteEvidence,
  deriveFinalDisposition,
  REQUIRED_CRITICAL_SCRIPTS
} = await import(`file:///${path.join(repoRoot, 'skills/3lens/scripts/finalize-scan.mjs').replace(/\\/g, '/')}`);
const { sanitizeSourceText } = await import(`file:///${path.join(repoRoot, 'skills/3lens/scripts/prepare-review-context.mjs').replace(/\\/g, '/')}`);

test('PR #73 Delta - TCB-01: Hook inclusion and integrity gate boundaries', async (t) => {
  await t.test('REQUIRED_CRITICAL_SCRIPTS contains hooks/pre-invocation-secret-guard.mjs', () => {
    assert.ok(
      REQUIRED_CRITICAL_SCRIPTS.includes('hooks/pre-invocation-secret-guard.mjs'),
      'hooks/pre-invocation-secret-guard.mjs must be pinned in REQUIRED_CRITICAL_SCRIPTS'
    );
  });

  await t.test('verifyToolSelfIntegrity passes on clean production scripts', () => {
    const res = verifyToolSelfIntegrity(path.resolve(repoRoot, 'skills/3lens'), repoRoot, { allowSelfAudit: true });
    assert.equal(res.valid, true);
    assert.equal(res.status, 'SELF_AUDIT_MODE');
  });

  await t.test('verifyToolSelfIntegrity detects tampered secret guard hook fail-closed', () => {
    const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcb-hook-sandbox-'));
    try {
      fs.cpSync(path.join(repoRoot, 'skills/3lens'), path.join(sandboxDir, 'skills/3lens'), { recursive: true });
      fs.cpSync(path.join(repoRoot, 'hooks'), path.join(sandboxDir, 'hooks'), { recursive: true });

      const hookFile = path.join(sandboxDir, 'hooks/pre-invocation-secret-guard.mjs');
      const hookContent = fs.readFileSync(hookFile, 'utf8');
      fs.writeFileSync(hookFile, hookContent + '\n// tampered line\n', 'utf8');

      const res = verifyToolSelfIntegrity(path.join(sandboxDir, 'skills/3lens'), sandboxDir, { allowSelfAudit: true });
      assert.equal(res.valid, false, 'Tampered hook must invalidate TCB');
      assert.equal(res.status, 'INTEGRITY_VIOLATION');
    } finally {
      fs.rmSync(sandboxDir, { recursive: true, force: true });
    }
  });

  await t.test('verifyToolSelfIntegrity detects simultaneous hook and manifest manipulation without valid digest', () => {
    const sandboxDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tcb-hook-sandbox2-'));
    try {
      fs.cpSync(path.join(repoRoot, 'skills/3lens'), path.join(sandboxDir, 'skills/3lens'), { recursive: true });
      fs.cpSync(path.join(repoRoot, 'hooks'), path.join(sandboxDir, 'hooks'), { recursive: true });

      const manifestFile = path.join(sandboxDir, 'skills/3lens/tool-integrity-manifest.json');
      const manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
      manifest.criticalScripts['hooks/pre-invocation-secret-guard.mjs'] = '0'.repeat(64);
      fs.writeFileSync(manifestFile, JSON.stringify(manifest, null, 2), 'utf8');

      const res = verifyToolSelfIntegrity(path.join(sandboxDir, 'skills/3lens'), sandboxDir, { allowSelfAudit: true });
      assert.equal(res.valid, false);
      assert.equal(res.status, 'INTEGRITY_VIOLATION');
    } finally {
      fs.rmSync(sandboxDir, { recursive: true, force: true });
    }
  });
});

test('PR #73 Delta - JWT-01: Whitespace formatted and compact JWT detection & redaction', async (t) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const compactPayload = Buffer.from(JSON.stringify({ sub: '1234567890', iat: 1516239022 })).toString('base64url');
  const formattedPayload = Buffer.from(JSON.stringify({ sub: '1234567890', iat: 1516239022 }, null, 2)).toString('base64url');
  const sig = 'SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  const compactJWT = `${header}.${compactPayload}.${sig}`;
  const formattedJWT = `${header}.${formattedPayload}.${sig}`;

  await t.test('scanForSecrets detects both compact and formatted JWTs', () => {
    const hitsCompact = scanForSecrets(compactJWT);
    const hitsFormatted = scanForSecrets(formattedJWT);
    assert.ok(hitsCompact && hitsCompact.length > 0, 'Compact JWT must be detected');
    assert.ok(hitsFormatted && hitsFormatted.length > 0, 'Formatted JWT must be detected');
  });

  await t.test('redactSecrets sanitizes both compact and formatted JWTs', () => {
    const redactedCompact = redactSecrets(compactJWT);
    const redactedFormatted = redactSecrets(formattedJWT);
    assert.notEqual(redactedCompact, compactJWT);
    assert.notEqual(redactedFormatted, formattedJWT);
    assert.match(redactedCompact, /\[REDACTED_JWT_TOKEN;.*fp=[a-f0-9]+\]/);
    assert.match(redactedFormatted, /\[REDACTED_JWT_TOKEN;.*fp=[a-f0-9]+\]/);
  });

  await t.test('Bearer prefix works for both formatted and compact JWTs', () => {
    const bearerCompact = `Bearer ${compactJWT}`;
    const bearerFormatted = `Bearer ${formattedJWT}`;
    assert.ok(scanForSecrets(bearerCompact));
    assert.ok(scanForSecrets(bearerFormatted));
  });

  await t.test('Invalid or arbitrary strings do not trigger JWT pattern false positive', () => {
    const falseToken = 'eyJhbGciOiJIUzI1NiJ9.notbase64!';
    assert.equal(scanForSecrets(falseToken), null);
  });
});

test('PR #73 Delta - QUOTE-01: Verifier tokenized placeholder evidence quote binding', async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'quote-sandbox-'));
  try {
    const secretLine = 'const awsKey = "AKIAIOSFODNN7EXAMPLE";';
    const targetFile = path.join(tempDir, 'test-secret.js');
    fs.writeFileSync(targetFile, secretLine + '\n', 'utf8');

    const tokenizedQuote = tokenizeSecretsForContext(secretLine).tokenizedText;

    const candidate = {
      id: 'CAND-01',
      findingId: 'CAND-01',
      ruleId: 'SEC-001',
      title: 'Secret leak',
      severity: 'HIGH',
      location: { uri: 'test-secret.js', startLine: 1, endLine: 1 },
      attackPath: { steps: [{ uri: 'test-secret.js', line: 1 }] }
    };

    const voteTokenized = {
      findingId: 'CAND-01',
      reviewerId: 'verifier-reachability',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ file: 'test-secret.js', line: 1, quote: tokenizedQuote }]
    };

    const voteRaw = {
      findingId: 'CAND-01',
      reviewerId: 'verifier-reachability',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ file: 'test-secret.js', line: 1, quote: secretLine }]
    };

    const resTokenized = validateVoteEvidence(voteTokenized, candidate, tempDir);
    const resRaw = validateVoteEvidence(voteRaw, candidate, tempDir);

    assert.equal(resTokenized.valid, true, 'Tokenized quote from review context must match physical line');
    assert.equal(resRaw.valid, true, 'Raw physical line must also match');

    // Mismatched quote fails without leaking raw secret into error message
    const badVote = {
      findingId: 'CAND-01',
      reviewerId: 'verifier-reachability',
      lens: 'REACHABILITY',
      decision: 'SUPPORTS',
      evidence: [{ file: 'test-secret.js', line: 1, quote: 'const awsKey = "AKIAUNKNOWNKEY123456";' }]
    };
    const resBad = validateVoteEvidence(badVote, candidate, tempDir);
    assert.equal(resBad.valid, false);
    assert.ok(!resBad.reason.includes('AKIAUNKNOWNKEY123456'), 'Raw secret must not leak into error reason');
    assert.ok(resBad.reason.includes('[REDACTED_AWS_ACCESS_KEY'), 'Secret in error must be safely redacted');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});

test('PR #73 Delta - PATH-01: Candidate absolute path safe normalization against repoRoot', async (t) => {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'path-sandbox-'));
  try {
    fs.mkdirSync(path.join(tempDir, 'src'), { recursive: true });
    const relPath = 'src/vuln.js';
    const absPath = path.join(tempDir, relPath);
    const line = 'function test() { return 1; }';
    fs.writeFileSync(absPath, line + '\n', 'utf8');

    const candAbs = {
      id: 'CAND-PATH-01',
      findingId: 'CAND-PATH-01',
      ruleId: 'SEC-002',
      title: 'Path test',
      location: { uri: absPath, startLine: 1, endLine: 1 },
      attackPath: { steps: [{ uri: absPath, line: 1 }] }
    };

    const candRel = {
      id: 'CAND-PATH-02',
      findingId: 'CAND-PATH-02',
      ruleId: 'SEC-002',
      title: 'Path test',
      location: { uri: relPath, startLine: 1, endLine: 1 },
      attackPath: { steps: [{ uri: relPath, line: 1 }] }
    };

    const refuteVotes = (candId) => [
      { findingId: candId, reviewerId: 'verifier-reachability', lens: 'REACHABILITY', decision: 'REFUTES', evidence: [{ file: relPath, line: 1, quote: line }] },
      { findingId: candId, reviewerId: 'verifier-defenses', lens: 'DEFENSES', decision: 'REFUTES', evidence: [{ file: relPath, line: 1, quote: line }] },
      { findingId: candId, reviewerId: 'verifier-impact', lens: 'IMPACT', decision: 'REFUTES', evidence: [{ file: relPath, line: 1, quote: line }] }
    ];

    const dispAbs = deriveFinalDisposition(candAbs, refuteVotes('CAND-PATH-01'), { score: 100 }, tempDir);
    const dispRel = deriveFinalDisposition(candRel, refuteVotes('CAND-PATH-02'), { score: 100 }, tempDir);

    assert.equal(dispAbs.disposition, 'SUPPRESSED', 'Absolute path candidate inside repoRoot must correlate with evidence');
    assert.equal(dispRel.disposition, 'SUPPRESSED', 'Relative path candidate must correlate with evidence');

    // Anti-traversal: candidate escaping repoRoot is rejected
    const candEscape = {
      id: 'CAND-ESCAPE',
      findingId: 'CAND-ESCAPE',
      ruleId: 'SEC-003',
      location: { uri: path.resolve(tempDir, '../outside.js'), startLine: 1 },
      attackPath: { steps: [] }
    };
    const dispEscape = deriveFinalDisposition(candEscape, refuteVotes('CAND-ESCAPE'), { score: 100 }, tempDir);
    assert.equal(dispEscape.disposition, 'DEFERRED', 'Escaping path must fail closed to DEFERRED');
  } finally {
    fs.rmSync(tempDir, { recursive: true, force: true });
  }
});
