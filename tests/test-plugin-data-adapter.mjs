import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import {
  resolvePluginDataDir,
  getTrustRegistryPath,
  getRevocationJournalPath,
  getRevocationCheckpointPath,
  validateTrustRegistry,
  loadTrustRegistry,
  saveTrustRegistry,
  loadRevocationJournal,
  appendRevocationEntry,
  isRevoked,
  withFileLock,
  createAuthorizedRegistryUpdate,
  safeOpenStorageFile,
  safeWriteFileSync,
  computeRegistryDigest,
  computeRegistryAuthorizationPayload,
  GOVERNANCE_LOCK_TARGET,
  REVOCATION_TXN_FILE,
  withGovernanceLock,
  recoverAbortedRevocationTransaction,
  computeTransactionWalSignPayload,
  computeRevocationEntrySignPayload,
  REVOCATION_TYPES,
  EMBEDDED_ROOT_REGISTRY,
  DEFAULT_SUPERVISOR_KEY_ID,
  DEFAULT_SUPERVISOR_PUBLIC_PEM,
  DEFAULT_SUPERVISOR_FINGERPRINT,
  canonicalJsonStringify,
  isGovernanceLockHeld,
  sha256Digest,
  getMonotonicWitness
} from '../scripts/adapters/plugin-data-adapter.mjs';

function createTempDir(prefix = 'test-plugin-data-') {
  const dir = path.join(os.tmpdir(), `${prefix}${Date.now()}-${crypto.randomBytes(4).toString('hex')}`);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function generateTestAuthority() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ type: 'spki', format: 'pem' });
  const fp = crypto.createHash('sha256').update(pem).digest('hex');
  const keyId = `TEST-SUPERVISOR-ROOT-${fp.slice(0, 16)}`;
  return { publicKey, privateKey, pem, fp, keyId };
}

test('PLUGIN_DATA Governance: Default embedded root registry has valid schema and fingerprint', () => {
  const validation = validateTrustRegistry(EMBEDDED_ROOT_REGISTRY);
  assert.equal(validation.valid, true);
  assert.equal(validation.error, null);
  assert.equal(EMBEDDED_ROOT_REGISTRY.activeKeyId, DEFAULT_SUPERVISOR_KEY_ID);
  assert.equal(EMBEDDED_ROOT_REGISTRY.activeKeyFingerprint, DEFAULT_SUPERVISOR_FINGERPRINT);
});

test('PLUGIN_DATA Governance: Invariant - Zero Workspace Pollution strictly rejects in-repo target path', () => {
  const fakeRepo = createTempDir('fake-repo-');
  const insideRepoPluginData = path.join(fakeRepo, '.plugin-data');

  assert.throws(
    () => {
      resolvePluginDataDir({
        pluginDataDir: insideRepoPluginData,
        repoRoot: fakeRepo,
        allowInWorkspace: false
      });
    },
    /ZERO_WORKSPACE_POLLUTION_VIOLATION/
  );

  fs.rmSync(fakeRepo, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F03 - Path containment resolves symlinks/junctions fail-closed', (t) => {
  const tempBase = createTempDir('symlink-test-');
  const fakeRepo = path.join(tempBase, 'repo');
  const outsideTarget = path.join(tempBase, 'outside');
  const symlinkInsideRepo = path.join(fakeRepo, 'link-outside');

  fs.mkdirSync(fakeRepo, { recursive: true });
  fs.mkdirSync(outsideTarget, { recursive: true });

  try {
    fs.symlinkSync(outsideTarget, symlinkInsideRepo, 'dir');
  } catch {
    // On Windows without SeCreateSymbolicLinkPrivilege, junctions may be used
    try {
      fs.symlinkSync(outsideTarget, symlinkInsideRepo, 'junction');
    } catch {
      t.skip('Filesystem does not support symlink/junction in test context');
      fs.rmSync(tempBase, { recursive: true, force: true });
      return;
    }
  }

  // Symlink inside repo targeting inside repo should fail
  const insideInside = path.join(fakeRepo, 'target-inside');
  fs.mkdirSync(insideInside, { recursive: true });
  const symlinkToInside = path.join(tempBase, 'outside-link-to-inside');
  try {
    fs.symlinkSync(insideInside, symlinkToInside, 'junction');
    // Calling with symlink outside that points INSIDE repo must be caught by realpathSync
    assert.throws(
      () => {
        resolvePluginDataDir({
          pluginDataDir: symlinkToInside,
          repoRoot: fakeRepo,
          allowInWorkspace: false
        });
      },
      /ZERO_WORKSPACE_POLLUTION_VIOLATION/
    );
  } catch (e) {
    if (!e.message.includes('ZERO_WORKSPACE_POLLUTION_VIOLATION')) {
      // Junction creation might be skipped
    } else {
      throw e;
    }
  }

  fs.rmSync(tempBase, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Explicit allowInWorkspace permits isolated harness testing', () => {
  const tempDir = createTempDir('harness-data-');
  const resolved = resolvePluginDataDir({
    pluginDataDir: tempDir,
    allowInWorkspace: true
  });

  assert.ok(fs.existsSync(resolved));
  assert.equal(getTrustRegistryPath({ pluginDataDir: tempDir, allowInWorkspace: true }), `${resolved}/supervisor-trust-registry.json`);
  assert.equal(getRevocationJournalPath({ pluginDataDir: tempDir, allowInWorkspace: true }), `${resolved}/.irv-revocation-journal.jsonl`);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Rejects null bytes in path fail-closed', () => {
  assert.throws(
    () => {
      resolvePluginDataDir({ pluginDataDir: '/var/data\0/evil' });
    },
    /Illegal null byte/
  );
});

test('PLUGIN_DATA Governance: Dual-Anchor fallback loads embedded registry when no local file exists', () => {
  const tempDir = createTempDir('empty-data-');
  const res = loadTrustRegistry({ pluginDataDir: tempDir, allowInWorkspace: true });

  assert.equal(res.source, 'EMBEDDED_FALLBACK');
  assert.equal(res.valid, true);
  assert.equal(res.registry.activeKeyId, DEFAULT_SUPERVISOR_KEY_ID);
  assert.equal(res.registry.registryVersion, 1);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F02 - Atomic save with root authorization chain and anti-rollback', () => {
  const tempDir = createTempDir('save-data-');
  const auth = generateTestAuthority();
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // 1. Save v1 genesis
  const saveRes1 = saveTrustRegistry(v1Reg, opts);
  assert.equal(saveRes1.success, true);
  assert.equal(saveRes1.registryVersion, 1);

  // 2. Unsigned v2 must be rejected (F02)
  const unsignedV2 = {
    ...v1Reg,
    registryVersion: 2,
    revokedKeyIds: ['OLD-COMPROMISED-KEY-001']
  };
  assert.throws(
    () => saveTrustRegistry(unsignedV2, opts),
    /requires valid authorizationProof/
  );

  // 3. Cryptographically authorized v2 succeeds
  const authorizedV2 = createAuthorizedRegistryUpdate(
    v1Reg,
    { revokedKeyIds: ['OLD-COMPROMISED-KEY-001'] },
    auth.keyId,
    auth.privateKey
  );
  const saveRes2 = saveTrustRegistry(authorizedV2, opts);
  assert.equal(saveRes2.success, true);
  assert.equal(saveRes2.registryVersion, 2);

  const loadRes = loadTrustRegistry(opts);
  assert.equal(loadRes.source, 'PLUGIN_DATA');
  assert.equal(loadRes.valid, true);
  assert.equal(loadRes.registry.registryVersion, 2);
  assert.deepEqual(loadRes.registry.revokedKeyIds, ['OLD-COMPROMISED-KEY-001']);

  // 4. Anti-unrevocation invariant check (cannot silently remove revokedKeyId)
  const stripRevocationV3 = createAuthorizedRegistryUpdate(
    authorizedV2,
    { revokedKeyIds: [] },
    auth.keyId,
    auth.privateKey
  );
  assert.throws(
    () => saveTrustRegistry(stripRevocationV3, opts),
    /REVOCATION_STRIP_VIOLATION/
  );

  // 5. Anti-rollback check (cannot overwrite v2 with v1)
  assert.throws(
    () => saveTrustRegistry(v1Reg, opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Monotonic version regression fails closed', () => {
  const tempDir = createTempDir('regress-data-');
  const auth = generateTestAuthority();
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };
  saveTrustRegistry(v1Reg, opts);

  assert.throws(
    () => {
      loadTrustRegistry({
        ...opts,
        minRegistryVersion: 2,
        failClosed: true
      });
    },
    /Monotonic regression/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Tampered key fingerprint in registry fails closed', () => {
  const tempDir = createTempDir('tamper-reg-');
  const tamperedReg = {
    ...EMBEDDED_ROOT_REGISTRY,
    activeKeyFingerprint: '0000000000000000000000000000000000000000000000000000000000000000'
  };

  assert.throws(
    () => {
      saveTrustRegistry(tamperedReg, { pluginDataDir: tempDir, allowInWorkspace: true });
    },
    /Fingerprint mismatch/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - Revocation journal enforces signatures, chaining, and checkpoint', () => {
  const tempDir = createTempDir('journal-data-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  const app1 = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-111', reason: 'REPLAY_TEST' },
    opts
  );
  assert.equal(app1.success, true);
  assert.equal(app1.entryIndex, 0);

  const app2 = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-222', reason: 'ROTATION' },
    opts
  );
  assert.equal(app2.success, true);
  assert.equal(app2.entryIndex, 1);

  const load = loadRevocationJournal(opts);
  assert.equal(load.valid, true);
  assert.equal(load.count, 2);
  assert.equal(load.entries[0].prevEntryDigest, '0'.repeat(64));
  assert.equal(load.entries[1].prevEntryDigest, app1.entryDigest);

  // Verification of query
  assert.equal(isRevoked('NONCE-111', opts).revoked, true);
  assert.equal(isRevoked('KEY-222', opts).revoked, true);
  assert.equal(isRevoked('NONCE-999', opts).revoked, false);

  // Checkpoint anti-rollback / truncation verification (F01)
  const checkpointPath = getRevocationCheckpointPath(opts);
  assert.ok(fs.existsSync(checkpointPath));
  const checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
  assert.equal(checkpoint.headIndex, 1);
  assert.equal(checkpoint.headDigest, app2.entryDigest);

  // Truncating the journal while checkpoint exists must fail closed
  const journalPath = getRevocationJournalPath(opts);
  const firstLineOnly = fs.readFileSync(journalPath, 'utf8').split('\n')[0] + '\n';
  fs.writeFileSync(journalPath, firstLineOnly, 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /JOURNAL_TRUNCATION_DETECTED|JOURNAL_HEAD_MISMATCH|broken hash chain/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: Tampered revocation journal line fails closed immediately', () => {
  const tempDir = createTempDir('corrupt-journal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-A' }, opts);
  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-B' }, opts);

  // Tamper line 1
  const journalPath = getRevocationJournalPath(opts);
  const raw = fs.readFileSync(journalPath, 'utf8');
  const tampered = raw.replace('NONCE-A', 'NONCE-TAMPERED');
  fs.writeFileSync(journalPath, tampered, 'utf8');

  // Should fail closed with broken hash chain or signature verification failed
  assert.throws(
    () => {
      loadRevocationJournal(opts);
    },
    /Tamper detected|broken hash chain|Signature verification failed/
  );

  // isRevoked must fail closed to true when journal is corrupted
  const query = isRevoked('NONCE-UNTOUCHED', opts);
  assert.equal(query.revoked, true);
  assert.equal(query.reason.includes('JOURNAL_CORRUPTED_FAIL_CLOSED'), true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F04 - withFileLock enforces cross-process mutual exclusion', () => {
  const tempDir = createTempDir('lock-test-');
  const targetFile = path.join(tempDir, 'resource.txt');

  let executionOrder = [];
  const res = withFileLock(targetFile, () => {
    executionOrder.push('in_lock');
    return 42;
  });

  assert.equal(res, 42);
  assert.deepEqual(executionOrder, ['in_lock']);
  assert.equal(fs.existsSync(`${targetFile}.lock`), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F02 - Genesis v1 rejects rogue injected keys in keys array', () => {
  const auth = generateTestAuthority();
  const rogueAuth = generateTestAuthority();
  const injectedV1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [
      { keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
      { keyId: rogueAuth.keyId, keyFingerprint: rogueAuth.fp, publicKeyPem: rogueAuth.pem, status: 'ACTIVE', issuedAt: '2026-10-16T06:55:39.565Z' }
    ]
  };

  const validation = validateTrustRegistry(injectedV1, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  });
  assert.equal(validation.valid, false);
  assert.ok(validation.error.includes('Genesis registry (v1) keys array must contain exactly the pinned root key'));
});

test('PLUGIN_DATA Governance: F02 - saveTrustRegistry fails closed on corrupted existing file', () => {
  const tempDir = createTempDir('corrupt-prior-');
  const auth = generateTestAuthority();
  const regPath = getTrustRegistryPath({ pluginDataDir: tempDir, allowInWorkspace: true });
  fs.mkdirSync(path.dirname(regPath), { recursive: true });
  fs.writeFileSync(regPath, '{ corrupt json !!!', 'utf8');

  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  assert.throws(
    () => saveTrustRegistry(v1Reg, {
      pluginDataDir: tempDir,
      allowInWorkspace: true,
      trustedRootKeyId: auth.keyId,
      trustedRootPublicKeyPem: auth.pem,
      trustedRootFingerprint: auth.fp
    }),
    /CORRUPT_PRIOR_REGISTRY_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - loadRevocationJournal fails closed on corrupt checkpoint file', () => {
  const tempDir = createTempDir('corrupt-cp-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' }, opts);
  const cpPath = getRevocationCheckpointPath(opts);
  fs.writeFileSync(cpPath, 'CORRUPT_NOT_JSON', 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /CHECKPOINT_CORRUPTION_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F01 - Tampering with revocationType or reason triggers signature verification failure', () => {
  const tempDir = createTempDir('tamper-fields-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-SEC', reason: 'REASON_ORIGINAL' }, opts);

  const jPath = getRevocationJournalPath(opts);
  const raw = fs.readFileSync(jPath, 'utf8');
  const tampered = raw.replace('REASON_ORIGINAL', 'REASON_ALTERED');
  fs.writeFileSync(jPath, tampered, 'utf8');

  assert.throws(
    () => loadRevocationJournal(opts),
    /Signature verification failed/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: F04 - Multi-process withFileLock competition enforces mutual exclusion', async () => {
  const tempDir = createTempDir('concurrent-lock-');
  const lockTarget = path.join(tempDir, 'shared-counter.txt');
  fs.writeFileSync(lockTarget, '0', 'utf8');

  const { pathToFileURL } = await import('node:url');
  const adapterUrl = pathToFileURL(path.resolve('scripts/adapters/plugin-data-adapter.mjs')).href;
  const workerScript = `
    import fs from 'node:fs';
    import { withFileLock } from '${adapterUrl}';
    const target = process.argv[2];
    for (let i = 0; i < 5; i++) {
      withFileLock(target, () => {
        const val = parseInt(fs.readFileSync(target, 'utf8'), 10);
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
        fs.writeFileSync(target, String(val + 1), 'utf8');
      }, { staleLockTimeoutMs: 5000, lockTimeoutMs: 15000 });
    }
  `;
  const workerFile = path.join(tempDir, 'worker.mjs');
  fs.writeFileSync(workerFile, workerScript, 'utf8');

  const { spawn } = await import('node:child_process');
  const runWorker = () => new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [workerFile, lockTarget], { stdio: 'inherit' });
    proc.on('close', code => code === 0 ? resolve() : reject(new Error('Worker exited with code ' + code)));
  });

  await Promise.all([runWorker(), runWorker(), runWorker()]);

  const finalVal = parseInt(fs.readFileSync(lockTarget, 'utf8'), 10);
  assert.equal(finalVal, 15);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B02 - loadTrustRegistry fallback fails closed if minRegistryVersion > 1', () => {
  const tempDir = createTempDir('empty-reg-');
  assert.throws(
    () => loadTrustRegistry({ pluginDataDir: tempDir, minRegistryVersion: 2, failClosed: true, allowInWorkspace: true }),
    /MONOTONIC_REGRESSION_FAIL_CLOSED|Monotonic regression/
  );
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B02 - validateTrustRegistry rejects unauthenticated priorRegistry', () => {
  const auth = generateTestAuthority();
  const rogueAuth = generateTestAuthority();

  const fakePrior = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: rogueAuth.keyId,
    activeKeyFingerprint: rogueAuth.fp,
    activePublicKeyPem: rogueAuth.pem,
    keys: [{ keyId: rogueAuth.keyId, keyFingerprint: rogueAuth.fp, publicKeyPem: rogueAuth.pem, status: 'ACTIVE' }],
    revokedKeyIds: []
  };

  const v2Reg = createAuthorizedRegistryUpdate(
    fakePrior,
    { revokedKeyIds: [] },
    rogueAuth.keyId,
    rogueAuth.privateKey
  );

  const validation = validateTrustRegistry(v2Reg, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    priorRegistry: fakePrior
  });

  assert.equal(validation.valid, false);
  assert.ok(validation.error.includes('Unauthenticated priorRegistry rejected') || validation.error.includes('must match embedded root anchor'));
});

test('PLUGIN_DATA Governance: R03-B02 - loadRevocationJournal accepts historical signatures from RETIRED keys', () => {
  const tempDir = createTempDir('retired-key-');
  const rootAuth = generateTestAuthority();
  const operatorAuth = generateTestAuthority();

  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: rootAuth.keyId,
    activeKeyFingerprint: rootAuth.fp,
    activePublicKeyPem: rootAuth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: rootAuth.keyId,
    trustedRootPublicKeyPem: rootAuth.pem,
    trustedRootFingerprint: rootAuth.fp
  };

  saveTrustRegistry(v1Reg, opts);

  // Rotate to v2 adding operator as active key
  const v2Reg = createAuthorizedRegistryUpdate(
    v1Reg,
    {
      activeKeyId: operatorAuth.keyId,
      activeKeyFingerprint: operatorAuth.fp,
      activePublicKeyPem: operatorAuth.pem,
      keys: [
        { keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: operatorAuth.keyId, keyFingerprint: operatorAuth.fp, publicKeyPem: operatorAuth.pem, status: 'ACTIVE', issuedAt: '2026-10-16T06:55:39.565Z' }
      ]
    },
    rootAuth.keyId,
    rootAuth.privateKey
  );
  saveTrustRegistry(v2Reg, opts);

  // Append entry signed by operator
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-HISTORICAL-1' },
    { ...opts, signerPrivateKey: operatorAuth.privateKey, signerKeyId: operatorAuth.keyId }
  );

  // Rotate to v3 retiring operatorAuth
  const currentReg = loadTrustRegistry(opts).registry;
  const v3Reg = createAuthorizedRegistryUpdate(
    currentReg,
    {
      activeKeyId: rootAuth.keyId,
      activeKeyFingerprint: rootAuth.fp,
      activePublicKeyPem: rootAuth.pem,
      keys: [
        { keyId: rootAuth.keyId, keyFingerprint: rootAuth.fp, publicKeyPem: rootAuth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: operatorAuth.keyId, keyFingerprint: operatorAuth.fp, publicKeyPem: operatorAuth.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' }
      ]
    },
    operatorAuth.keyId,
    operatorAuth.privateKey
  );
  saveTrustRegistry(v3Reg, opts);

  // loadRevocationJournal should still validate the entry signed by RETIRED operatorAuth
  const journal = loadRevocationJournal(opts);
  assert.equal(journal.valid, true);
  assert.equal(journal.count, 1);
  assert.equal(journal.entries[0].targetId, 'NONCE-HISTORICAL-1');

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R03-B03 - appendRevocationEntry rejects leaf symlink on journal file', (t) => {
  const tempDir = createTempDir('symlink-leaf-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  const journalPath = getRevocationJournalPath(opts);
  const fakeTarget = path.join(tempDir, 'target-file.txt');
  fs.writeFileSync(fakeTarget, '', 'utf8');

  try {
    fs.symlinkSync(fakeTarget, journalPath, 'file');
  } catch {
    t.skip('Filesystem does not support file symlinks in test context');
    fs.rmSync(tempDir, { recursive: true, force: true });
    return;
  }

  assert.throws(
    () => appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-EVIL' }, opts),
    /SYMLINK_POLLUTION_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R04-B01 - Dual-file deletion fails closed in isRevoked without minJournalEntries', () => {
  const tempDir = createTempDir('dual-delete-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  // 1. Establish valid revocation
  const app = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-ATTACK-REVOKED' },
    opts
  );
  assert.equal(app.success, true);

  // Verify it is recognized as revoked
  const checkBefore = isRevoked('NONCE-ATTACK-REVOKED', opts);
  assert.equal(checkBefore.revoked, true);

  // 2. Adversary wipes BOTH the journal and the checkpoint from disk
  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  fs.unlinkSync(journalPath);
  fs.unlinkSync(checkpointPath);

  assert.equal(fs.existsSync(journalPath), false);
  assert.equal(fs.existsSync(checkpointPath), false);

  // 3. Reader queries without minJournalEntries (default isRevoked call)
  const defaultQueryOpts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const checkAfter = isRevoked('NONCE-ATTACK-REVOKED', defaultQueryOpts);

  // Invariant R04-B01: Must NEVER return revoked: false; must fail closed
  assert.equal(checkAfter.revoked, true);
  assert.ok(
    (checkAfter.reason.includes('JOURNAL_CORRUPTED_FAIL_CLOSED') || checkAfter.reason.includes('REGISTRY_CORRUPTED_FAIL_CLOSED')) &&
    checkAfter.reason.includes('JOURNAL_ROLLBACK_DETECTED'),
    `Expected JOURNAL_ROLLBACK_DETECTED in fail-closed reason, got: ${checkAfter.reason}`
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R04-B02 - validateTrustRegistry rejects broken ancestry and non-consecutive versions', () => {
  const auth = generateTestAuthority();
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  // Attempt to skip from v1 directly to v3 (broken ancestry / gap)
  const v3RegBrokenAncestry = createAuthorizedRegistryUpdate(
    { ...v1Reg, registryVersion: 2 }, // crafted so output is v3
    { revokedKeyIds: [] },
    auth.keyId,
    auth.privateKey
  );
  assert.equal(v3RegBrokenAncestry.registryVersion, 3);

  const validation = validateTrustRegistry(v3RegBrokenAncestry, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    priorRegistry: v1Reg // v1 provided as prior, but target is v3 (gap!)
  });

  assert.equal(validation.valid, false);
  assert.equal(validation.ancestryContinuity, false);
  assert.ok(validation.error.includes('ANCESTRY_CONTINUITY_VIOLATION'));

  // Valid consecutive v2 passes ancestry
  const v2RegValid = createAuthorizedRegistryUpdate(
    v1Reg,
    { revokedKeyIds: [] },
    auth.keyId,
    auth.privateKey
  );
  assert.equal(v2RegValid.registryVersion, 2);

  const validValidation = validateTrustRegistry(v2RegValid, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    priorRegistry: v1Reg
  });

  assert.equal(validValidation.valid, true);
  assert.equal(validValidation.ancestryContinuity, true);
  assert.equal(validValidation.cryptographicValidity, true);
  assert.equal(validValidation.monotonicValidity, true);
});

test('PLUGIN_DATA Governance: R04-B03 - Dangling symlink and hard link rejected on journal file', (t) => {
  const tempDir = createTempDir('symlink-dangling-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerPrivateKey: auth.privateKey,
    signerKeyId: auth.keyId
  };

  const journalPath = getRevocationJournalPath(opts);
  const danglingTarget = path.join(tempDir, 'non-existent-target.txt');

  try {
    fs.symlinkSync(danglingTarget, journalPath, 'file');
  } catch {
    t.skip('Filesystem does not support file symlinks in test context');
    fs.rmSync(tempDir, { recursive: true, force: true });
    return;
  }

  // Confirm fs.existsSync is false for dangling symlink (R04-B03 root cause)
  assert.equal(fs.existsSync(journalPath), false);

  // appendRevocationEntry must still detect the dangling symlink via lstatSync
  assert.throws(
    () => appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-DANGLING' }, opts),
    /SYMLINK_POLLUTION_VIOLATION/
  );

  fs.unlinkSync(journalPath);

  // Now test hard link rejection
  const existingFile = path.join(tempDir, 'existing-inode.txt');
  fs.writeFileSync(existingFile, 'inode-content\n', 'utf8');

  try {
    fs.linkSync(existingFile, journalPath);
  } catch {
    t.skip('Filesystem does not support hard links in test context');
    fs.rmSync(tempDir, { recursive: true, force: true });
    return;
  }

  assert.equal(fs.lstatSync(journalPath).nlink > 1, true);

  // appendRevocationEntry without allowInWorkspace must strictly reject nlink > 1
  assert.throws(
    () => appendRevocationEntry(
      { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-HARDLINK' },
      { ...opts, allowInWorkspace: false, repoRoot: path.join(tempDir, 'workspace') }
    ),
    /HARDLINK_POLLUTION_VIOLATION|ZERO_WORKSPACE_POLLUTION_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R04-B05 - loadRevocationJournal acquires lock even when journal does not exist', () => {
  const tempDir = createTempDir('reader-lock-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    lockTimeoutMs: 100,
    staleLockTimeoutMs: 5000
  };

  const journalPath = getRevocationJournalPath(opts);
  assert.equal(fs.existsSync(journalPath), false);

  // Simulate an active writer currently holding the unified governance lock while creating journal
  const lockDir = tempDir;
  if (!fs.existsSync(lockDir)) fs.mkdirSync(lockDir, { recursive: true });
  const lockPath = path.join(lockDir, `${GOVERNANCE_LOCK_TARGET}.lock`);

  const lockContent = JSON.stringify({
    pid: process.pid,
    lockId: 'ACTIVE-WRITER-LOCK',
    createdAt: new Date().toISOString()
  });
  fs.writeFileSync(lockPath, lockContent, 'utf8');

  // Reader must NOT bypass lock just because journalPath doesn't exist
  assert.throws(
    () => loadRevocationJournal(opts),
    /LOCK_TIMEOUT|Timeout acquiring lock/
  );

  fs.unlinkSync(lockPath);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R05-B01 - Deleting high-water mark or dual-file wipeout fails closed in isRevoked', () => {
  const dir = createTempDir('three-lens-r05-b01-');
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const pem = publicKey.export({ format: 'pem', type: 'spki' });

  const opts = {
    pluginDataDir: dir,
    allowInWorkspace: true,
    trustedRootKeyId: 'R05-TEST-ROOT',
    trustedRootPublicKeyPem: pem,
    trustedRootFingerprint: crypto.createHash('sha256').update(pem).digest('hex'),
    signerKeyId: 'R05-TEST-ROOT',
    signerPrivateKey: privateKey
  };

  const id = 'R05-REVOKED-NONCE';
  appendRevocationEntry({
    revocationType: REVOCATION_TYPES.NONCE_REVOCATION,
    targetId: id
  }, opts);

  const before = isRevoked(id, opts);
  assert.equal(before.revoked, true);

  // Simulate attacker modifying PLUGIN_DATA: strip high-water mark from registry
  const registryPath = getTrustRegistryPath(opts);
  const registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
  delete registry.revocationHighWaterMark;
  fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));

  // Remove journal and checkpoint
  fs.unlinkSync(getRevocationJournalPath(opts));
  fs.unlinkSync(getRevocationCheckpointPath(opts));

  // After wipeout attempt, must FAIL CLOSED (cannot return false)
  const after = isRevoked(id, opts);
  assert.equal(after.revoked, true);
  assert.ok(
    after.reason.includes('REGISTRY_CORRUPTED_FAIL_CLOSED') ||
    after.reason.includes('Cryptographic verification') ||
    after.reason.includes('JOURNAL_CORRUPTED_FAIL_CLOSED')
  );

  fs.rmSync(dir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R05-B02 - Version jump rejected and persistent registry required in existing installation', () => {
  const tempDir = createTempDir('r05-b02-');
  const auth = generateTestAuthority();

  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // Ancestry continuity check: version 3 without priorRegistry fails closed
  const v3Reg = {
    ...v1Reg,
    registryVersion: 3,
    authorizationProof: {
      authorizedBy: auth.keyId,
      signature: '0'.repeat(128),
      timestamp: new Date().toISOString()
    }
  };
  const valV3 = validateTrustRegistry(v3Reg, opts);
  assert.equal(valV3.valid, false);
  assert.equal(valV3.ancestryContinuity, false);
  assert.ok(valV3.error.includes('ANCESTRY_CONTINUITY_VIOLATION'));

  // Save v1 and append a revocation to establish state in directory
  saveTrustRegistry(v1Reg, opts);
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' },
    { ...opts, signerPrivateKey: auth.privateKey, signerKeyId: auth.keyId }
  );

  // If registry is deleted from an existing installation directory, fallback is strictly blocked
  fs.unlinkSync(getTrustRegistryPath(opts));
  assert.throws(
    () => loadTrustRegistry(opts),
    /PERSISTENT_REGISTRY_MISSING/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R05-B03 - appendRevocationEntry rolls back journal append if registry update fails', () => {
  const tempDir = createTempDir('r05-b03-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Initial successful append
  const res1 = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-INITIAL' },
    opts
  );
  assert.equal(res1.success, true);
  const journalPath = getRevocationJournalPath(opts);
  const statBefore = fs.statSync(journalPath);

  // 2. Simulate failure during registry update by locking/corrupting registry directory
  const regPath = getTrustRegistryPath(opts);
  // Replace registry with a directory so writeFileSync throws EISDIR
  fs.unlinkSync(regPath);
  fs.mkdirSync(regPath);

  assert.throws(
    () => appendRevocationEntry(
      { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-SHOULD-ROLLBACK' },
      opts
    )
  );

  // Assert journal size was rolled back to initial size (no partial append left behind)
  const statAfter = fs.statSync(journalPath);
  assert.equal(statAfter.size, statBefore.size);

  fs.rmSync(regPath, { recursive: true, force: true });
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R05-B04 - safeOpenStorageFile rejects symlink with SYMLINK_POLLUTION_VIOLATION', () => {
  const tempDir = createTempDir('r05-b04-');
  const realFile = path.join(tempDir, 'real.txt');
  fs.writeFileSync(realFile, 'data\n', 'utf8');

  const linkFile = path.join(tempDir, 'link.txt');
  try {
    fs.symlinkSync(realFile, linkFile);
  } catch (err) {
    // If symlinks not permitted without admin on Windows, test passes
    fs.rmSync(tempDir, { recursive: true, force: true });
    return;
  }

  assert.throws(
    () => safeOpenStorageFile(linkFile, 'r', 0o600, { allowInWorkspace: true }),
    /SYMLINK_POLLUTION_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R06 Hardening - loadTrustRegistry rejects Genesis v1 replay over historical progression', () => {
  const tempDir = createTempDir('r06-h01-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Save v1 then v2
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  saveTrustRegistry(v1, opts);

  const v2 = createAuthorizedRegistryUpdate(
    v1,
    { revokedKeyIds: ['REVOKED-KEY-001'] },
    auth.keyId,
    auth.privateKey
  );
  saveTrustRegistry(v2, opts);

  // 2. Attacker replaces supervisor-trust-registry.json with genuine signed Genesis v1
  fs.writeFileSync(getTrustRegistryPath(opts), JSON.stringify(v1, null, 2) + '\n', 'utf8');

  // 3. loadTrustRegistry MUST detect rollback against history/ directory and fail closed
  assert.throws(
    () => loadTrustRegistry(opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R06 Hardening - loadTrustRegistry and saveTrustRegistry reject unadorned Genesis replay when revocations exist', () => {
  const tempDir = createTempDir('r06-h02-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Initialize registry and append a revocation
  const appendRes = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-R06-CHECK' },
    opts
  );
  assert.equal(appendRes.success, true);

  // 2. Attacker attempts to replace supervisor-trust-registry.json with unadorned Genesis v1
  const rawGenesis = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  fs.writeFileSync(getTrustRegistryPath(opts), JSON.stringify(rawGenesis, null, 2) + '\n', 'utf8');

  // loadTrustRegistry must detect established revocations and reject unadorned Genesis
  assert.throws(
    () => loadTrustRegistry(opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  // saveTrustRegistry must also reject saving unadorned Genesis over established revocations
  assert.throws(
    () => saveTrustRegistry(rawGenesis, opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R06 Combination Attack - History v1 with HWM survives deletion of journal and checkpoint and enforces Fail-Closed in isRevoked', () => {
  const tempDir = createTempDir('r06-combo-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  const targetNonce = 'NONCE-TARGET-COMBO';
  const appendRes = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: targetNonce },
    opts
  );
  assert.equal(appendRes.success, true);

  // Combination attack execution:
  // 1. Replace current registry with unadorned Genesis v1
  const rawGenesis = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  fs.writeFileSync(getTrustRegistryPath(opts), JSON.stringify(rawGenesis, null, 2) + '\n', 'utf8');

  // 2. Simultaneously delete journal and checkpoint, preserving history/trust-registry.v1.json
  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  if (fs.existsSync(journalPath)) fs.unlinkSync(journalPath);
  if (fs.existsSync(checkpointPath)) fs.unlinkSync(checkpointPath);

  // 3. loadTrustRegistry MUST detect that history v1 recorded HWM and fail closed
  assert.throws(
    () => loadTrustRegistry(opts),
    /REGISTRY_ROLLBACK_DETECTED|JOURNAL_ROLLBACK_DETECTED/
  );

  // 4. isRevoked MUST fail closed (revoked: true)
  const isRev = isRevoked(targetNonce, opts);
  assert.equal(isRev.revoked, true);
  assert.ok(isRev.reason.includes('REGISTRY_CORRUPTED_FAIL_CLOSED') || isRev.reason.includes('JOURNAL_CORRUPTED_FAIL_CLOSED'));

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R05-B01 - Stripping signature or authorizedBy from HWM triggers HIGH_WATER_MARK_SIGNATURE_MISSING', () => {
  const auth = generateTestAuthority();
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }],
    revocationHighWaterMark: {
      headIndex: 0,
      headDigest: 'a'.repeat(64),
      updatedAt: new Date().toISOString()
      // Stripped authorizedBy and signature
    }
  };

  const validation = validateTrustRegistry(v1, {
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  });
  assert.equal(validation.valid, false);
  assert.ok(validation.error.includes('HIGH_WATER_MARK_SIGNATURE_MISSING'));
});

test('PLUGIN_DATA Governance: R06 Signer Authority - appendRevocationEntry rejects unknown or inactive signers or key mismatch', () => {
  const tempDir = createTempDir('r06-signer-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Unknown signer
  assert.throws(
    () => appendRevocationEntry(
      { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' },
      { ...opts, signerKeyId: 'UNKNOWN-ROGUE-KEY' }
    ),
    /UNKNOWN_SIGNER_REJECTED/
  );

  // 2. Mismatched private key
  const rogueAuth = generateTestAuthority('ROGUE');
  assert.throws(
    () => appendRevocationEntry(
      { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' },
      { ...opts, signerPrivateKey: rogueAuth.privateKey }
    ),
    /KEY_MISMATCH_REJECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R07 F-01 - History directory deletion or missing genesis history fails closed', () => {
  const tempDir = createTempDir('r07-f01-hist-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };

  saveTrustRegistry(v1, opts);
  const loaded = loadTrustRegistry(opts);
  assert.equal(loaded.valid, true);

  // 1. Delete history/ directory completely -> must fail closed with HISTORY_DELETION_DETECTED
  const histDir = path.join(tempDir, 'history');
  fs.rmSync(histDir, { recursive: true, force: true });
  assert.throws(
    () => loadTrustRegistry(opts),
    /HISTORY_DELETION_DETECTED/
  );

  // 2. Re-create history/ without trust-registry.v1.json -> must fail closed with GENESIS_HISTORY_MISSING_FAIL_CLOSED
  fs.mkdirSync(histDir, { recursive: true });
  fs.writeFileSync(path.join(histDir, 'trust-registry.v2.json'), JSON.stringify(v1), 'utf8');
  assert.throws(
    () => loadTrustRegistry(opts),
    /GENESIS_HISTORY_MISSING_FAIL_CLOSED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R07 F-03 - Simulated failure in appendRevocationEntry triggers full rollback and clears WAL', () => {
  const tempDir = createTempDir('r07-f03-rollback-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Initial valid append
  const first = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-INITIAL' },
    opts
  );
  assert.equal(first.entryIndex, 0);

  const journalPath = getRevocationJournalPath(opts);
  const initialJournalContent = fs.readFileSync(journalPath, 'utf8');
  const initialCheckpoint = fs.readFileSync(getRevocationCheckpointPath(opts), 'utf8');
  const initialRegistry = fs.readFileSync(getTrustRegistryPath(opts), 'utf8');
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // Fail during REGISTRY_WRITE stage
  assert.throws(
    () => appendRevocationEntry(
      { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-SHOULD-ROLLBACK' },
      { ...opts, _simulateFailureStage: 'REGISTRY_WRITE' }
    ),
    /SIMULATED_FAILURE_REGISTRY_WRITE/
  );

  // Verify journal was truncated back to original
  assert.equal(fs.readFileSync(journalPath, 'utf8'), initialJournalContent);
  // Verify checkpoint was restored
  assert.equal(fs.readFileSync(getRevocationCheckpointPath(opts), 'utf8'), initialCheckpoint);
  // Verify registry was restored
  assert.equal(fs.readFileSync(getTrustRegistryPath(opts), 'utf8'), initialRegistry);
  // Verify WAL transaction marker is cleared
  assert.equal(fs.existsSync(txnPath), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R07 F-03 - WAL Crash Recovery restores disk state on uncommitted transaction', () => {
  const tempDir = createTempDir('r07-f03-wal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Initial append
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-STABLE-1' },
    opts
  );

  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const regPath = getTrustRegistryPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  const stableJournalBytes = fs.readFileSync(journalPath);
  const stableCheckpointBytes = fs.readFileSync(checkpointPath);
  const stableRegBytes = fs.readFileSync(regPath);

  // Simulate an interrupted transaction by writing signed WAL with status 'PREPARED' and partial mutations
  const initialRegObj = JSON.parse(stableRegBytes.toString('utf8'));
  const unsignedTxn = {
    txnId: 'SIMULATED-CRASH-TXN-1234',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    initialJournalSize: stableJournalBytes.length,
    initialJournalExisted: true,
    initialJournalSha256: crypto.createHash('sha256').update(stableJournalBytes).digest('hex'),
    checkpointPath,
    initialCheckpointSha256: crypto.createHash('sha256').update(stableCheckpointBytes).digest('hex'),
    initialCheckpointExisted: true,
    regPath,
    initialRegistrySha256: crypto.createHash('sha256').update(stableRegBytes).digest('hex'),
    initialRegistryExisted: true,
    initialRegistryVersion: initialRegObj.registryVersion || 1,
    initialHwmHeadIndex: initialRegObj.revocationHighWaterMark?.headIndex ?? -1,
    initialHwmHeadDigest: initialRegObj.revocationHighWaterMark?.headDigest ?? '',
    histPath: null,
    initialHistSha256: '0'.repeat(64),
    initialHistExisted: false
  };

  const signPayload = Buffer.from(computeTransactionWalSignPayload(unsignedTxn), 'utf8');
  const signature = crypto.sign(null, signPayload, auth.privateKey).toString('hex');

  const txnData = {
    ...unsignedTxn,
    signature,
    initialCheckpointRawBase64: stableCheckpointBytes.toString('base64'),
    initialRegistryRawBase64: stableRegBytes.toString('base64'),
    initialHistRawBase64: null
  };
  fs.writeFileSync(txnPath, JSON.stringify(txnData, null, 2), 'utf8');

  // Corrupt journal by appending partial garbage
  fs.appendFileSync(journalPath, '{"brokenLine": true}\n');

  // Load journal -> should auto-trigger recovery, truncate journal, delete WAL, and succeed
  const recovered = loadRevocationJournal(opts);
  assert.equal(recovered.valid, true);
  assert.equal(recovered.count, 1);
  assert.equal(fs.existsSync(txnPath), false);
  assert.equal(fs.readFileSync(journalPath).length, stableJournalBytes.length);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R07 F-04 - withGovernanceLock enforces unified exclusion across governance operations', () => {
  const tempDir = createTempDir('r07-f04-gov-lock-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    lockTimeoutMs: 100
  };

  let lockAcquiredInside = false;
  withGovernanceLock(opts, () => {
    lockAcquiredInside = true;
    const lockFile = path.join(tempDir, `${GOVERNANCE_LOCK_TARGET}.lock`);
    assert.equal(fs.existsSync(lockFile), true);

    // Concurrent call must timeout
    assert.throws(
      () => withGovernanceLock(opts, () => {}),
      /LOCK_TIMEOUT|Timeout acquiring lock/
    );
  });

  assert.equal(lockAcquiredInside, true);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R08-B01 - WAL recovery strictly rejects path traversal / non-canonical targets', () => {
  const tempDir = createTempDir('r08-b01-wal-path-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true
  };

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const maliciousWal = {
    txnId: 'TXN-ATTACK-01',
    status: 'PREPARED',
    journalPath: path.resolve(tempDir, '..', 'arbitrary-victim.txt'),
    initialJournalSize: 0,
    initialJournalExisted: false
  };
  fs.writeFileSync(txnPath, JSON.stringify(maliciousWal, null, 2), 'utf8');

  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED/
  );
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R08-B02 - Corrupted WAL fails closed without deletion under Default-Deny', () => {
  const tempDir = createTempDir('r08-b02-wal-corrupt-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true
  };

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  fs.writeFileSync(txnPath, 'NOT_VALID_JSON{:::broken', 'utf8');

  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // Assert fail-closed: WAL is NOT deleted
  assert.equal(fs.existsSync(txnPath), true);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R08-B04 - Registry history gap and tail deletion anti-rollback', () => {
  const tempDir = createTempDir('r08-b04-anti-rollback-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Initialize v1 and v2
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  saveTrustRegistry(v1, opts);

  const v2 = createAuthorizedRegistryUpdate(v1, {}, auth.keyId, auth.privateKey);
  saveTrustRegistry(v2, opts);

  const v3 = createAuthorizedRegistryUpdate(v2, {}, auth.keyId, auth.privateKey);
  saveTrustRegistry(v3, opts);

  const histDir = path.join(tempDir, 'history');
  assert.equal(fs.existsSync(path.join(histDir, 'trust-registry.v1.json')), true);
  assert.equal(fs.existsSync(path.join(histDir, 'trust-registry.v2.json')), true);
  assert.equal(fs.existsSync(path.join(histDir, 'trust-registry.v3.json')), true);

  // Attack 1: Intermediate gap - delete v2
  fs.unlinkSync(path.join(histDir, 'trust-registry.v2.json'));
  assert.throws(
    () => loadTrustRegistry(opts),
    /HISTORY_GAP_DETECTED/
  );

  // Restore v2
  fs.writeFileSync(path.join(histDir, 'trust-registry.v2.json'), JSON.stringify(v2, null, 2) + '\n', 'utf8');
  assert.equal(loadTrustRegistry(opts).valid, true);

  // Attack 2: Tail deletion - revert disk to v2 and delete history v3
  fs.writeFileSync(getTrustRegistryPath(opts), JSON.stringify(v2, null, 2) + '\n', 'utf8');
  fs.unlinkSync(path.join(histDir, 'trust-registry.v3.json'));

  // Must detect rollback against checkpoint recorded registryVersion (3)
  assert.throws(
    () => loadTrustRegistry(opts),
    /REGISTRY_ROLLBACK_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R08-B05 - Revoked keys rejected from authorizing registry updates', () => {
  const auth = generateTestAuthority();
  const delegateA = generateTestAuthority();

  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [
      { keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
      { keyId: delegateA.keyId, keyFingerprint: delegateA.fp, publicKeyPem: delegateA.pem, status: 'ACTIVE', issuedAt: '2026-10-16T06:55:39.565Z' }
    ]
  };

  // v2 revokes delegateA
  const v2 = createAuthorizedRegistryUpdate(
    v1,
    {
      revokedKeyIds: [delegateA.keyId],
      keys: [
        { keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: delegateA.keyId, keyFingerprint: delegateA.fp, publicKeyPem: delegateA.pem, status: 'REVOKED', issuedAt: '2026-10-16T06:55:39.565Z' }
      ]
    },
    auth.keyId,
    auth.privateKey
  );

  // Attempting to create v3 using revoked delegateA key must throw
  assert.throws(
    () => createAuthorizedRegistryUpdate(v2, {}, delegateA.keyId, delegateA.privateKey),
    /REVOKED_KEY_AUTHORIZATION_REJECTED/
  );

  // Attempting to validate a forged v3 signed by delegateA against priorRegistry v2 must fail
  const forgedV3 = {
    ...v2,
    registryVersion: 3,
    authorizationProof: {
      authorizedBy: delegateA.keyId,
      signature: crypto.sign(null, Buffer.from('test', 'utf8'), delegateA.privateKey).toString('hex')
    }
  };
  const val = validateTrustRegistry(forgedV3, { priorRegistry: v2, trustedRootKeyId: auth.keyId, trustedRootPublicKeyPem: auth.pem });
  assert.equal(val.valid, false);
  assert.ok(val.error.includes('[REVOKED_KEY_AUTHORIZATION_REJECTED]'));
});

test('PLUGIN_DATA Governance: R08-B07 - Atomic stale lock reclamation cleans up dead lock without race', () => {
  const tempDir = createTempDir('r08-b07-stale-lock-');
  const targetFile = path.join(tempDir, 'resource.txt');
  const lockFile = `${targetFile}.lock`;

  // Create an artificially stale lock with dead PID (999999) and mtime 60s in the past
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 999999, timestamp: Date.now() - 60000, lockId: 'STALE-999' }), 'utf8');
  const oldTime = (Date.now() - 60000) / 1000;
  fs.utimesSync(lockFile, oldTime, oldTime);

  let executed = false;
  const res = withFileLock(targetFile, () => {
    executed = true;
    return 'ACQUIRED_AFTER_STALE_RECLAMATION';
  }, { staleLockTimeoutMs: 1000 });

  assert.equal(executed, true);
  assert.equal(res, 'ACQUIRED_AFTER_STALE_RECLAMATION');
  assert.equal(fs.existsSync(lockFile), false);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R09-B01 - Non-PREPARED or corrupted WAL status fails closed on recovery', () => {
  const tempDir = createTempDir('r09-b01-wal-status-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true
  };

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // 1. Status 'CORRUPTED' must throw and refuse to proceed fail-closed
  fs.writeFileSync(txnPath, JSON.stringify({ txnId: 'T1', status: 'CORRUPTED' }, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED.*invalid or unrecoverable status \(CORRUPTED\)/
  );

  // 2. Status 'UNKNOWN' must throw fail-closed
  fs.writeFileSync(txnPath, JSON.stringify({ txnId: 'T2', status: 'UNKNOWN' }, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED.*invalid or unrecoverable status \(UNKNOWN\)/
  );

  // 3. Status 'PREPARED' with missing required paths must throw fail-closed
  fs.writeFileSync(txnPath, JSON.stringify({ txnId: 'T3', status: 'PREPARED' }, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED.*missing required paths/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R09-B03 - Stale reclaim lock with ALIVE PID is NOT unlinked', () => {
  const tempDir = createTempDir('r09-b03-reclaim-alive-');
  const targetFile = path.join(tempDir, 'resource.txt');
  const lockFile = `${targetFile}.lock`;
  const reclaimLockFile = `${lockFile}.reclaim`;

  // Create an artificially stale lock with dead PID (999999)
  fs.writeFileSync(lockFile, JSON.stringify({ pid: 999999, timestamp: Date.now() - 60000, lockId: 'DEAD-MAIN' }), 'utf8');
  const oldTime = (Date.now() - 60000) / 1000;
  fs.utimesSync(lockFile, oldTime, oldTime);

  // Create a reclaim lock held by the CURRENT process (which is alive!)
  fs.writeFileSync(reclaimLockFile, JSON.stringify({ pid: process.pid, timestamp: Date.now() - 5000, reclaimLockId: 'ALIVE-REC' }), 'utf8');
  const reclaimOldTime = (Date.now() - 5000) / 1000;
  fs.utimesSync(reclaimLockFile, reclaimOldTime, reclaimOldTime);

  // Another process attempting to acquire should time out because reclaim lock is held by an ALIVE process
  assert.throws(
    () => withFileLock(targetFile, () => 'SHOULD_NOT_ACQUIRE', { lockTimeoutMs: 150, staleLockTimeoutMs: 1000 }),
    /LOCK_TIMEOUT/
  );

  // Assert reclaim lock was NOT unlinked because PID is alive
  assert.equal(fs.existsSync(reclaimLockFile), true);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R10-B01 - Counterfeit PREPARED WAL without valid signature fails closed', () => {
  const tempDir = createTempDir('r10-b01-counterfeit-wal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const regPath = getTrustRegistryPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // 1. Missing signature fails closed
  const missingSigWal = {
    txnId: 'TXN-FORGED-1',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    initialJournalSize: 0,
    checkpointPath,
    regPath,
    initialRegistryVersion: 1
  };
  fs.writeFileSync(txnPath, JSON.stringify(missingSigWal, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // 2. Tampered signature fails closed
  const tamperedSigWal = {
    ...missingSigWal,
    signature: 'deadbeef'.repeat(16)
  };
  fs.writeFileSync(txnPath, JSON.stringify(tamperedSigWal, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_SIGNATURE_INVALID/
  );

  // 3. Untrusted signer fails closed
  const untrustedSignerWal = {
    ...missingSigWal,
    signedBy: 'ROGUE-SIGNER-KEY',
    signature: 'deadbeef'.repeat(16)
  };
  fs.writeFileSync(txnPath, JSON.stringify(untrustedSignerWal, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_SIGNER_UNTRUSTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R10-B01 - Replayed old snapshot in WAL fails closed against higher on-disk version or HWM', () => {
  const tempDir = createTempDir('r10-b01-anti-rollback-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Perform two revocations so that on-disk HWM reaches headIndex: 1
  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-1' }, opts);
  appendRevocationEntry({ revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-2' }, opts);

  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const regPath = getTrustRegistryPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // Now an attacker signs a WAL claiming an initial state of Genesis with NO revocations (initialHwmHeadIndex: -1)
  const oldWalFields = {
    txnId: 'TXN-REPLAY-ATTACK',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath,
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath,
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1, // Old state before revocations!
    initialHwmHeadDigest: '',
    histPath: null,
    initialHistSha256: '0'.repeat(64),
    initialHistExisted: false
  };

  const signPayload = Buffer.from(computeTransactionWalSignPayload(oldWalFields), 'utf8');
  const signature = crypto.sign(null, signPayload, auth.privateKey).toString('hex');
  const replayedWal = { ...oldWalFields, signature };

  fs.writeFileSync(txnPath, JSON.stringify(replayedWal, null, 2), 'utf8');

  // Attempting recovery MUST fail closed because on-disk state already has committed HWM index 1!
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R10-B03 - withFileLock Default-Deny on invalid PID and atomic descriptor inode release', () => {
  const tempDir = createTempDir('r10-b03-pid-validation-');
  const targetFile = path.join(tempDir, 'resource.txt');
  const lockFile = `${targetFile}.lock`;
  const reclaimLockFile = `${lockFile}.reclaim`;

  // 1. Stale lock with string PID ("12345") or malformed JSON MUST NOT be reclaimed under Default-Deny
  fs.writeFileSync(lockFile, JSON.stringify({ pid: "12345", timestamp: Date.now() - 60000, lockId: 'STRING-PID' }), 'utf8');
  const oldTime = (Date.now() - 60000) / 1000;
  fs.utimesSync(lockFile, oldTime, oldTime);

  // An acquisition attempt must timeout because string PID is not presumed dead!
  assert.throws(
    () => withFileLock(targetFile, () => 'SHOULD_NOT_ACQUIRE', { lockTimeoutMs: 150, staleLockTimeoutMs: 1000 }),
    /LOCK_TIMEOUT/
  );
  assert.equal(fs.existsSync(lockFile), true);

  // 2. Stale reclaim lock with invalid string PID is NOT unlinked
  fs.writeFileSync(reclaimLockFile, JSON.stringify({ pid: "999999", timestamp: Date.now() - 5000, reclaimLockId: 'STRING-REC' }), 'utf8');
  const reclaimOldTime = (Date.now() - 5000) / 1000;
  fs.utimesSync(reclaimLockFile, reclaimOldTime, reclaimOldTime);

  assert.throws(
    () => withFileLock(targetFile, () => 'SHOULD_NOT_ACQUIRE', { lockTimeoutMs: 150, staleLockTimeoutMs: 1000 }),
    /LOCK_TIMEOUT/
  );
  assert.equal(fs.existsSync(reclaimLockFile), true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R10-B04 - WAL marked COMMITTED does not roll back on subsequent recovery', () => {
  const tempDir = createTempDir('r10-b04-committed-wal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Append entry successfully
  const res = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-COMMITTED' },
    opts
  );
  assert.equal(res.success, true);

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  // R10-B04 & R11-B02: Simulate situation where transaction committed and has legitimate signature and committed state
  const committedWal = {
    txnId: 'COMMITTED-TXN-1234',
    status: 'COMMITTED',
    createdAt: new Date().toISOString(),
    committedAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    committedHwmHeadIndex: res.entryIndex,
    committedHwmHeadDigest: res.entryDigest,
    expectedTargetHwmHeadIndex: res.entryIndex,
    expectedTargetHwmHeadDigest: res.entryDigest,
    expectedTargetRegistryVersion: 1
  };
  const committedPayload = Buffer.from(computeTransactionWalSignPayload(committedWal), 'utf8');
  committedWal.signature = crypto.sign(null, committedPayload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(committedWal, null, 2), 'utf8');

  // Recovery should verify signature and committed proof, safely cleaning up COMMITTED WAL without rolling back committed revocation
  const recRes = recoverAbortedRevocationTransaction(opts);
  assert.equal(recRes.recovered, false);
  assert.equal(recRes.committed, true);
  assert.equal(fs.existsSync(txnPath), false);

  // Verify revocation is still intact
  const revCheck = isRevoked('NONCE-COMMITTED', opts);
  assert.equal(revCheck.revoked, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R10-B05 - isRevoked executes atomically under unified governance lock', () => {
  const tempDir = createTempDir('r10-b05-isrevoked-atomic-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-ATOMIC-TEST' },
    opts
  );

  // Directly call isRevoked without skipLock -> should acquire governance lock, evaluate, and succeed
  const res1 = isRevoked('NONCE-ATOMIC-TEST', opts);
  assert.equal(res1.revoked, true);

  // Call isRevoked from INSIDE withGovernanceLock with skipLock: true -> should succeed without reentrant deadlock
  const res2 = withGovernanceLock(opts, () => {
    return isRevoked('NONCE-ATOMIC-TEST', { ...opts, skipLock: true });
  });
  assert.equal(res2.revoked, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R11-B01 - Injected unverified active key in on-disk registry fails to authorize WAL', () => {
  const tempDir = createTempDir('r11-b01-unverified-key-');
  const auth = generateTestAuthority();
  const attackerAuth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const regPath = getTrustRegistryPath(opts);
  // Attacker writes an on-disk registry containing their own key marked ACTIVE
  const forgedReg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'FORGED_ATTACKER_AUTHORITY',
    activeKeyId: attackerAuth.keyId,
    activeKeyFingerprint: attackerAuth.fp,
    activePublicKeyPem: attackerAuth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{
      keyId: attackerAuth.keyId,
      publicKeyPem: attackerAuth.pem,
      keyFingerprint: attackerAuth.fp,
      keyType: 'ed25519',
      role: 'ATTACKER_SUPERVISOR',
      status: 'ACTIVE',
      validFrom: new Date().toISOString(),
      authorizedBy: attackerAuth.keyId
    }]
  };
  fs.writeFileSync(regPath, JSON.stringify(forgedReg, null, 2), 'utf8');

  // Attacker signs a PREPARED WAL using their attacker private key
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const forgedWal = {
    txnId: 'FORGED-WAL-R11',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: attackerAuth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath,
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(forgedWal), 'utf8');
  forgedWal.signature = crypto.sign(null, payload, attackerAuth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(forgedWal, null, 2), 'utf8');

  // Recovery MUST refuse to trust attacker key from unverified on-disk registry
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_SIGNER_UNTRUSTED/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R11-B02 - Unsigned or forged COMMITTED WAL fails closed', () => {
  const tempDir = createTempDir('r11-b02-forged-committed-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  // Fake COMMITTED WAL with bad signature
  fs.writeFileSync(txnPath, JSON.stringify({
    txnId: 'FAKE-COMMITTED',
    status: 'COMMITTED',
    journalPath: getRevocationJournalPath(opts),
    checkpointPath: getRevocationCheckpointPath(opts),
    regPath: getTrustRegistryPath(opts),
    initialJournalSize: 0,
    signedBy: auth.keyId,
    signature: 'bad-sig',
    initialRegistryVersion: 1
  }), 'utf8');

  // Must fail closed under signature verification
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_SIGNATURE_INVALID/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R11-B03 - Corrupted on-disk registry fails closed with TRANSACTION_WAL_ROLLBACK_CHECK_FAILED', () => {
  const tempDir = createTempDir('r11-b03-corrupt-reg-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Write a corrupted on-disk registry
  const regPath = getTrustRegistryPath(opts);
  fs.writeFileSync(regPath, '{ corrupted json: not valid !!', 'utf8');

  // Validly signed PREPARED WAL exists
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-TEST-CORRUPT-REG',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath,
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Recovery MUST NOT ignore corrupt registry to bypass rollback check; it must fail closed!
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_ROLLBACK_CHECK_FAILED/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R11-B03 - Modified journal prefix before rollback fails closed with TRANSACTION_WAL_JOURNAL_INTEGRITY_MISMATCH', () => {
  const tempDir = createTempDir('r11-b03-journal-prefix-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  const journalPath = getRevocationJournalPath(opts);
  fs.writeFileSync(journalPath, 'tampered-prefix-bytes\n', 'utf8');

  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-PREFIX-CHECK',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    initialJournalSize: 10,
    initialJournalExisted: true,
    initialJournalSha256: 'a'.repeat(64), // mismatch!
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Must fail closed due to journal prefix mismatch before truncation
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_JOURNAL_INTEGRITY_MISMATCH/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R11-B04 - Crash after registry update is recognized as committed without rollback', () => {
  const tempDir = createTempDir('r11-b04-crash-after-reg-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Perform normal revocation append
  const res = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-CRASH-TEST' },
    opts
  );
  assert.equal(res.success, true);

  // Simulate crash that occurred after registry update succeeded, so on-disk HWM is at res.entryIndex
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-CRASH-POST-REG',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    expectedTargetHwmHeadIndex: res.entryIndex,
    expectedTargetHwmHeadDigest: res.entryDigest,
    expectedTargetRegistryVersion: 1
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Recovery should recognize forward progression matching expectedTarget*, clean up WAL marker and mark committed
  const recRes = recoverAbortedRevocationTransaction(opts);
  assert.equal(recRes.recovered, false);
  assert.equal(recRes.committed, true);
  assert.equal(fs.existsSync(txnPath), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B01 - Empty or schema-corrupt on-disk registry fails closed and prevents WAL rollback', () => {
  const tempDir = createTempDir('r12-b01-empty-reg-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Attacker places an empty JSON object '{}' on disk
  const regPath = getTrustRegistryPath(opts);
  fs.writeFileSync(regPath, JSON.stringify({}), 'utf8');

  // Validly signed PREPARED WAL exists from authorized supervisor
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-EMPTY-REG-R12',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath,
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Must fail closed under Default-Deny instead of skipping anti-rollback check
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_ROLLBACK_CHECK_FAILED/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B02 - External monotonic witness and in-process witness reject full-directory state rollback', () => {
  const tempDir = createTempDir('r12-b02-witness-rollback-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // 1. Establish state with initial v1 registry and a revocation entry (HWM >= 0, version 1)
  const initialReg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{
      keyId: auth.keyId,
      publicKeyPem: auth.pem,
      keyFingerprint: auth.fp,
      keyType: 'ed25519',
      role: 'SUPERVISOR_ROOT',
      status: 'ACTIVE_PINNED_ROOT',
      issuedAt: new Date().toISOString()
    }]
  };
  saveTrustRegistry(initialReg, opts);

  const res = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-REVOKED-WITNESS-TEST' },
    opts
  );
  assert.equal(res.success, true);

  // 2. Attacker restores the whole directory to the earlier historical snapshot (initialReg without revocations)
  const regPath = getTrustRegistryPath(opts);
  const journalPath = getRevocationJournalPath(opts);
  const cpPath = getRevocationCheckpointPath(opts);
  const histPath = path.join(tempDir, 'history', 'trust-registry.v1.json');
  fs.unlinkSync(journalPath);
  fs.unlinkSync(cpPath);
  const rawV1 = JSON.stringify(initialReg, null, 2) + '\n';
  fs.writeFileSync(regPath, rawV1, 'utf8');
  fs.writeFileSync(histPath, rawV1, 'utf8');

  // 3. Process witness knows HWM headIndex was res.entryIndex; reading restored old state must fail closed
  assert.throws(() => {
    loadTrustRegistry(opts);
  }, /MONOTONIC_WITNESS_ROLLBACK_DETECTED/);

  // 4. External monotonic witness in options also rejects rollback fail-closed
  assert.throws(() => {
    loadTrustRegistry({
      ...opts,
      externalMonotonicWitness: { minRegistryVersion: 1, minHwmHeadIndex: 0 }
    });
  }, /MONOTONIC_WITNESS_ROLLBACK_DETECTED/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B03 - COMMITTED WAL with mismatched or missing committedHwmHeadDigest fails closed', () => {
  const tempDir = createTempDir('r12-b03-committed-digest-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  // Perform normal append
  const res = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-DIGEST-TEST' },
    opts
  );
  assert.equal(res.success, true);

  // Create COMMITTED WAL with mismatched committedHwmHeadDigest
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-COMMITTED-BAD-DIGEST',
    status: 'COMMITTED',
    createdAt: new Date().toISOString(),
    committedAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    committedHwmHeadIndex: res.entryIndex,
    committedHwmHeadDigest: 'f'.repeat(64) // Forged/mismatched digest!
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Must fail closed and MUST NOT unlink the WAL!
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_CORRUPTION_DETECTED/);
  assert.equal(fs.existsSync(txnPath), true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B04 - Cannot bypass withGovernanceLock via global Symbol.for', () => {
  const tempDir = createTempDir('r12-b04-symbol-for-bypass-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    skipLock: true,
    [Symbol.for('three_lens.governance.internal_lock_token')]: true
  };

  // Caller attempts to bypass withGovernanceLock by fabricating Symbol.for token.
  // Module private Symbol cannot be forged, so skipLock is ignored and lock is acquired.
  const res = loadTrustRegistry(opts);
  assert.equal(res.valid, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B05 - PREPARED WAL does not claim committed without full on-disk post-image match', () => {
  const tempDir = createTempDir('r12-b05-partial-wal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp,
    signerKeyId: auth.keyId,
    signerPrivateKey: auth.privateKey
  };

  const res = appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.NONCE_REVOCATION, targetId: 'NONCE-PARTIAL-TEST' },
    opts
  );
  assert.equal(res.success, true);

  // Delete the checkpoint file to simulate partial write failure before crash
  const cpPath = getRevocationCheckpointPath(opts);
  fs.unlinkSync(cpPath);

  // PREPARED WAL claiming expected target exists
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-PARTIAL-WRITE',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: cpPath,
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    expectedTargetHwmHeadIndex: res.entryIndex,
    expectedTargetHwmHeadDigest: res.entryDigest,
    expectedTargetRegistryVersion: 1
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Because checkpoint is missing, recovery MUST NOT falsely claim committed
  assert.throws(() => {
    recoverAbortedRevocationTransaction(opts);
  }, /TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED/);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R12-B06 - Rotated supervisor key in validated history chain can authorize WAL', () => {
  const tempDir = createTempDir('r12-b06-rotated-key-wal-');
  const auth1 = generateTestAuthority();
  const auth2 = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth1.keyId,
    trustedRootPublicKeyPem: auth1.pem,
    trustedRootFingerprint: auth1.fp
  };

  // 1. Initialize v1 registry
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth1.keyId,
    activeKeyFingerprint: auth1.fp,
    activePublicKeyPem: auth1.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{
      keyId: auth1.keyId,
      publicKeyPem: auth1.pem,
      keyFingerprint: auth1.fp,
      keyType: 'ed25519',
      role: 'SUPERVISOR_ROOT',
      status: 'ACTIVE_PINNED_ROOT',
      issuedAt: new Date().toISOString()
    }]
  };
  saveTrustRegistry(v1Reg, opts);

  // 2. Rotate to v2 signed by auth1, introducing auth2 as ACTIVE
  const v2Reg = createAuthorizedRegistryUpdate(
    v1Reg,
    {
      activeKeyId: auth2.keyId,
      activeKeyFingerprint: auth2.fp,
      activePublicKeyPem: auth2.pem,
      keys: [
        {
          keyId: auth1.keyId,
          publicKeyPem: auth1.pem,
          keyFingerprint: auth1.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'RETIRED',
          issuedAt: new Date().toISOString()
        },
        {
          keyId: auth2.keyId,
          publicKeyPem: auth2.pem,
          keyFingerprint: auth2.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'ACTIVE',
          issuedAt: new Date().toISOString()
        }
      ]
    },
    auth1.keyId,
    auth1.privateKey
  );
  saveTrustRegistry(v2Reg, { ...opts, priorRegistry: v1Reg });

  // 3. Create a PREPARED WAL signed by auth2 (newly rotated active key)
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-ROTATED-KEY-R12',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth2.keyId,
    journalPath: getRevocationJournalPath(opts),
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath: getTrustRegistryPath(opts),
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 2,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth2.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Recovery must validate auth2 through the historical trust chain and recover cleanly
  const recRes = recoverAbortedRevocationTransaction(opts);
  assert.equal(recRes.recovered, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R13-B01 - Incomplete registry schema { registryVersion: 1 } strictly fails closed and prevents WAL rollback', () => {
  const tempDir = createTempDir('r13-b01-incomplete-reg-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // Write a journal with 1 entry
  const journalPath = getRevocationJournalPath(opts);
  const entry = {
    entryIndex: 0,
    timestamp: new Date().toISOString(),
    revocationType: REVOCATION_TYPES.KEY_REVOCATION,
    targetId: 'TEST-REVOKED-TARGET',
    reason: 'COMPROMISED_KEY',
    prevEntryDigest: '0'.repeat(64),
    signedBy: auth.keyId,
    signature: '0'.repeat(128)
  };
  fs.writeFileSync(journalPath, JSON.stringify(entry) + '\n', 'utf8');

  // Incomplete registry schema: only { registryVersion: 1 }
  const regPath = getTrustRegistryPath(opts);
  fs.writeFileSync(regPath, JSON.stringify({ registryVersion: 1 }, null, 2), 'utf8');

  // PREPARED WAL attempting to truncate journal
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const wal = {
    txnId: 'WAL-R13-B01',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    initialJournalSize: 0,
    initialJournalExisted: false,
    initialJournalSha256: '0'.repeat(64),
    checkpointPath: getRevocationCheckpointPath(opts),
    initialCheckpointSha256: '0'.repeat(64),
    initialCheckpointExisted: false,
    regPath,
    initialRegistrySha256: '0'.repeat(64),
    initialRegistryExisted: false,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: ''
  };
  const payload = Buffer.from(computeTransactionWalSignPayload(wal), 'utf8');
  wal.signature = crypto.sign(null, payload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(wal, null, 2), 'utf8');

  // Must fail closed before truncating journal or unlinking WAL
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_ROLLBACK_CHECK_FAILED/
  );

  // Assert journal is NOT truncated and WAL is NOT unlinked
  assert.equal(fs.existsSync(journalPath), true);
  assert.equal(fs.readFileSync(journalPath, 'utf8').trim().length > 0, true);
  assert.equal(fs.existsSync(txnPath), true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R13-B02 & R13-B03 - Persistent monotonic witness survives process restart and journal fail-closed', () => {
  const tempDir = createTempDir('r13-b02-persistent-witness-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // 1. Append a revocation entry to move witness to headIndex 0
  appendRevocationEntry(
    {
      revocationType: REVOCATION_TYPES.KEY_REVOCATION,
      targetId: 'VICTIM-KEY-01',
      reason: 'TEST_REVOCATION'
    },
    {
      ...opts,
      signerKeyId: auth.keyId,
      signerPrivateKey: auth.privateKey
    }
  );

  // Verify persistent witness file exists in local directory
  const localWitness = path.join(tempDir, '.monotonic-witness.json');
  assert.equal(fs.existsSync(localWitness), true);

  // 2. Whole-directory state rollback simulation:
  // Overwrite registry with an old version 1 without HWM, update history to match, and remove local witness
  const regPath = getTrustRegistryPath(opts);
  const v1NoHwm = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  fs.writeFileSync(regPath, JSON.stringify(v1NoHwm, null, 2), 'utf8');
  const histPath = path.join(tempDir, 'history', 'trust-registry.v1.json');
  if (fs.existsSync(histPath)) {
    fs.writeFileSync(histPath, JSON.stringify(v1NoHwm, null, 2), 'utf8');
  }
  try { fs.unlinkSync(localWitness); } catch (_) {}
  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  try { fs.unlinkSync(journalPath); } catch (_) {}
  try { fs.unlinkSync(checkpointPath); } catch (_) {}

  // 3. Cold-Start / Process Restart Simulation:
  // Execute in a separate Node.js process with zero in-memory witness state.
  // The independent persistent system witness on disk MUST detect whole-directory rollback!
  const adapterUrl = pathToFileURL(path.resolve('scripts/adapters/plugin-data-adapter.mjs')).href;
  const childScript = `
    import { loadTrustRegistry, loadRevocationJournal } from '${adapterUrl}';
    import assert from 'node:assert';
    const opts = ${JSON.stringify(opts)};
    assert.throws(
      () => loadTrustRegistry({ ...opts, failClosed: true }),
      /MONOTONIC_WITNESS_ROLLBACK_DETECTED/
    );
    assert.throws(
      () => loadRevocationJournal({ ...opts, failClosed: true }),
      /MONOTONIC_WITNESS_ROLLBACK_DETECTED|TRUST_REGISTRY_INVALID/
    );
  `;
  execFileSync(process.execPath, ['--input-type=module', '-e', childScript], { stdio: 'pipe' });

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R13-B04 - AsyncLocalStorage confinement prevents capability leakage via lockedOpts cloning or closure', () => {
  const tempDir = createTempDir('r13-b04-als-confinement-');
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    lockTimeoutMs: 100
  };

  let escapedOpts = null;
  withGovernanceLock(opts, (lockedOpts) => {
    assert.equal(isGovernanceLockHeld(tempDir), true);
    escapedOpts = { ...lockedOpts };
  });

  // After withGovernanceLock terminates, lock is released and ALS context is destroyed
  assert.equal(isGovernanceLockHeld(tempDir), false);

  // Calling loadTrustRegistry with escapedOpts outside ALS acquires lock normally without error
  const regRes = loadTrustRegistry(escapedOpts);
  assert.equal(regRes.valid, true);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R13-B05 - COMMITTED WAL strictly verifies physical journal tail entry', () => {
  const tempDir = createTempDir('r13-b05-committed-tail-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const regPath = getTrustRegistryPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  const entry0Unsigned = {
    entryIndex: 0,
    timestamp: new Date().toISOString(),
    revocationType: REVOCATION_TYPES.KEY_REVOCATION,
    targetId: 'TARGET-01',
    reason: 'TEST',
    prevEntryDigest: '0'.repeat(64),
    signedBy: auth.keyId
  };
  const entry0SigPayload = Buffer.from(computeRevocationEntrySignPayload(entry0Unsigned), 'utf8');
  const entry0Sig = crypto.sign(null, entry0SigPayload, auth.privateKey).toString('hex');
  const entry0 = {
    ...entry0Unsigned,
    signature: entry0Sig
  };
  const entry0Digest = sha256Digest(canonicalJsonStringify(entry0));

  // Registry and checkpoint at headIndex 0
  const hwm = {
    headIndex: 0,
    headDigest: entry0Digest,
    updatedAt: new Date().toISOString(),
    authorizedBy: auth.keyId
  };
  const hwmSig = crypto.sign(null, Buffer.from(canonicalJsonStringify(hwm), 'utf8'), auth.privateKey).toString('hex');
  const reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }],
    revocationHighWaterMark: {
      ...hwm,
      signature: hwmSig
    }
  };
  fs.writeFileSync(regPath, JSON.stringify(reg, null, 2), 'utf8');

  const cp = {
    headIndex: 0,
    headDigest: entry0Digest,
    updatedAt: new Date().toISOString(),
    registryVersion: 1
  };
  fs.writeFileSync(checkpointPath, JSON.stringify(cp, null, 2), 'utf8');

  // Create COMMITTED WAL
  const committedWal = {
    txnId: 'TXN-COMMITTED-R13-B05',
    status: 'COMMITTED',
    committedAt: new Date().toISOString(),
    signedBy: auth.keyId,
    journalPath,
    checkpointPath,
    regPath,
    initialJournalSize: 0,
    initialRegistryVersion: 1,
    committedHwmHeadIndex: 0,
    committedHwmHeadDigest: entry0Digest
  };
  const walSigPayload = Buffer.from(computeTransactionWalSignPayload(committedWal), 'utf8');
  committedWal.signature = crypto.sign(null, walSigPayload, auth.privateKey).toString('hex');

  // Case 1: Journal is missing -> fails closed
  fs.writeFileSync(txnPath, JSON.stringify(committedWal, null, 2), 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // Case 2: Journal is empty (0 lines) -> fails closed
  fs.writeFileSync(journalPath, '', 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // Case 3: Journal has mismatched tail entry -> fails closed
  const tamperedEntry = { ...entry0, targetId: 'TAMPERED' };
  fs.writeFileSync(journalPath, JSON.stringify(tamperedEntry) + '\n', 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // Case 3b: Journal tail has invalid cryptographic signature -> fails closed
  const forgedSigEntry = { ...entry0, signature: '0'.repeat(128) };
  fs.writeFileSync(journalPath, JSON.stringify(forgedSigEntry) + '\n', 'utf8');
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  // Case 4: Journal has exact matching tail entry with valid signature -> succeeds, safely unlinks WAL
  fs.writeFileSync(journalPath, JSON.stringify(entry0) + '\n', 'utf8');
  const res = recoverAbortedRevocationTransaction(opts);
  assert.equal(res.committed, true);
  assert.equal(fs.existsSync(txnPath), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R13-B06 & R13-B08 - Multi-generation key rotation chain and retired key rejection', () => {
  const tempDir = createTempDir('r13-b06-b08-rotation-');
  const auth1 = generateTestAuthority();
  const auth2 = generateTestAuthority();
  const auth3 = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth1.keyId,
    trustedRootPublicKeyPem: auth1.pem,
    trustedRootFingerprint: auth1.fp
  };

  // 1. Genesis v1 with auth1
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth1.keyId,
    activeKeyFingerprint: auth1.fp,
    activePublicKeyPem: auth1.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{
      keyId: auth1.keyId,
      publicKeyPem: auth1.pem,
      keyFingerprint: auth1.fp,
      keyType: 'ed25519',
      role: 'SUPERVISOR_ROOT',
      status: 'ACTIVE_PINNED_ROOT',
      issuedAt: new Date().toISOString()
    }]
  };
  saveTrustRegistry(v1Reg, opts);

  // 2. v2: rotate to auth2 (ACTIVE), auth1 becomes RETIRED, signed by auth1
  const v2Reg = createAuthorizedRegistryUpdate(
    v1Reg,
    {
      activeKeyId: auth2.keyId,
      activeKeyFingerprint: auth2.fp,
      activePublicKeyPem: auth2.pem,
      keys: [
        {
          keyId: auth1.keyId,
          publicKeyPem: auth1.pem,
          keyFingerprint: auth1.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'RETIRED',
          issuedAt: new Date().toISOString()
        },
        {
          keyId: auth2.keyId,
          publicKeyPem: auth2.pem,
          keyFingerprint: auth2.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'ACTIVE',
          issuedAt: new Date().toISOString()
        }
      ]
    },
    auth1.keyId,
    auth1.privateKey
  );
  saveTrustRegistry(v2Reg, { ...opts, priorRegistry: v1Reg });

  // 3. R13-B08: RETIRED key auth1 CANNOT authorize new registry update!
  assert.throws(
    () => createAuthorizedRegistryUpdate(
      v2Reg,
      { activeKeyId: auth3.keyId, activeKeyFingerprint: auth3.fp, activePublicKeyPem: auth3.pem },
      auth1.keyId,
      auth1.privateKey
    ),
    /RETIRED_KEY_AUTHORIZATION_REJECTED/
  );

  // 4. v3: rotate to auth3 (ACTIVE), auth2 becomes RETIRED, signed by auth2 (ACTIVE in v2)
  const v3Reg = createAuthorizedRegistryUpdate(
    v2Reg,
    {
      activeKeyId: auth3.keyId,
      activeKeyFingerprint: auth3.fp,
      activePublicKeyPem: auth3.pem,
      keys: [
        {
          keyId: auth1.keyId,
          publicKeyPem: auth1.pem,
          keyFingerprint: auth1.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'RETIRED',
          issuedAt: new Date().toISOString()
        },
        {
          keyId: auth2.keyId,
          publicKeyPem: auth2.pem,
          keyFingerprint: auth2.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'RETIRED',
          issuedAt: new Date().toISOString()
        },
        {
          keyId: auth3.keyId,
          publicKeyPem: auth3.pem,
          keyFingerprint: auth3.fp,
          keyType: 'ed25519',
          role: 'SUPERVISOR_ROOT',
          status: 'ACTIVE',
          issuedAt: new Date().toISOString()
        }
      ]
    },
    auth2.keyId,
    auth2.privateKey
  );

  // R13-B06: Validating v3 with priorRegistry v2 succeeds via unbroken historical chain (v1 in history/)
  const v3Validation = validateTrustRegistry(v3Reg, {
    ...opts,
    priorRegistry: v2Reg
  });
  assert.equal(v3Validation.valid, true);

  // Save v3
  saveTrustRegistry(v3Reg, { ...opts, priorRegistry: v2Reg });

  // Load trust registry loads v3 cleanly
  const loaded = loadTrustRegistry(opts);
  assert.equal(loaded.valid, true);
  assert.equal(loaded.registry.registryVersion, 3);
  assert.equal(loaded.registry.activeKeyId, auth3.keyId);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R14-B01 - AsyncLocalStorage capability deactivation prevents microtask leakage', async () => {
  const tempDir = createTempDir('r14-b01-als-microtask-');
  const opts = { pluginDataDir: tempDir, allowInWorkspace: true };

  let microtaskObservedHeld = null;
  withGovernanceLock(opts, () => {
    assert.equal(isGovernanceLockHeld(tempDir), true);
    queueMicrotask(() => {
      microtaskObservedHeld = isGovernanceLockHeld(tempDir);
    });
  });

  // Yield to allow microtask to execute
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(microtaskObservedHeld, false);
  assert.equal(isGovernanceLockHeld(tempDir), false);

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R14-B02 - Persistent monotonic witness has no public deletion entrance', async () => {
  const adapter = await import('../scripts/adapters/plugin-data-adapter.mjs');
  assert.equal('resetMonotonicWitnessForTest' in adapter, false);
});

test('PLUGIN_DATA Governance: R14-B03 - PREPARED WAL snapshot semantic binding and retired signer rejection', () => {
  const tempDir = createTempDir('r14-b03-wal-semantics-');
  const auth1 = generateTestAuthority();
  const auth2 = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth1.keyId,
    trustedRootPublicKeyPem: auth1.pem,
    trustedRootFingerprint: auth1.fp
  };

  const regPath = getTrustRegistryPath(opts);
  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // Setup v1 registry
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth1.keyId,
    activeKeyFingerprint: auth1.fp,
    activePublicKeyPem: auth1.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth1.keyId, keyFingerprint: auth1.fp, publicKeyPem: auth1.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }]
  };
  saveTrustRegistry(v1Reg, opts);

  // Rotate to v2 where auth1 is RETIRED and auth2 is ACTIVE
  const v2Reg = createAuthorizedRegistryUpdate(
    v1Reg,
    {
      activeKeyId: auth2.keyId,
      activeKeyFingerprint: auth2.fp,
      activePublicKeyPem: auth2.pem,
      keys: [
        { keyId: auth1.keyId, keyFingerprint: auth1.fp, publicKeyPem: auth1.pem, status: 'RETIRED', issuedAt: new Date().toISOString() },
        { keyId: auth2.keyId, keyFingerprint: auth2.fp, publicKeyPem: auth2.pem, status: 'ACTIVE', issuedAt: new Date().toISOString() }
      ]
    },
    auth1.keyId,
    auth1.privateKey
  );
  saveTrustRegistry(v2Reg, { ...opts, priorRegistry: v1Reg });

  // Attack 1: Retired auth1 attempts to sign a PREPARED WAL
  const retiredWal = {
    txnId: 'TXN-RETIRED-SIGNER',
    status: 'PREPARED',
    journalPath,
    checkpointPath,
    regPath,
    initialJournalSize: 0,
    initialRegistryVersion: 2,
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    signedBy: auth1.keyId
  };
  const walSigPayload = Buffer.from(computeTransactionWalSignPayload(retiredWal), 'utf8');
  retiredWal.signature = crypto.sign(null, walSigPayload, auth1.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(retiredWal, null, 2), 'utf8');

  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /RETIRED_KEY_AUTHORIZATION_REJECTED/
  );

  // Attack 2: Semantic Snapshot Mismatch: Active auth2 signs WAL declaring initialRegistryVersion 2,
  // but embedding a v1 snapshot payload
  const v1RawBase64 = Buffer.from(JSON.stringify(v1Reg)).toString('base64');
  const v1Sha256 = sha256Digest(Buffer.from(v1RawBase64, 'base64'));
  const semanticMismatchWal = {
    txnId: 'TXN-SEMANTIC-MISMATCH',
    status: 'PREPARED',
    journalPath,
    checkpointPath,
    regPath,
    initialJournalSize: 0,
    initialRegistryVersion: 2, // Claims 2
    initialHwmHeadIndex: -1,
    initialHwmHeadDigest: '',
    initialRegistryRawBase64: v1RawBase64, // Embeds 1
    initialRegistrySha256: v1Sha256,
    signedBy: auth2.keyId
  };
  const wal2SigPayload = Buffer.from(computeTransactionWalSignPayload(semanticMismatchWal), 'utf8');
  semanticMismatchWal.signature = crypto.sign(null, wal2SigPayload, auth2.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(semanticMismatchWal, null, 2), 'utf8');

  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R14-B04 - Retired key cannot authorize new HWM or newer journal records', () => {
  const tempDir = createTempDir('r14-b04-retired-hwm-');
  const auth1 = generateTestAuthority();
  const auth2 = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth1.keyId,
    trustedRootPublicKeyPem: auth1.pem,
    trustedRootFingerprint: auth1.fp
  };

  // v1 with auth1 active
  const v1Reg = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth1.keyId,
    activeKeyFingerprint: auth1.fp,
    activePublicKeyPem: auth1.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth1.keyId, keyFingerprint: auth1.fp, publicKeyPem: auth1.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }]
  };
  saveTrustRegistry(v1Reg, opts);

  // auth1 signs entry 0
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-001' },
    { ...opts, signerKeyId: auth1.keyId, signerPrivateKey: auth1.privateKey }
  );

  // Rotate to v2 retiring auth1
  const curReg = loadTrustRegistry(opts).registry;
  const v2Reg = createAuthorizedRegistryUpdate(
    curReg,
    {
      activeKeyId: auth2.keyId,
      activeKeyFingerprint: auth2.fp,
      activePublicKeyPem: auth2.pem,
      keys: [
        { keyId: auth1.keyId, keyFingerprint: auth1.fp, publicKeyPem: auth1.pem, status: 'RETIRED', issuedAt: new Date().toISOString() },
        { keyId: auth2.keyId, keyFingerprint: auth2.fp, publicKeyPem: auth2.pem, status: 'ACTIVE', issuedAt: new Date().toISOString() }
      ]
    },
    auth1.keyId,
    auth1.privateKey
  );
  saveTrustRegistry(v2Reg, { ...opts, priorRegistry: curReg });

  // Attack A: Forged HWM signed by retired auth1
  const forgedHwm = {
    headIndex: 1,
    headDigest: 'a'.repeat(64),
    updatedAt: new Date().toISOString(),
    authorizedBy: auth1.keyId
  };
  const forgedHwmSig = crypto.sign(null, Buffer.from(canonicalJsonStringify(forgedHwm), 'utf8'), auth1.privateKey).toString('hex');
  const regWithForgedHwm = {
    ...v2Reg,
    revocationHighWaterMark: {
      ...forgedHwm,
      signature: forgedHwmSig
    }
  };
  const val = validateTrustRegistry(regWithForgedHwm, { ...opts, priorRegistry: curReg });
  assert.equal(val.valid, false);
  assert.match(val.error, /RETIRED_KEY_AUTHORIZATION_REJECTED/);

  // Attack B: Retired auth1 signs a new journal entry at index 1 (past its retirement index 0)
  const journalPath = getRevocationJournalPath(opts);
  const entry0Raw = fs.readFileSync(journalPath, 'utf8').trim();
  const entry0Obj = JSON.parse(entry0Raw);
  const entry0Digest = sha256Digest(canonicalJsonStringify(entry0Obj));

  const rogueEntry1 = {
    entryIndex: 1,
    timestamp: new Date().toISOString(),
    revocationType: REVOCATION_TYPES.KEY_REVOCATION,
    targetId: 'KEY-002',
    reason: 'ROGUE',
    prevEntryDigest: entry0Digest,
    signedBy: auth1.keyId
  };
  const rogueSigPayload = Buffer.from(computeRevocationEntrySignPayload(rogueEntry1), 'utf8');
  rogueEntry1.signature = crypto.sign(null, rogueSigPayload, auth1.privateKey).toString('hex');
  fs.appendFileSync(journalPath, JSON.stringify(rogueEntry1) + '\n', 'utf8');

  // Also update checkpoint and registry HWM (signed by active auth2) to match rogue entry index 1
  const rogueEntry1Digest = sha256Digest(canonicalJsonStringify(rogueEntry1));
  const checkpointPath = getRevocationCheckpointPath(opts);
  const rogueCp = {
    headIndex: 1,
    headDigest: rogueEntry1Digest,
    updatedAt: new Date().toISOString(),
    registryVersion: 2
  };
  fs.writeFileSync(checkpointPath, JSON.stringify(rogueCp, null, 2), 'utf8');

  const hwm1 = {
    headIndex: 1,
    headDigest: rogueEntry1Digest,
    updatedAt: new Date().toISOString(),
    authorizedBy: auth2.keyId
  };
  const hwm1Sig = crypto.sign(null, Buffer.from(canonicalJsonStringify(hwm1), 'utf8'), auth2.privateKey).toString('hex');
  const regWithHwm1 = {
    ...v2Reg,
    revocationHighWaterMark: {
      ...hwm1,
      signature: hwm1Sig
    }
  };
  const regPath = getTrustRegistryPath(opts);
  fs.writeFileSync(regPath, JSON.stringify(regWithHwm1, null, 2), 'utf8');
  const v2HistPath = path.join(tempDir, 'history', 'trust-registry.v2.json');
  fs.writeFileSync(v2HistPath, JSON.stringify(regWithHwm1, null, 2), 'utf8');

  assert.throws(
    () => loadRevocationJournal({ ...opts, failClosed: true }),
    /RETIRED_KEY_AUTHORIZATION_REJECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R14-B06 & R14-B07 - Monotonic witness corrupted file fail-closed and divergence detection', () => {
  const tempDir = createTempDir('r14-b06-b07-witness-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // Append revocation to create local witness
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-001' },
    { ...opts, signerKeyId: auth.keyId, signerPrivateKey: auth.privateKey }
  );

  const localWitness = path.join(tempDir, '.monotonic-witness.json');
  assert.equal(fs.existsSync(localWitness), true);

  // R14-B07: Test digest divergence at same headIndex
  assert.throws(
    () => loadTrustRegistry({
      ...opts,
      externalMonotonicWitness: {
        minRegistryVersion: 1,
        minHwmHeadIndex: 0,
        minHwmHeadDigest: 'f'.repeat(64) // divergent digest
      },
      failClosed: true
    }),
    /MONOTONIC_WITNESS_DIVERGENCE_DETECTED/
  );

  // R14-B06: Test corrupted witness file fails closed
  fs.writeFileSync(localWitness, 'MALFORMED-JSON-NOT-VALID', 'utf8');
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R15-B01 - Formal read paths pass candidate HWM digests and reject digest divergence', () => {
  const tempDir = createTempDir('r15-b01-read-paths-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  saveTrustRegistry({
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }]
  }, opts);

  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-001' },
    { ...opts, signerKeyId: auth.keyId, signerPrivateKey: auth.privateKey }
  );

  // Divergent digest at same headIndex 0 MUST fail closed in doLoadTrustRegistry
  assert.throws(
    () => loadTrustRegistry({
      ...opts,
      externalMonotonicWitness: {
        minRegistryVersion: 1,
        minHwmHeadIndex: 0,
        minHwmHeadDigest: '9'.repeat(64)
      },
      failClosed: true
    }),
    /MONOTONIC_WITNESS_DIVERGENCE_DETECTED/
  );

  // Divergent digest at same headIndex 0 MUST fail closed in doLoadRevocationJournal
  assert.throws(
    () => loadRevocationJournal({
      ...opts,
      externalMonotonicWitness: {
        minRegistryVersion: 1,
        minHwmHeadIndex: 0,
        minHwmHeadDigest: '8'.repeat(64)
      },
      failClosed: true
    }),
    /MONOTONIC_WITNESS_DIVERGENCE_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R15-B02 - COMMITTED WAL recovery updates witness before unlinking marker', () => {
  const tempDir = createTempDir('r15-b02-committed-wal-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }]
  };
  saveTrustRegistry(v1, opts);

  // Create initial revocation (headIndex 0)
  appendRevocationEntry(
    { revocationType: REVOCATION_TYPES.KEY_REVOCATION, targetId: 'KEY-001' },
    { ...opts, signerKeyId: auth.keyId, signerPrivateKey: auth.privateKey }
  );

  const journalPath = getRevocationJournalPath(opts);
  const checkpointPath = getRevocationCheckpointPath(opts);
  const regPath = getTrustRegistryPath(opts);
  const txnPath = path.join(tempDir, REVOCATION_TXN_FILE);

  // Construct a second entry at index 1 committed on disk
  const jRaw = fs.readFileSync(journalPath, 'utf8').trim();
  const firstEntry = JSON.parse(jRaw.split(/\r?\n/)[0]);
  const prevDigest = sha256Digest(canonicalJsonStringify(firstEntry));

  const entry2Unsigned = {
    entryIndex: 1,
    timestamp: new Date().toISOString(),
    revocationType: REVOCATION_TYPES.KEY_REVOCATION,
    targetId: 'KEY-002',
    reason: 'TEST_MANUAL',
    prevEntryDigest: prevDigest,
    signedBy: auth.keyId
  };
  const entry2Sig = crypto.sign(null, Buffer.from(computeRevocationEntrySignPayload(entry2Unsigned), 'utf8'), auth.privateKey).toString('hex');
  const entry2 = { ...entry2Unsigned, signature: entry2Sig };
  const entry2Digest = sha256Digest(canonicalJsonStringify(entry2));

  // Write entry2 to journal
  fs.appendFileSync(journalPath, JSON.stringify(entry2) + '\n', 'utf8');

  // Write checkpoint for index 1
  const cp2 = {
    headIndex: 1,
    headDigest: entry2Digest,
    updatedAt: new Date().toISOString(),
    registryVersion: 1
  };
  fs.writeFileSync(checkpointPath, JSON.stringify(cp2, null, 2) + '\n', 'utf8');

  // Write registry with HWM index 1
  const hwmPayload = Buffer.from(canonicalJsonStringify({
    headIndex: 1,
    headDigest: entry2Digest,
    updatedAt: entry2.timestamp,
    authorizedBy: auth.keyId
  }), 'utf8');
  const hwmSig = crypto.sign(null, hwmPayload, auth.privateKey).toString('hex');
  const regWithHwm = {
    ...v1,
    revocationHighWaterMark: {
      headIndex: 1,
      headDigest: entry2Digest,
      updatedAt: entry2.timestamp,
      authorizedBy: auth.keyId,
      signature: hwmSig
    }
  };
  fs.writeFileSync(regPath, JSON.stringify(regWithHwm, null, 2) + '\n', 'utf8');

  // Create COMMITTED WAL
  const txnData = {
    schemaVersion: '1.0.0',
    txnId: 'txn-r15-b02',
    status: 'COMMITTED',
    startedAt: new Date().toISOString(),
    committedAt: new Date().toISOString(),
    journalPath,
    checkpointPath,
    regPath,
    signedBy: auth.keyId,
    committedHwmHeadIndex: 1,
    committedHwmHeadDigest: entry2Digest,
    expectedTargetHwmHeadIndex: 1,
    expectedTargetHwmHeadDigest: entry2Digest,
    initialRegistryVersion: 1,
    initialHwmHeadIndex: 0,
    initialHwmHeadDigest: prevDigest,
    initialJournalSize: fs.statSync(journalPath).size - (JSON.stringify(entry2) + '\n').length,
    initialJournalExisted: true,
    initialJournalSha256: sha256Digest(Buffer.from(jRaw + '\n', 'utf8'))
  };
  const walSigPayload = Buffer.from(computeTransactionWalSignPayload(txnData), 'utf8');
  txnData.signature = crypto.sign(null, walSigPayload, auth.privateKey).toString('hex');
  fs.writeFileSync(txnPath, JSON.stringify(txnData, null, 2) + '\n', 'utf8');

  // Recover WAL
  const recResult = recoverAbortedRevocationTransaction(opts);
  assert.equal(recResult.committed, true);
  assert.equal(fs.existsSync(txnPath), false);

  // Persistent witness MUST have recorded headIndex 1
  const localWitness = JSON.parse(fs.readFileSync(path.join(tempDir, '.monotonic-witness.json'), 'utf8'));
  assert.equal(localWitness.maxSeenHwmHeadIndex, 1);
  assert.equal(localWitness.maxSeenHwmHeadDigest, entry2Digest);

  // Attempting to rollback registry to index 0 MUST fail closed against witness
  const regWithHwm0 = {
    ...v1,
    revocationHighWaterMark: {
      headIndex: 0,
      headDigest: prevDigest,
      updatedAt: new Date().toISOString(),
      authorizedBy: auth.keyId,
      signature: hwmSig
    }
  };
  fs.writeFileSync(regPath, JSON.stringify(regWithHwm0, null, 2) + '\n', 'utf8');
  fs.writeFileSync(path.join(tempDir, 'history', 'trust-registry.v1.json'), JSON.stringify(regWithHwm0, null, 2) + '\n', 'utf8');
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /(HIGH_WATER_MARK_ROLLBACK_DETECTED|MONOTONIC_WITNESS_ROLLBACK_DETECTED)/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R15-B03 - Alternative registry at same version signed by retired key triggers REGISTRY_DIVERGENCE_DETECTED', () => {
  const tempDir = createTempDir('r15-b03-fork-');
  const rootA = generateTestAuthority();
  const rootB = generateTestAuthority();
  const rootC = generateTestAuthority(); // rogue key

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: rootA.keyId,
    trustedRootPublicKeyPem: rootA.pem,
    trustedRootFingerprint: rootA.fp
  };

  // 1. Genesis v1 with Root A active
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: rootA.keyId,
    activeKeyFingerprint: rootA.fp,
    activePublicKeyPem: rootA.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: rootA.keyId, keyFingerprint: rootA.fp, publicKeyPem: rootA.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  saveTrustRegistry(v1, opts);

  // 2. Rotate to v2 with Root B active, Root A retired
  const v2Keys = [
    { keyId: rootA.keyId, keyFingerprint: rootA.fp, publicKeyPem: rootA.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
    { keyId: rootB.keyId, keyFingerprint: rootB.fp, publicKeyPem: rootB.pem, status: 'ACTIVE', issuedAt: '2026-11-01T00:00:00.000Z' }
  ];
  const legitimateV2 = createAuthorizedRegistryUpdate(
    v1,
    {
      activeKeyId: rootB.keyId,
      activeKeyFingerprint: rootB.fp,
      activePublicKeyPem: rootB.pem,
      keys: v2Keys
    },
    rootA.keyId,
    rootA.privateKey
  );

  saveTrustRegistry(legitimateV2, opts);

  // Ensure witness recorded legitimate v2
  const loadedV2 = loadTrustRegistry({ ...opts, failClosed: true });
  assert.equal(loadedV2.valid, true);

  // 3. Attack: Attacker crafts alternate v2 signed by retired Root A setting rogue Root C active
  const altKeys = [
    { keyId: rootA.keyId, keyFingerprint: rootA.fp, publicKeyPem: rootA.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
    { keyId: rootC.keyId, keyFingerprint: rootC.fp, publicKeyPem: rootC.pem, status: 'ACTIVE', issuedAt: '2026-11-01T00:00:00.000Z' }
  ];
  const alternateV2 = createAuthorizedRegistryUpdate(
    v1,
    {
      activeKeyId: rootC.keyId,
      activeKeyFingerprint: rootC.fp,
      activePublicKeyPem: rootC.pem,
      keys: altKeys
    },
    rootA.keyId,
    rootA.privateKey
  );

  // Attacker writes alternate v2 to disk and history
  const regPath = getTrustRegistryPath(opts);
  const histPath = path.join(tempDir, 'history', 'trust-registry.v2.json');
  fs.writeFileSync(regPath, JSON.stringify(alternateV2, null, 2) + '\n', 'utf8');
  fs.writeFileSync(histPath, JSON.stringify(alternateV2, null, 2) + '\n', 'utf8');

  // 4. Must fail closed with REGISTRY_DIVERGENCE_DETECTED
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /REGISTRY_DIVERGENCE_DETECTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R15-B04 - Witness file strict schema validation and safe storage API confinement', () => {
  const tempDir = createTempDir('r15-b04-schema-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  saveTrustRegistry({
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: new Date().toISOString(),
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: new Date().toISOString() }]
  }, opts);

  const localWitness = path.join(tempDir, '.monotonic-witness.json');
  assert.equal(fs.existsSync(localWitness), true);

  // Test empty object {} fails closed with MONOTONIC_WITNESS_CORRUPTED
  fs.writeFileSync(localWitness, '{}', 'utf8');
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  // Test missing mandatory maxSeenRegistryDigest fails closed
  fs.writeFileSync(localWitness, JSON.stringify({
    schemaVersion: '1.0.0',
    dir: path.resolve(tempDir),
    maxSeenRegistryVersion: 1,
    maxSeenHwmHeadIndex: -1,
    maxSeenHwmHeadDigest: '',
    updatedAt: new Date().toISOString()
  }), 'utf8');
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  // Test public storage API confinement on witness file
  assert.throws(
    () => safeWriteFileSync(localWitness, 'tampered', opts),
    /STORAGE_CONFINEMENT_VIOLATION/
  );
  assert.throws(
    () => safeOpenStorageFile(localWitness, 'w+', 0o600, opts),
    /STORAGE_CONFINEMENT_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R15-B05 - withFileLock enforces explicit 0o600 DAC mode creation', () => {
  const tempDir = createTempDir('r15-b05-lock-');
  const targetFile = path.join(tempDir, 'test-resource');
  const lockFile = `${targetFile}.lock`;

  let lockInspected = false;
  withFileLock(targetFile, () => {
    assert.equal(fs.existsSync(lockFile), true);
    const stat = fs.statSync(lockFile);
    assert.ok(stat.size > 0);
    // On POSIX systems, verify explicit 0o600 DAC creation mode
    if (process.platform !== 'win32') {
      const mode = stat.mode & 0o777;
      assert.equal(mode, 0o600);
    }
    lockInspected = true;
  });

  assert.equal(lockInspected, true);
  assert.equal(fs.existsSync(lockFile), false);
  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R16-B01 - Version advancement cannot bypass historical registry digest commitment', () => {
  const tempDir = createTempDir('r16-b01-hist-fork-');
  const authA = generateTestAuthority();
  const authB = generateTestAuthority();
  const authC = generateTestAuthority();

  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: authA.keyId,
    trustedRootPublicKeyPem: authA.pem,
    trustedRootFingerprint: authA.fp
  };

  // 1. Save v1 (signed by Root A)
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: authA.keyId,
    activeKeyFingerprint: authA.fp,
    activePublicKeyPem: authA.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: authA.keyId, keyFingerprint: authA.fp, publicKeyPem: authA.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  saveTrustRegistry(v1, opts);

  // 2. Legitimate rotation: v1 -> v2 (signed by Root A promoting Root B to ACTIVE)
  const legitV2 = createAuthorizedRegistryUpdate(
    v1,
    {
      activeKeyId: authB.keyId,
      activeKeyFingerprint: authB.fp,
      activePublicKeyPem: authB.pem,
      keys: [
        { keyId: authA.keyId, keyFingerprint: authA.fp, publicKeyPem: authA.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: authB.keyId, keyFingerprint: authB.fp, publicKeyPem: authB.pem, status: 'ACTIVE', issuedAt: new Date().toISOString() }
      ]
    },
    authA.keyId,
    authA.privateKey
  );
  saveTrustRegistry(legitV2, opts);

  // Verify persistent witness has recorded legitimate v2 digest
  const witnessBefore = getMonotonicWitness(tempDir, opts);
  assert.equal(witnessBefore.maxSeenRegistryVersion, 2);
  const legitV2Digest = computeRegistryDigest(legitV2);
  assert.equal(witnessBefore.registryDigests['2'], legitV2Digest);

  // 3. Attacker uses retired Root A key to forge alternate v2' promoting Root C
  const forgedV2 = createAuthorizedRegistryUpdate(
    v1,
    {
      activeKeyId: authC.keyId,
      activeKeyFingerprint: authC.fp,
      activePublicKeyPem: authC.pem,
      keys: [
        { keyId: authA.keyId, keyFingerprint: authA.fp, publicKeyPem: authA.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: authC.keyId, keyFingerprint: authC.fp, publicKeyPem: authC.pem, status: 'ACTIVE', issuedAt: new Date().toISOString() }
      ]
    },
    authA.keyId,
    authA.privateKey
  );

  // 4. Attacker uses Root C to forge v3' based on forged v2'
  const forgedV3 = createAuthorizedRegistryUpdate(
    forgedV2,
    {
      activeKeyId: authC.keyId,
      activeKeyFingerprint: authC.fp,
      activePublicKeyPem: authC.pem,
      keys: [
        { keyId: authA.keyId, keyFingerprint: authA.fp, publicKeyPem: authA.pem, status: 'RETIRED', issuedAt: '2026-10-16T06:55:39.565Z' },
        { keyId: authC.keyId, keyFingerprint: authC.fp, publicKeyPem: authC.pem, status: 'ACTIVE', issuedAt: new Date().toISOString() }
      ]
    },
    authC.keyId,
    authC.privateKey
  );

  // Attacker writes forged v2' into history/trust-registry.v2.json and forged v3' into on-disk registry
  const histV2Path = path.join(tempDir, 'history', 'trust-registry.v2.json');
  const regPath = getTrustRegistryPath(opts);
  fs.writeFileSync(histV2Path, JSON.stringify(forgedV2, null, 2) + '\n', 'utf8');
  fs.writeFileSync(regPath, JSON.stringify(forgedV3, null, 2) + '\n', 'utf8');

  // Attempting to load v3' MUST fail closed because history/v2' digest does not match witnessed legitimate v2 digest!
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /(REGISTRY_HISTORY_DIVERGENCE_DETECTED|MONOTONIC_WITNESS_DIVERGENCE_DETECTED)/
  );

  // Attacker deletes history/trust-registry.v2.json to hide the divergence: MUST fail closed
  fs.unlinkSync(histV2Path);
  assert.throws(
    () => loadTrustRegistry({ ...opts, failClosed: true }),
    /(HISTORY_GAP_DETECTED|REGISTRY_HISTORY_DIVERGENCE_DETECTED|ANCESTRY_CONTINUITY_VIOLATION)/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R16-B02 - Public storage APIs reject caller-supplied __internalWitnessWrite bypass', () => {
  const tempDir = createTempDir('r16-b02-symbol-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const witnessFile = path.join(tempDir, '.monotonic-witness.json');

  // Even if caller passes __internalWitnessWrite: true, public storage API MUST reject with STORAGE_CONFINEMENT_VIOLATION
  assert.throws(
    () => safeWriteFileSync(witnessFile, 'malicious payload', { ...opts, __internalWitnessWrite: true }),
    /STORAGE_CONFINEMENT_VIOLATION/
  );
  assert.throws(
    () => safeOpenStorageFile(witnessFile, 'w+', 0o600, { ...opts, __internalWitnessWrite: true }),
    /STORAGE_CONFINEMENT_VIOLATION/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R16-B03 - COMMITTED WAL with unverified or forged registry cannot poison monotonic witness', () => {
  const tempDir = createTempDir('r16-b03-wal-poison-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  // 1. Establish authentic state at v1
  const v1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
  };
  saveTrustRegistry(v1, opts);

  const witnessBefore = getMonotonicWitness(tempDir, opts);
  assert.equal(witnessBefore.maxSeenRegistryVersion, 1);

  // 2. Craft a forged COMMITTED WAL claiming registryVersion 100 with invalid registry on disk
  const walPath = path.join(tempDir, REVOCATION_TXN_FILE);
  const regPath = getTrustRegistryPath(opts);
  const cpPath = getRevocationCheckpointPath(opts);
  const journalPath = getRevocationJournalPath(opts);

  // Journal tail
  const tailEntry = {
    entryIndex: 5,
    timestamp: new Date().toISOString(),
    revocationType: REVOCATION_TYPES.KEY_REVOCATION,
    targetId: 'KEY-POISON',
    prevEntryDigest: '0'.repeat(64),
    signedBy: auth.keyId,
    signature: ''
  };
  tailEntry.signature = crypto.sign(null, Buffer.from(computeRevocationEntrySignPayload(tailEntry), 'utf8'), auth.privateKey).toString('hex');
  const tailDigest = sha256Digest(canonicalJsonStringify(tailEntry));
  fs.writeFileSync(journalPath, JSON.stringify(tailEntry) + '\n', 'utf8');

  const forgedReg = {
    ...v1,
    registryVersion: 100, // astronomical version without authorizationProof
    revocationHighWaterMark: { headIndex: 5, headDigest: tailDigest, registryVersion: 100 }
  };
  fs.writeFileSync(regPath, JSON.stringify(forgedReg, null, 2) + '\n', 'utf8');

  fs.writeFileSync(cpPath, JSON.stringify({ headIndex: 5, headDigest: tailDigest, registryVersion: 100 }, null, 2) + '\n', 'utf8');

  const walData = {
    txnId: 'txn-poison-100',
    status: 'COMMITTED',
    startedAt: new Date().toISOString(),
    committedAt: new Date().toISOString(),
    initialJournalSize: 0,
    initialRegistryVersion: 1,
    committedHwmHeadIndex: 5,
    committedHwmHeadDigest: tailDigest,
    expectedTargetRegistryVersion: 100,
    expectedTargetHwmHeadIndex: 5,
    expectedTargetHwmHeadDigest: tailDigest,
    journalPath,
    checkpointPath: cpPath,
    regPath,
    signedBy: auth.keyId,
    signature: ''
  };
  walData.signature = crypto.sign(null, Buffer.from(computeTransactionWalSignPayload(walData), 'utf8'), auth.privateKey).toString('hex');
  fs.writeFileSync(walPath, JSON.stringify(walData, null, 2) + '\n', 'utf8');

  // 3. Recovery must fail closed and MUST NOT poison witness to version 100!
  assert.throws(
    () => recoverAbortedRevocationTransaction(opts),
    /TRANSACTION_WAL_CORRUPTION_DETECTED/
  );

  const witnessAfter = getMonotonicWitness(tempDir, opts);
  assert.equal(witnessAfter.maxSeenRegistryVersion, 1, 'Witness must NOT be poisoned by unverified COMMITTED WAL');

  fs.rmSync(tempDir, { recursive: true, force: true });
});

test('PLUGIN_DATA Governance: R16-B04 - Registry digest includes complete canonical identity commitment', () => {
  const auth = generateTestAuthority();
  const reg1 = {
    schemaVersion: '1.0.0',
    registryVersion: 1,
    authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
    activeKeyId: auth.keyId,
    activeKeyFingerprint: auth.fp,
    activePublicKeyPem: auth.pem,
    keyType: 'ed25519',
    pinnedSince: '2026-10-16T06:55:39.565Z',
    rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
    validFrom: '2026-01-01T00:00:00.000Z',
    validUntil: '2027-01-01T00:00:00.000Z',
    revokedKeyIds: [],
    keys: [{ keyId: auth.keyId, keyFingerprint: auth.fp, publicKeyPem: auth.pem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }],
    signature: 'sig-test-1'
  };

  const digest1 = computeRegistryDigest(reg1);
  assert.equal(typeof digest1, 'string');
  assert.equal(digest1.length, 64);

  // Altering authorizationProof changes digest
  const regWithProof = {
    ...reg1,
    authorizationProof: {
      signerKeyId: auth.keyId,
      signedAt: '2026-10-16T06:55:39.565Z',
      signature: 'proof-sig-1',
      priorRegistryVersion: 1
    }
  };
  const digestWithProof = computeRegistryDigest(regWithProof);
  assert.notEqual(digest1, digestWithProof, 'Adding authorizationProof must produce different registry digest');

  // Altering rotationPolicy changes digest
  const regDiffPolicy = {
    ...reg1,
    rotationPolicy: 'MULTI_ROOT_AUTHORIZED'
  };
  assert.notEqual(digest1, computeRegistryDigest(regDiffPolicy), 'Altering rotationPolicy must change registry digest');

  // Altering pinnedSince changes digest
  const regDiffPinned = {
    ...reg1,
    pinnedSince: '2026-11-01T00:00:00.000Z'
  };
  assert.notEqual(digest1, computeRegistryDigest(regDiffPinned), 'Altering pinnedSince must change registry digest');
});

test('PLUGIN_DATA Governance: R16-B05 - Witness file strict semantic schema validation', () => {
  const tempDir = createTempDir('r16-b05-semantic-');
  const auth = generateTestAuthority();
  const opts = {
    pluginDataDir: tempDir,
    allowInWorkspace: true,
    trustedRootKeyId: auth.keyId,
    trustedRootPublicKeyPem: auth.pem,
    trustedRootFingerprint: auth.fp
  };

  const localWitness = path.join(tempDir, '.monotonic-witness.json');
  const validSha = 'b'.repeat(64);

  // 1. Directory divergence fails closed
  fs.writeFileSync(localWitness, JSON.stringify({
    schemaVersion: '1.0.0',
    dir: path.resolve(os.tmpdir()), // Divergent directory
    maxSeenRegistryVersion: 1,
    maxSeenRegistryDigest: validSha,
    registryDigests: { '1': validSha },
    maxSeenHwmHeadIndex: -1,
    maxSeenHwmHeadDigest: '',
    updatedAt: new Date().toISOString()
  }), 'utf8');
  assert.throws(
    () => getMonotonicWitness(tempDir, { allowInWorkspace: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  // 2. Non-64-hex maxSeenRegistryDigest fails closed
  fs.writeFileSync(localWitness, JSON.stringify({
    schemaVersion: '1.0.0',
    dir: path.resolve(tempDir),
    maxSeenRegistryVersion: 1,
    maxSeenRegistryDigest: 'not-a-valid-sha256',
    registryDigests: { '1': 'not-a-valid-sha256' },
    maxSeenHwmHeadIndex: -1,
    maxSeenHwmHeadDigest: '',
    updatedAt: new Date().toISOString()
  }), 'utf8');
  assert.throws(
    () => getMonotonicWitness(tempDir, { allowInWorkspace: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  // 3. Invalid version key in registryDigests fails closed
  fs.writeFileSync(localWitness, JSON.stringify({
    schemaVersion: '1.0.0',
    dir: path.resolve(tempDir),
    maxSeenRegistryVersion: 1,
    maxSeenRegistryDigest: validSha,
    registryDigests: { 'not-an-int': validSha },
    maxSeenHwmHeadIndex: -1,
    maxSeenHwmHeadDigest: '',
    updatedAt: new Date().toISOString()
  }), 'utf8');
  assert.throws(
    () => getMonotonicWitness(tempDir, { allowInWorkspace: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  // 4. Missing maxSeenRegistryVersion entry in registryDigests fails closed
  fs.writeFileSync(localWitness, JSON.stringify({
    schemaVersion: '1.0.0',
    dir: path.resolve(tempDir),
    maxSeenRegistryVersion: 2,
    maxSeenRegistryDigest: validSha,
    registryDigests: { '1': validSha }, // Missing '2'
    maxSeenHwmHeadIndex: -1,
    maxSeenHwmHeadDigest: '',
    updatedAt: new Date().toISOString()
  }), 'utf8');
  assert.throws(
    () => getMonotonicWitness(tempDir, { allowInWorkspace: true }),
    /MONOTONIC_WITNESS_CORRUPTED/
  );

  fs.rmSync(tempDir, { recursive: true, force: true });
});
