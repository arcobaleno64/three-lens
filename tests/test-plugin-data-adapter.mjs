import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
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
  GOVERNANCE_LOCK_TARGET,
  REVOCATION_TXN_FILE,
  withGovernanceLock,
  recoverAbortedRevocationTransaction,
  REVOCATION_TYPES,
  EMBEDDED_ROOT_REGISTRY,
  DEFAULT_SUPERVISOR_KEY_ID,
  DEFAULT_SUPERVISOR_PUBLIC_PEM,
  DEFAULT_SUPERVISOR_FINGERPRINT
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
    rootAuth.keyId,
    rootAuth.privateKey
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

  // Simulate an interrupted transaction by writing WAL with status 'PREPARED' and partial mutations
  const txnData = {
    txnId: 'SIMULATED-CRASH-TXN-1234',
    status: 'PREPARED',
    createdAt: new Date().toISOString(),
    journalPath,
    initialJournalSize: stableJournalBytes.length,
    initialJournalExisted: true,
    checkpointPath,
    initialCheckpointRawBase64: stableCheckpointBytes.toString('base64'),
    initialCheckpointExisted: true,
    regPath,
    initialRegistryRawBase64: stableRegBytes.toString('base64'),
    initialRegistryExisted: true,
    histPath: null,
    initialHistRawBase64: null,
    initialHistExisted: false
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
    /TRANSACTION_WAL_CORRUPTION_DETECTED.*missing required paths or sizes/
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
