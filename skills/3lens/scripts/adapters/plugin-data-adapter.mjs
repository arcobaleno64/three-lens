#!/usr/bin/env node
/**
 * scripts/adapters/plugin-data-adapter.mjs
 * Milestone 5.4 Phase 2 (RFC 0005 Workstream 3 — R01 Hardening):
 * Dual-Anchor Persistent Storage and Root-Authorized Revocation Governance Adapter.
 *
 * Requirements & Invariants:
 * 1. Dual-Anchor Architecture with Root Authorization (F02 Closure):
 *    - Primary Anchor (Isolated State): $PLUGIN_DATA directory.
 *    - Secondary Anchor (Root of Trust): EMBEDDED_ROOT_REGISTRY with Ed25519 root key.
 *    - Mandatory Root Authorization Chain: Registry version updates (> 1) must carry a valid
 *      cryptographic authorizationProof signed by an authorized supervisor key.
 *    - Strict Monotonicity: Versions cannot regress; revokedKeyIds cannot be removed without root authority.
 * 2. Zero Workspace Pollution (F03 Closure):
 *    - Uses fs.realpathSync() to resolve symlinks and Windows junctions.
 *    - Strictly checks that resolved PLUGIN_DATA does not reside inside options.repoRoot, process.cwd(),
 *      or any active workspace directory.
 * 3. Fail-Closed Tamper-Evident Revocation Journal (F01 Closure):
 *    - Append-only hash-chained journal (.irv-revocation-journal.jsonl).
 *    - Mandatory Ed25519 signatures verified on read against trusted keys.
 *    - Root-anchored checkpoint (supervisor-revocation-checkpoint.json) to detect deletion,
 *      truncation, or rollback attacks.
 * 4. Cross-Process Mutual Exclusion (F04 Closure):
 *    - Atomic file locking (withFileLock) for concurrent registry writes and journal appends.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';

export const ADAPTER_NAME = 'PLUGIN_DATA_DUAL_ANCHOR_ADAPTER';
export const ADAPTER_VERSION = '1.1.0';

export const REVOCATION_TYPES = Object.freeze({
  KEY_REVOCATION: 'KEY_REVOCATION',
  NONCE_REVOCATION: 'NONCE_REVOCATION',
  BALLOT_DISPUTE: 'BALLOT_DISPUTE',
  EMERGENCY_FREEZE: 'EMERGENCY_FREEZE'
});

export const DEFAULT_SUPERVISOR_KEY_ID = 'IRV-SUPERVISOR-ROOT-ED25519-v1-a2a222ec7ca28466';
export const DEFAULT_SUPERVISOR_PUBLIC_PEM =
  '-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAugD3MpoZoJb47Y2U8IRqzlyhjulIdNp+vKgfkn5tIzU=\n-----END PUBLIC KEY-----\n';
export const DEFAULT_SUPERVISOR_FINGERPRINT =
  'a2a222ec7ca284666f70554925dc8596b96e163cbc881cafdec9e0f7dabbb678';

export const EMBEDDED_ROOT_REGISTRY = Object.freeze({
  schemaVersion: '1.0.0',
  registryVersion: 1,
  authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
  activeKeyId: DEFAULT_SUPERVISOR_KEY_ID,
  activeKeyFingerprint: DEFAULT_SUPERVISOR_FINGERPRINT,
  activePublicKeyPem: DEFAULT_SUPERVISOR_PUBLIC_PEM,
  keyType: 'ed25519',
  pinnedSince: '2026-10-16T06:55:39.565Z',
  rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
  revokedKeyIds: [],
  keys: [
    {
      keyId: DEFAULT_SUPERVISOR_KEY_ID,
      keyFingerprint: DEFAULT_SUPERVISOR_FINGERPRINT,
      publicKeyPem: DEFAULT_SUPERVISOR_PUBLIC_PEM,
      status: 'ACTIVE_PINNED_ROOT',
      issuedAt: '2026-10-16T06:55:39.565Z'
    }
  ]
});

/**
 * Normalizes a path string to POSIX forward slashes while preserving drive letters.
 */
export function normalizePath(p) {
  if (typeof p !== 'string' || !p.trim()) return '';
  return p.replace(/\\/g, '/');
}

/**
 * Resolves real physical path resolving symlinks and Windows junctions.
 * Resolves M54-P2-F03: Traverses up to the deepest existing ancestor to neutralize
 * intermediate uncreated symlink directories.
 */
export function toRealNormalizedPath(p) {
  if (typeof p !== 'string' || !p.trim()) return '';
  const abs = path.resolve(p);
  let current = abs;
  const uncreatedSuffix = [];
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) break;
    uncreatedSuffix.unshift(path.basename(current));
    current = parent;
  }
  try {
    if (fs.existsSync(current)) {
      const realAncestor = fs.realpathSync(current);
      return normalizePath(uncreatedSuffix.length > 0 ? path.join(realAncestor, ...uncreatedSuffix) : realAncestor);
    }
  } catch {}
  return normalizePath(abs);
}

/**
 * Asserts that a target storage file is safe from symlink redirection and hard link aliasing.
 * Resolves R04-B03:
 * 1. Dangling symlink detection: calls lstatSync without guarding on existsSync().
 * 2. Hard link detection: asserts stat.nlink === 1, rejecting multi-link inode sharing.
 * 3. Zero workspace pollution: checks realpath against workspace roots.
 *
 * @param {string} targetPath - Path to target file
 * @param {object} [options={}] - Options containing repoRoot or workspacePaths
 */
export function assertSafeStorageTarget(targetPath, options = {}) {
  const forbiddenRoots = [
    options.repoRoot ? toRealNormalizedPath(options.repoRoot) : null,
    toRealNormalizedPath(process.cwd()),
    process.env.INIT_CWD ? toRealNormalizedPath(process.env.INIT_CWD) : null,
    ...(Array.isArray(options.workspacePaths) ? options.workspacePaths.map(p => toRealNormalizedPath(p)) : [])
  ].filter(Boolean);

  let stat = null;
  try {
    stat = fs.lstatSync(targetPath);
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }

  if (stat) {
    if (stat.isSymbolicLink()) {
      throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Target file (${targetPath}) must not be a symbolic link`);
    }
    if (stat.nlink > 1 && options.allowInWorkspace !== true) {
      throw new Error(
        `[HARDLINK_POLLUTION_VIOLATION] Target file (${targetPath}) has multiple hard links (nlink: ${stat.nlink}), potential workspace inode aliasing`
      );
    }
    if (options.allowInWorkspace !== true) {
      const realFile = toRealNormalizedPath(targetPath).toLowerCase();
      for (const root of forbiddenRoots) {
        const rLower = root.toLowerCase();
        if (realFile === rLower || realFile.startsWith(rLower + '/')) {
          throw new Error(`[ZERO_WORKSPACE_POLLUTION_VIOLATION] Target file realpath (${realFile}) resides inside workspace (${root})`);
        }
      }
    }
  } else {
    // Target file does not exist yet: verify parent directory
    const parentDir = path.dirname(targetPath);
    let parentStat = null;
    try {
      parentStat = fs.lstatSync(parentDir);
    } catch (e) {
      if (e.code !== 'ENOENT') throw e;
    }
    if (parentStat) {
      if (parentStat.isSymbolicLink()) {
        throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Parent directory of target file (${parentDir}) must not be a symbolic link`);
      }
      if (options.allowInWorkspace !== true) {
        const realParent = toRealNormalizedPath(parentDir).toLowerCase();
        for (const root of forbiddenRoots) {
          const rLower = root.toLowerCase();
          if (realParent === rLower || realParent.startsWith(rLower + '/')) {
            throw new Error(`[ZERO_WORKSPACE_POLLUTION_VIOLATION] Target parent directory realpath (${realParent}) resides inside workspace (${root})`);
          }
        }
      }
    }
  }
}

/**
 * Safely opens a storage target file with anti-TOCTOU descriptor inspection.
 * Resolves R05-B04:
 * 1. Enforces O_NOFOLLOW flag on platforms where supported.
 * 2. Inspects descriptor via fstatSync immediately upon open.
 * 3. Compares lstat of path with opened descriptor to detect symlink swaps and inode aliasing.
 * 4. Verifies zero workspace pollution via resolved descriptor / path realpath.
 *
 * @param {string} targetPath - File path to open
 * @param {string|number} flags - fs open flags (e.g. 'a+', 'r', 'w+')
 * @param {number} [mode=0o600] - File creation mode
 * @param {object} [options={}] - Options
 * @returns {number} Open file descriptor (caller must closeSync)
 */
export function safeOpenStorageFile(targetPath, flags, mode = 0o600, options = {}) {
  assertSafeStorageTarget(targetPath, options);

  let numericFlags = 0;
  const noFollow = fs.constants.O_NOFOLLOW || 0;
  if (typeof flags === 'number') {
    numericFlags = flags | noFollow;
  } else {
    if (flags === 'a+' || flags === 'a') {
      numericFlags = (flags === 'a+' ? fs.constants.O_RDWR : fs.constants.O_WRONLY) |
        fs.constants.O_CREAT | fs.constants.O_APPEND | noFollow;
    } else if (flags === 'w+' || flags === 'w') {
      numericFlags = (flags === 'w+' ? fs.constants.O_RDWR : fs.constants.O_WRONLY) |
        fs.constants.O_CREAT | fs.constants.O_TRUNC | noFollow;
    } else if (flags === 'r+' || flags === 'r') {
      numericFlags = (flags === 'r+' ? fs.constants.O_RDWR : fs.constants.O_RDONLY) | noFollow;
    }
  }

  let fd;
  try {
    fd = numericFlags ? fs.openSync(targetPath, numericFlags, mode) : fs.openSync(targetPath, flags, mode);
  } catch (openErr) {
    if (openErr.code === 'ELOOP' || openErr.code === 'SYMLINK') {
      throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Target file (${targetPath}) is a symbolic link (blocked by O_NOFOLLOW)`);
    }
    throw openErr;
  }

  try {
    const lstat = fs.lstatSync(targetPath);
    if (lstat.isSymbolicLink()) {
      throw new Error(`[SYMLINK_POLLUTION_VIOLATION] Target file (${targetPath}) must not be a symbolic link`);
    }
    const fdStat = fs.fstatSync(fd);
    if (fdStat.nlink > 1 && options.allowInWorkspace !== true) {
      throw new Error(`[HARDLINK_POLLUTION_VIOLATION] Target file (${targetPath}) has multiple hard links (nlink: ${fdStat.nlink})`);
    }
    if (typeof lstat.ino === 'number' && typeof fdStat.ino === 'number' && lstat.ino !== 0 && fdStat.ino !== 0) {
      if (lstat.dev !== fdStat.dev || lstat.ino !== fdStat.ino) {
        throw new Error(`[TOCTOU_POLLUTION_VIOLATION] Inode mismatch between path and opened descriptor for ${targetPath}`);
      }
    }
    if (options.allowInWorkspace !== true) {
      const forbiddenRoots = [
        options.repoRoot ? toRealNormalizedPath(options.repoRoot) : null,
        toRealNormalizedPath(process.cwd()),
        process.env.INIT_CWD ? toRealNormalizedPath(process.env.INIT_CWD) : null,
        ...(Array.isArray(options.workspacePaths) ? options.workspacePaths.map(p => toRealNormalizedPath(p)) : [])
      ].filter(Boolean);
      const realFile = toRealNormalizedPath(targetPath).toLowerCase();
      for (const root of forbiddenRoots) {
        const rLower = root.toLowerCase();
        if (realFile === rLower || realFile.startsWith(rLower + '/')) {
          throw new Error(`[ZERO_WORKSPACE_POLLUTION_VIOLATION] Target file realpath (${realFile}) resides inside workspace (${root})`);
        }
      }
    }
    return fd;
  } catch (inspectErr) {
    try { fs.closeSync(fd); } catch (_) {}
    throw inspectErr;
  }
}

/**
 * Safely writes content to targetPath using safeOpenStorageFile on temp file and atomic rename.
 * Resolves R05-B04: Eliminates TOCTOU windows on storage files.
 */
export function safeWriteFileSync(targetPath, content, options = {}) {
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  assertSafeStorageTarget(targetPath, options);
  const tmpPath = path.join(dir, `.tmp.${path.basename(targetPath)}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
  const fd = safeOpenStorageFile(tmpPath, 'w', 0o600, options);
  try {
    fs.writeSync(fd, content, null, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  assertSafeStorageTarget(tmpPath, options);
  fs.renameSync(tmpPath, targetPath);
}

/**
 * Checks whether a process PID is currently alive on the host.
 * Resolves M54-P2-F04.
 */
export function isPidAlive(pid) {
  if (!pid || typeof pid !== 'number' || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    return err.code === 'EPERM'; // EPERM means process exists but belongs to another user
  }
}

/**
 * Computes deterministic SHA-256 hex digest of string or buffer.
 */
export function sha256Digest(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Deterministic JSON serialization for canonical hashing.
 */
export function canonicalJsonStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (obj instanceof Date) {
    return JSON.stringify(obj.toISOString());
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => item === undefined ? 'null' : canonicalJsonStringify(item)).join(',') + ']';
  }
  const keys = Object.keys(obj).filter(k => obj[k] !== undefined).sort();
  const pairs = keys.map(k => JSON.stringify(k) + ':' + canonicalJsonStringify(obj[k]));
  return '{' + pairs.join(',') + '}';
}

/**
 * Cross-process file locking primitive using exclusive file creation.
 * Resolves M54-P2-F04: Lock info contains PID and unique lockId; stale lock
 * reclamation strictly verifies PID liveness; lock release verifies lockId ownership.
 *
 * @param {string} targetFile - Path to file needing mutual exclusion
 * @param {Function} fn - Operation to execute while lock is held
 * @param {object} [options={}] - Lock options
 * @returns {any} Result of fn()
 */
export function withFileLock(targetFile, fn, options = {}) {
  const lockFile = `${targetFile}.lock`;
  const timeoutMs = options.lockTimeoutMs || 5000;
  const pollIntervalMs = 15;
  const staleTimeoutMs = options.staleLockTimeoutMs || 30000;
  const start = Date.now();
  const lockId = crypto.randomBytes(8).toString('hex');

  let lockFd = null;
  while (Date.now() - start < timeoutMs) {
    try {
      lockFd = fs.openSync(lockFile, 'wx');
      const info = JSON.stringify({ pid: process.pid, timestamp: Date.now(), lockId });
      fs.writeFileSync(lockFd, info, 'utf8');
      break;
    } catch (err) {
      if (err.code === 'EEXIST') {
        try {
          const stats = fs.statSync(lockFile);
          if (Date.now() - stats.mtimeMs > staleTimeoutMs) {
            // R08-B07 / R09-B03: Authenticated two-phase stale lock reclamation
            const reclaimLockFile = `${lockFile}.reclaim`;
            const reclaimLockId = crypto.randomBytes(8).toString('hex');
            let reclaimFd = null;
            try {
              reclaimFd = fs.openSync(reclaimLockFile, 'wx');
              fs.writeFileSync(reclaimFd, JSON.stringify({ pid: process.pid, timestamp: Date.now(), reclaimLockId }), 'utf8');
            } catch (recErr) {
              if (recErr.code === 'EEXIST') {
                try {
                  const recStat = fs.statSync(reclaimLockFile);
                  if (Date.now() - recStat.mtimeMs > 3000) {
                    try {
                      const recRaw = fs.readFileSync(reclaimLockFile, 'utf8');
                      const recParsed = JSON.parse(recRaw);
                      // Only reclaim if holder PID is definitively dead
                      if (recParsed.pid && !isPidAlive(recParsed.pid)) {
                        const recheck = fs.readFileSync(reclaimLockFile, 'utf8');
                        if (recheck === recRaw) {
                          fs.unlinkSync(reclaimLockFile);
                        }
                      }
                    } catch {}
                  }
                } catch {}
              }
            }

            if (reclaimFd !== null) {
              try {
                // Re-read lockFile under exclusive reclamation lock
                if (fs.existsSync(lockFile)) {
                  const recheckStats = fs.statSync(lockFile);
                  if (Date.now() - recheckStats.mtimeMs > staleTimeoutMs) {
                    let canRecover = true;
                    try {
                      const content = fs.readFileSync(lockFile, 'utf8');
                      const parsed = JSON.parse(content);
                      if (parsed.pid && isPidAlive(parsed.pid)) {
                        canRecover = false;
                      }
                    } catch {}
                    if (canRecover) {
                      try { fs.unlinkSync(lockFile); } catch {}
                    }
                  }
                }
              } finally {
                try { fs.closeSync(reclaimFd); } catch {}
                try {
                  if (fs.existsSync(reclaimLockFile)) {
                    const content = fs.readFileSync(reclaimLockFile, 'utf8');
                    const parsed = JSON.parse(content);
                    if (parsed.reclaimLockId === reclaimLockId) {
                      fs.unlinkSync(reclaimLockFile);
                    }
                  }
                } catch {}
              }
              continue;
            }
          }
        } catch {}
        // Sleep briefly
        const sleepEnd = Date.now() + pollIntervalMs;
        while (Date.now() < sleepEnd) {}
      } else {
        throw err;
      }
    }
  }

  if (lockFd === null) {
    throw new Error(`[LOCK_TIMEOUT] Failed to acquire lock for ${targetFile} within ${timeoutMs}ms`);
  }

  try {
    return fn();
  } finally {
    try {
      fs.closeSync(lockFd);
    } catch {}
    try {
      if (fs.existsSync(lockFile)) {
        const content = fs.readFileSync(lockFile, 'utf8');
        const parsed = JSON.parse(content);
        if (parsed.lockId === lockId) {
          fs.unlinkSync(lockFile);
        }
      }
    } catch {}
  }
}

export const GOVERNANCE_LOCK_TARGET = '.governance';
export const REVOCATION_TXN_FILE = '.revocation-txn.json';

/**
 * Executes a function under the unified governance lock covering all TCB governance files.
 * Resolves Round 07 F-04: Eliminates cross-lock TOCTOU by establishing a joint lock.
 *
 * @param {object} [options={}]
 * @param {Function} fn
 * @returns {any}
 */
export function withGovernanceLock(options, fn) {
  let opts = options;
  let callback = fn;
  if (typeof options === 'function') {
    callback = options;
    opts = {};
  }
  const dir = resolvePluginDataDir(opts);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const lockTarget = path.join(dir, GOVERNANCE_LOCK_TARGET);
  return withFileLock(lockTarget, callback, opts);
}

/**
 * Recovers an uncommitted or interrupted revocation transaction from WAL snapshot.
 * Resolves Round 07 F-03: Crash recovery / power loss recovery across multi-file writes.
 *
 * @param {object} [options={}]
 * @returns {{ recovered: boolean, txnId?: string }}
 */
export function recoverAbortedRevocationTransaction(options = {}) {
  const dir = resolvePluginDataDir(options);
  const txnPath = path.join(dir, REVOCATION_TXN_FILE);
  if (!fs.existsSync(txnPath)) {
    return { recovered: false };
  }

  let txnData = null;
  try {
    txnData = JSON.parse(fs.readFileSync(txnPath, 'utf8'));
  } catch (parseErr) {
    // R08-B02: Corrupted or unparseable WAL JSON MUST fail closed under Default-Deny.
    // Never unlink or ignore an unparseable WAL.
    throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Transaction WAL is corrupted or unparseable: ${parseErr.message}`);
  }

  if (!txnData || typeof txnData !== 'object' || !txnData.txnId || !txnData.status) {
    throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] Transaction WAL missing required fields (txnId, status)');
  }

  // R09-B01: If a WAL file exists on disk, its status MUST be PREPARED to be recoverable.
  // Any corrupted, unknown, or non-PREPARED status MUST fail closed under Default-Deny.
  if (txnData.status !== 'PREPARED') {
    throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Transaction WAL has invalid or unrecoverable status (${txnData.status}); refusing to proceed fail-closed`);
  }

  const expectedJournalPath = getRevocationJournalPath(options);
  const expectedCheckpointPath = getRevocationCheckpointPath(options);
  const expectedRegPath = getTrustRegistryPath(options);
  const histDir = path.join(dir, 'history');

  // R08-B01: Strict canonical path verification to prevent arbitrary file overwrite/deletion
  if (txnData.journalPath && path.resolve(txnData.journalPath) !== path.resolve(expectedJournalPath)) {
    throw new Error(`[TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED] WAL journalPath (${txnData.journalPath}) does not match expected canonical path (${expectedJournalPath})`);
  }
  if (txnData.checkpointPath && path.resolve(txnData.checkpointPath) !== path.resolve(expectedCheckpointPath)) {
    throw new Error(`[TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED] WAL checkpointPath (${txnData.checkpointPath}) does not match expected canonical path (${expectedCheckpointPath})`);
  }
  if (txnData.regPath && path.resolve(txnData.regPath) !== path.resolve(expectedRegPath)) {
    throw new Error(`[TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED] WAL regPath (${txnData.regPath}) does not match expected canonical path (${expectedRegPath})`);
  }
  if (txnData.histPath) {
    if (typeof txnData.histPath !== 'string') {
      throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] WAL histPath must be string');
    }
    const resolvedHist = path.resolve(txnData.histPath);
    if (
      path.dirname(resolvedHist) !== path.resolve(histDir) ||
      !/^trust-registry\.v\d+\.json$/.test(path.basename(resolvedHist))
    ) {
      throw new Error(`[TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED] WAL histPath (${txnData.histPath}) escapes history directory or has invalid filename`);
    }
  }

  // R09-B01: Mandatory paths and sizes in PREPARED WAL
  if (
    !txnData.journalPath || typeof txnData.journalPath !== 'string' ||
    !txnData.checkpointPath || typeof txnData.checkpointPath !== 'string' ||
    !txnData.regPath || typeof txnData.regPath !== 'string' ||
    typeof txnData.initialJournalSize !== 'number'
  ) {
    throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] Transaction WAL PREPARED state missing required paths or sizes (journalPath, checkpointPath, regPath, initialJournalSize)');
  }

  try {
    // R09-B02: Descriptor-bound truncate and safe atomic writes to eliminate TOCTOU race
    if (fs.existsSync(expectedJournalPath)) {
      if (txnData.initialJournalSize === 0 && txnData.initialJournalExisted === false) {
        assertSafeStorageTarget(expectedJournalPath, options);
        fs.unlinkSync(expectedJournalPath);
      } else {
        const journalFd = safeOpenStorageFile(expectedJournalPath, 'r+', 0o600, options);
        try {
          fs.ftruncateSync(journalFd, txnData.initialJournalSize);
          fs.fsyncSync(journalFd);
        } finally {
          fs.closeSync(journalFd);
        }
      }
    }
    if (txnData.initialCheckpointRawBase64) {
      safeWriteFileSync(expectedCheckpointPath, Buffer.from(txnData.initialCheckpointRawBase64, 'base64'), options);
    } else if (fs.existsSync(expectedCheckpointPath) && txnData.initialCheckpointExisted === false) {
      assertSafeStorageTarget(expectedCheckpointPath, options);
      fs.unlinkSync(expectedCheckpointPath);
    }
    if (txnData.initialRegistryRawBase64) {
      safeWriteFileSync(expectedRegPath, Buffer.from(txnData.initialRegistryRawBase64, 'base64'), options);
    } else if (fs.existsSync(expectedRegPath) && txnData.initialRegistryExisted === false) {
      assertSafeStorageTarget(expectedRegPath, options);
      fs.unlinkSync(expectedRegPath);
    }
    if (txnData.histPath) {
      const canonicalHistPath = path.resolve(txnData.histPath);
      if (txnData.initialHistRawBase64) {
        safeWriteFileSync(canonicalHistPath, Buffer.from(txnData.initialHistRawBase64, 'base64'), options);
      } else if (fs.existsSync(canonicalHistPath) && txnData.initialHistExisted === false) {
        assertSafeStorageTarget(canonicalHistPath, options);
        fs.unlinkSync(canonicalHistPath);
      }
    }
    assertSafeStorageTarget(txnPath, options);
    fs.unlinkSync(txnPath);
    return { recovered: true, txnId: txnData.txnId };
  } catch (recErr) {
    if (recErr.message && recErr.message.includes('TRANSACTION_WAL_PATH_TRAVERSAL_DETECTED')) {
      throw recErr;
    }
    txnData.status = 'CORRUPTED';
    try {
      safeWriteFileSync(txnPath, JSON.stringify(txnData, null, 2), options);
    } catch (_) {}
    throw new Error(`[TRANSACTION_CRASH_RECOVERY_FAILED] Failed to recover aborted transaction ${txnData.txnId}: ${recErr.message}`);
  }
}

/**
 * Resolves the persistent plugin data directory location.
 * Resolves M54-P2-F03: Enforces realpath resolution and post-creation validation against symlink/junction bypass.
 *
 * @param {object} [options={}]
 * @returns {string} Normalized absolute path to plugin data directory
 */
export function resolvePluginDataDir(options = {}) {
  let targetDir = options.pluginDataDir || process.env.PLUGIN_DATA || process.env.AGY_PLUGIN_DATA;

  if (!targetDir || typeof targetDir !== 'string' || !targetDir.trim()) {
    const homeDir = os.homedir();
    targetDir = path.join(homeDir, '.gemini', 'antigravity-cli', 'plugin_data', 'security-audit');
  }

  if (targetDir.includes('\0')) {
    throw new Error('Illegal null byte detected in plugin data path');
  }

  const normalized = toRealNormalizedPath(targetDir);

  // Zero Workspace Pollution Invariant Check (F03: Check both repoRoot and cwd using realpaths)
  if (options.allowInWorkspace !== true) {
    const forbiddenPaths = new Set();

    if (options.repoRoot) {
      forbiddenPaths.add(toRealNormalizedPath(options.repoRoot));
    }
    forbiddenPaths.add(toRealNormalizedPath(process.cwd()));

    if (process.env.INIT_CWD) {
      forbiddenPaths.add(toRealNormalizedPath(process.env.INIT_CWD));
    }

    if (Array.isArray(options.workspacePaths)) {
      for (const ws of options.workspacePaths) {
        if (ws) forbiddenPaths.add(toRealNormalizedPath(ws));
      }
    }

    const normLower = normalized.toLowerCase();
    for (const forbidden of forbiddenPaths) {
      const fLower = forbidden.toLowerCase();
      if (forbidden && (normLower === fLower || normLower.startsWith(fLower + '/'))) {
        throw new Error(
          `[ZERO_WORKSPACE_POLLUTION_VIOLATION] PLUGIN_DATA (${normalized}) must not reside inside target workspace (${forbidden})`
        );
      }
    }
  }

  if (options.ensureDir !== false) {
    if (!fs.existsSync(normalized)) {
      fs.mkdirSync(normalized, { recursive: true });
    }
    // Post-creation physical verification (F03 Closure)
    if (options.allowInWorkspace !== true && fs.existsSync(normalized)) {
      const postReal = normalizePath(fs.realpathSync(normalized)).toLowerCase();
      const checkRoots = [
        options.repoRoot ? toRealNormalizedPath(options.repoRoot) : null,
        toRealNormalizedPath(process.cwd()),
        process.env.INIT_CWD ? toRealNormalizedPath(process.env.INIT_CWD) : null
      ].filter(Boolean);
      for (const root of checkRoots) {
        const rLower = root.toLowerCase();
        if (postReal === rLower || postReal.startsWith(rLower + '/')) {
          throw new Error(
            `[ZERO_WORKSPACE_POLLUTION_VIOLATION] Post-creation check: physical realpath (${postReal}) resides inside target workspace (${root})`
          );
        }
      }
    }
  }

  return normalized;
}

export function getTrustRegistryPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, 'supervisor-trust-registry.json'));
}

export function getRevocationJournalPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, '.irv-revocation-journal.jsonl'));
}

export function getRevocationCheckpointPath(options = {}) {
  const dir = resolvePluginDataDir(options);
  return normalizePath(path.join(dir, 'supervisor-revocation-checkpoint.json'));
}

/**
 * Computes canonical payload for revocation record signature.
 * Resolves M54-P2-F01: Signs all canonical fields to prevent field tampering.
 */
export function computeRevocationEntrySignPayload(record) {
  return canonicalJsonStringify({
    entryIndex: record.entryIndex,
    timestamp: record.timestamp,
    revocationType: record.revocationType,
    targetId: record.targetId,
    reason: record.reason || 'MANUAL_REVOCATION',
    prevEntryDigest: record.prevEntryDigest,
    signedBy: record.signedBy
  });
}

/**
 * Computes canonical payload for trust registry authorization signature.
 * Resolves M54-P2-F02: Enforces canonical signing over keys array as well as root identity.
 */
export function computeRegistryAuthorizationPayload(registry) {
  const normalizedKeys = Array.isArray(registry.keys)
    ? registry.keys.map(k => ({
        keyId: k.keyId,
        keyFingerprint: k.keyFingerprint,
        publicKeyPem: k.publicKeyPem,
        status: k.status,
        issuedAt: k.issuedAt || ''
      })).sort((a, b) => a.keyId.localeCompare(b.keyId))
    : [];
  const payload = {
    schemaVersion: registry.schemaVersion,
    registryVersion: registry.registryVersion,
    authority: registry.authority,
    activeKeyId: registry.activeKeyId,
    activeKeyFingerprint: registry.activeKeyFingerprint,
    activePublicKeyPem: registry.activePublicKeyPem,
    keys: normalizedKeys,
    revokedKeyIds: Array.isArray(registry.revokedKeyIds) ? [...registry.revokedKeyIds].sort() : []
  };
  return canonicalJsonStringify(payload);
}

/**
 * Validates the schema and cryptographic integrity of a trust registry object.
 * Resolves M54-P2-F02: Enforces root authorization chain verification.
 * - Genesis v1: keys array must contain strictly the genesis root anchor (anti-rogue injection).
 * - Version > 1: Signer public key MUST originate from root anchor or an authenticated priorRegistry (no self-signed loop).
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ valid: boolean, error: string|null, cryptographicValidity: boolean|null, monotonicValidity: boolean, ancestryContinuity: boolean }}
 */
export function validateTrustRegistry(registry, options = {}) {
  let cryptographicValidity = null;
  let monotonicValidity = true;
  let ancestryContinuity = true;

  if (!registry || typeof registry !== 'object') {
    return {
      valid: false,
      error: 'Registry must be a non-null object',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  if (typeof registry.schemaVersion !== 'string' || !registry.schemaVersion) {
    return {
      valid: false,
      error: 'Missing or invalid schemaVersion',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  if (!Number.isInteger(registry.registryVersion) || registry.registryVersion < 1) {
    return {
      valid: false,
      error: 'registryVersion must be an integer >= 1',
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  const expectedMinVersion = typeof options.minRegistryVersion === 'number'
    ? options.minRegistryVersion
    : (process.env.THREE_LENS_MIN_REGISTRY_VERSION ? parseInt(process.env.THREE_LENS_MIN_REGISTRY_VERSION, 10) : 1);

  if (registry.registryVersion < expectedMinVersion) {
    monotonicValidity = false;
    return {
      valid: false,
      error: `Monotonic regression: registryVersion (${registry.registryVersion}) < min required (${expectedMinVersion})`,
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: true
    };
  }

  if (typeof registry.activeKeyId !== 'string' || !registry.activeKeyId) {
    return {
      valid: false,
      error: 'Missing or invalid activeKeyId',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (typeof registry.activePublicKeyPem !== 'string' || !registry.activePublicKeyPem.includes('BEGIN PUBLIC KEY')) {
    return {
      valid: false,
      error: 'Missing or malformed activePublicKeyPem',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  const computedFp = sha256Digest(registry.activePublicKeyPem);
  if (computedFp !== registry.activeKeyFingerprint) {
    return {
      valid: false,
      error: `Fingerprint mismatch: expected ${registry.activeKeyFingerprint}, computed ${computedFp}`,
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (!Array.isArray(registry.keys) || registry.keys.length === 0) {
    return {
      valid: false,
      error: 'keys array must be non-empty',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  if (!Array.isArray(registry.revokedKeyIds)) {
    return {
      valid: false,
      error: 'revokedKeyIds must be an array',
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  // High-water mark validation if present (R05-B01)
  if (registry.revocationHighWaterMark !== undefined && registry.revocationHighWaterMark !== null) {
    const hwm = registry.revocationHighWaterMark;
    if (
      typeof hwm !== 'object' ||
      typeof hwm.headIndex !== 'number' ||
      hwm.headIndex < 0 ||
      typeof hwm.headDigest !== 'string' ||
      !/^[0-9a-f]{64}$/i.test(hwm.headDigest)
    ) {
      return {
        valid: false,
        error: 'Malformed revocationHighWaterMark in trust registry',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }

    if (typeof hwm.signature !== 'string' || !hwm.signature.trim() || typeof hwm.authorizedBy !== 'string' || !hwm.authorizedBy.trim()) {
      return {
        valid: false,
        error: '[HIGH_WATER_MARK_SIGNATURE_MISSING] revocationHighWaterMark requires authorizedBy and cryptographic signature',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }

    // R08-B05: Signer must not have been already revoked in priorRegistry.
    // However, if the key was active when it signed the historical HWM and only revoked in this version,
    // its historical cryptographic signature remains valid against its public key.
    if (options.priorRegistry && Array.isArray(options.priorRegistry.revokedKeyIds) && options.priorRegistry.revokedKeyIds.includes(hwm.authorizedBy)) {
      return {
        valid: false,
        error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer '${hwm.authorizedBy}' for revocationHighWaterMark was already revoked in prior registry`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }

    const hwmSignerKey = registry.keys.find(
      k => k.keyId === hwm.authorizedBy && ['ACTIVE_PINNED_ROOT', 'ACTIVE', 'RETIRED', 'REVOKED'].includes(k.status)
    );
    if (!hwmSignerKey) {
      return {
        valid: false,
        error: `Signer '${hwm.authorizedBy}' for revocationHighWaterMark not found in registry keys`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
    const hwmPayload = Buffer.from(canonicalJsonStringify({
      headIndex: hwm.headIndex,
      headDigest: hwm.headDigest,
      updatedAt: hwm.updatedAt,
      authorizedBy: hwm.authorizedBy
    }), 'utf8');
    const isHwmSigValid = crypto.verify(null, hwmPayload, hwmSignerKey.publicKeyPem, Buffer.from(hwm.signature, 'hex'));
    if (!isHwmSigValid) {
      return {
        valid: false,
        error: 'Cryptographic verification of revocationHighWaterMark failed',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
  }

  // F02 & R04-B02 & R05-B01 & R05-B02: Ancestry verification against priorRegistry
  if (options.priorRegistry && typeof options.priorRegistry === 'object') {
    if (typeof options.priorRegistry.registryVersion === 'number') {
      if (registry.registryVersion <= options.priorRegistry.registryVersion) {
        monotonicValidity = false;
        return {
          valid: false,
          error: `[REGISTRY_ROLLBACK_DETECTED] Version ${registry.registryVersion} <= priorRegistry version ${options.priorRegistry.registryVersion}`,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      if (registry.registryVersion !== options.priorRegistry.registryVersion + 1) {
        ancestryContinuity = false;
        return {
          valid: false,
          error: `[ANCESTRY_CONTINUITY_VIOLATION] Non-consecutive version progression: version ${registry.registryVersion} is not consecutive successor to priorRegistry version ${options.priorRegistry.registryVersion}`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: false
        };
      }
    }

    // High-water mark strip and rollback protection across versions (R05-B01)
    if (options.priorRegistry.revocationHighWaterMark) {
      if (!registry.revocationHighWaterMark) {
        return {
          valid: false,
          error: '[HIGH_WATER_MARK_STRIP_VIOLATION] Cannot strip previously established revocationHighWaterMark',
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      if (registry.revocationHighWaterMark.headIndex < options.priorRegistry.revocationHighWaterMark.headIndex) {
        return {
          valid: false,
          error: `[HIGH_WATER_MARK_ROLLBACK_DETECTED] Cannot rollback revocation high-water mark from ${options.priorRegistry.revocationHighWaterMark.headIndex} to ${registry.revocationHighWaterMark.headIndex}`,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
    }
  } else if (registry.registryVersion > 1) {
    ancestryContinuity = false;
    return {
      valid: false,
      error: `[ANCESTRY_CONTINUITY_VIOLATION] Registry version ${registry.registryVersion} (> 1) requires verified priorRegistry for unbroken ancestry verification`,
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: false
    };
  }

  // Root Authorization Chain Verification
  const expectedRootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
  const expectedRootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
  const expectedRootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;

  if (registry.registryVersion === 1) {
    if (registry.activeKeyId !== expectedRootId || registry.activeKeyFingerprint !== expectedRootFp) {
      return {
        valid: false,
        error: `Genesis registry (v1) activeKeyId/fingerprint must match embedded root anchor (${expectedRootId})`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
    if (
      registry.keys.length !== 1 ||
      registry.keys[0].keyId !== expectedRootId ||
      registry.keys[0].keyFingerprint !== expectedRootFp ||
      registry.keys[0].publicKeyPem !== expectedRootPem ||
      registry.keys[0].status !== 'ACTIVE_PINNED_ROOT'
    ) {
      return {
        valid: false,
        error: `Genesis registry (v1) keys array must contain exactly the pinned root key (${expectedRootId}) with status ACTIVE_PINNED_ROOT and matching PEM`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }
    if (registry.authorizationProof) {
      const proof = registry.authorizationProof;
      if (!proof.authorizedBy || !proof.signature) {
        return {
          valid: false,
          error: 'authorizationProof missing authorizedBy or signature',
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: true
        };
      }
      if (proof.authorizedBy !== expectedRootId) {
        return {
          valid: false,
          error: `Genesis authorizationProof signer '${proof.authorizedBy}' must match root anchor (${expectedRootId})`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: true
        };
      }
      const payload = Buffer.from(computeRegistryAuthorizationPayload(registry), 'utf8');
      const isValid = crypto.verify(null, payload, expectedRootPem, Buffer.from(proof.signature, 'hex'));
      if (!isValid) {
        return {
          valid: false,
          error: 'Cryptographic verification of authorizationProof failed',
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: true
        };
      }
      cryptographicValidity = true;
    } else {
      // In-memory or unadorned genesis v1 matches root anchor
      cryptographicValidity = true;
    }
  } else {
    // Version > 1 MUST carry a cryptographic authorizationProof signed by an authorized key
    if (!registry.authorizationProof || typeof registry.authorizationProof !== 'object') {
      return {
        valid: false,
        error: `Registry version ${registry.registryVersion} (> 1) requires valid authorizationProof`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    const proof = registry.authorizationProof;
    if (!proof.authorizedBy || !proof.signature) {
      return {
        valid: false,
        error: 'authorizationProof missing authorizedBy or signature',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    // R08-B05: Revoked keys cannot authorize new registries
    if (options.priorRegistry && Array.isArray(options.priorRegistry.revokedKeyIds)) {
      if (options.priorRegistry.revokedKeyIds.includes(proof.authorizedBy)) {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' was already revoked in prior registry`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
    }
    if (options.priorRegistry && Array.isArray(options.priorRegistry.keys)) {
      const priorKey = options.priorRegistry.keys.find(k => k.keyId === proof.authorizedBy);
      if (priorKey && priorKey.status === 'REVOKED') {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' has status 'REVOKED' in prior registry`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
    }

    let signerPem = null;
    if (proof.authorizedBy === expectedRootId) {
      signerPem = expectedRootPem;
    } else if (options.priorRegistry && typeof options.priorRegistry === 'object' && Array.isArray(options.priorRegistry.keys)) {
      const priorValidation = validateTrustRegistry(options.priorRegistry, {
        ...options,
        priorRegistry: null,
        minRegistryVersion: 1
      });
      if (!priorValidation.valid) {
        return {
          valid: false,
          error: `Unauthenticated priorRegistry rejected: ${priorValidation.error}`,
          cryptographicValidity: false,
          monotonicValidity: priorValidation.monotonicValidity,
          ancestryContinuity: false
        };
      }
      const priorKey = options.priorRegistry.keys.find(
        k => k.keyId === proof.authorizedBy && (k.status === 'ACTIVE_PINNED_ROOT' || k.status === 'ACTIVE')
      );
      if (priorKey) {
        signerPem = priorKey.publicKeyPem;
      }
    }

    if (!signerPem) {
      return {
        valid: false,
        error: `Signer key '${proof.authorizedBy}' for authorizationProof not found in trusted authority root or authenticated prior registry`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }

    const payload = Buffer.from(computeRegistryAuthorizationPayload(registry), 'utf8');
    const isValid = crypto.verify(null, payload, signerPem, Buffer.from(proof.signature, 'hex'));
    if (!isValid) {
      return {
        valid: false,
        error: 'Cryptographic verification of authorizationProof failed',
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: ancestryContinuity
      };
    }
    cryptographicValidity = true;
  }

  return {
    valid: cryptographicValidity && monotonicValidity && ancestryContinuity,
    error: null,
    cryptographicValidity,
    monotonicValidity,
    ancestryContinuity
  };
}

/**
 * Creates an authorized registry update carrying a cryptographic authorizationProof.
 *
 * @param {object} currentRegistry
 * @param {object} updates
 * @param {string} signerKeyId
 * @param {KeyObject|string} signerPrivateKey
 * @returns {object} Updated registry with authorizationProof
 */
export function createAuthorizedRegistryUpdate(currentRegistry, updates, signerKeyId, signerPrivateKey) {
  // R08-B05: Revoked keys cannot authorize updates
  if (Array.isArray(currentRegistry.revokedKeyIds) && currentRegistry.revokedKeyIds.includes(signerKeyId)) {
    throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${signerKeyId}' has already been revoked in current registry`);
  }

  const updated = {
    ...currentRegistry,
    ...updates,
    registryVersion: (currentRegistry.registryVersion || 1) + 1
  };

  // R08-B05: If HWM exists and its prior signer was revoked, or if re-signing requested,
  // re-sign HWM with the new authorized signer
  if (updated.revocationHighWaterMark) {
    const isSignerRevoked = Array.isArray(updated.revokedKeyIds) && updated.revokedKeyIds.includes(updated.revocationHighWaterMark.authorizedBy);
    if (isSignerRevoked || updates.reSignHighWaterMark === true) {
      const hwmPayload = Buffer.from(canonicalJsonStringify({
        headIndex: updated.revocationHighWaterMark.headIndex,
        headDigest: updated.revocationHighWaterMark.headDigest,
        updatedAt: updated.revocationHighWaterMark.updatedAt,
        authorizedBy: signerKeyId
      }), 'utf8');
      const hwmSig = crypto.sign(null, hwmPayload, signerPrivateKey).toString('hex');
      updated.revocationHighWaterMark = {
        ...updated.revocationHighWaterMark,
        authorizedBy: signerKeyId,
        signature: hwmSig
      };
    }
  }

  const payload = Buffer.from(computeRegistryAuthorizationPayload(updated), 'utf8');
  const signature = crypto.sign(null, payload, signerPrivateKey).toString('hex');
  updated.authorizationProof = {
    authorizedBy: signerKeyId,
    signature,
    timestamp: new Date().toISOString()
  };
  return updated;
}

/**
 * Loads trust registry, adhering to dual-anchor resolution.
 * Primary: Reads from PLUGIN_DATA.
 * Secondary: Falls back to embedded static root registry.
 *
 * @param {object} [options={}]
 * @returns {{ source: 'PLUGIN_DATA'|'EMBEDDED_FALLBACK', registry: object, valid: boolean }}
 */
function doLoadTrustRegistry(options = {}) {
  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(regPath);

  if (fs.existsSync(regPath)) {
    try {
      const raw = fs.readFileSync(regPath, 'utf8');
      const parsed = JSON.parse(raw);

      // Check for rollback against historical state in dir (R06 & R07 F-01 hardening)
      const histDir = path.join(dir, 'history');
      if (!fs.existsSync(histDir)) {
        const errorMsg = `[HISTORY_DELETION_DETECTED] On-disk trust registry exists at ${regPath} but historical directory ${histDir} is missing (history wiped/tampered)`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }

      const histFiles = fs.readdirSync(histDir).filter(f => /^trust-registry\.v(\d+)\.json$/.test(f));
      if (histFiles.length === 0) {
        const errorMsg = `[HISTORY_DELETION_DETECTED] Historical directory ${histDir} contains zero trust-registry.v*.json files (history wiped)`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }

      if (!fs.existsSync(path.join(histDir, 'trust-registry.v1.json'))) {
        const errorMsg = `[GENESIS_HISTORY_MISSING_FAIL_CLOSED] Historical genesis entry trust-registry.v1.json is missing in ${histDir} (history rollback/deletion detected)`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }

      let highestHistHwmIndex = -1;
      let maxHistVersion = 0;
      let sameVersionHistRegistry = null;

      try {
        for (const hf of histFiles) {
          const m = hf.match(/^trust-registry\.v(\d+)\.json$/);
          if (m) {
            const v = parseInt(m[1], 10);
            if (v > maxHistVersion) maxHistVersion = v;
            try {
              const histObj = JSON.parse(fs.readFileSync(path.join(histDir, hf), 'utf8'));
              if (v === parsed.registryVersion) {
                sameVersionHistRegistry = histObj;
              }
              if (histObj.revocationHighWaterMark && typeof histObj.revocationHighWaterMark.headIndex === 'number') {
                if (histObj.revocationHighWaterMark.headIndex > highestHistHwmIndex) {
                  highestHistHwmIndex = histObj.revocationHighWaterMark.headIndex;
                }
              }
            } catch (_) {}
          }
        }

        // R08-B04: Consecutive historical unbroken progression check (anti-intermediate and anti-tail gap)
        for (let i = 1; i <= maxHistVersion; i++) {
          const expectedHistPath = path.join(histDir, `trust-registry.v${i}.json`);
          if (!fs.existsSync(expectedHistPath)) {
            const errorMsg = `[HISTORY_GAP_DETECTED] Missing intermediate or tail history file trust-registry.v${i}.json in ${histDir} (1..${maxHistVersion} unbroken chain required)`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
        }

        if (maxHistVersion > parsed.registryVersion) {
          const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] On-disk registry version ${parsed.registryVersion} is less than historical version ${maxHistVersion}`;
          if (options.failClosed !== false) {
            throw new Error(errorMsg);
          }
          return {
            source: 'PLUGIN_DATA',
            registry: null,
            valid: false,
            error: errorMsg,
            cryptographicValidity: false,
            monotonicValidity: false,
            ancestryContinuity: false
          };
        }

        // R08-B04: Match on-disk registry content against historical counterpart
        if (sameVersionHistRegistry) {
          const histContent = fs.readFileSync(path.join(histDir, `trust-registry.v${parsed.registryVersion}.json`), 'utf8');
          const diskHash = sha256Digest(raw);
          const histHash = sha256Digest(histContent);
          if (diskHash !== histHash) {
            const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] [REGISTRY_HISTORY_DESYNC_DETECTED] On-disk trust registry content (SHA-256 ${diskHash}) does not match historical trust-registry.v${parsed.registryVersion}.json (SHA-256 ${histHash})`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
        }

        // Same-version anti-rollback check (e.g. Genesis v1 with established HWM)
        if (sameVersionHistRegistry) {
          if (sameVersionHistRegistry.revocationHighWaterMark && !parsed.revocationHighWaterMark) {
            const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] Replay of unadorned Genesis registry over historical version ${parsed.registryVersion} with established revocations`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
          if (
            sameVersionHistRegistry.revocationHighWaterMark &&
            parsed.revocationHighWaterMark &&
            parsed.revocationHighWaterMark.headIndex < sameVersionHistRegistry.revocationHighWaterMark.headIndex
          ) {
            const errorMsg = `[HIGH_WATER_MARK_ROLLBACK_DETECTED] On-disk registry high-water mark (${parsed.revocationHighWaterMark.headIndex}) is behind historical version ${parsed.registryVersion} mark (${sameVersionHistRegistry.revocationHighWaterMark.headIndex})`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
        }

        // Invariant: If ANY historical registry recorded a high-water mark, parsed registry cannot have a lower or stripped mark
        if (highestHistHwmIndex >= 0) {
          if (!parsed.revocationHighWaterMark) {
            const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] Replay of registry without revocation high-water mark rejected (historical high-water mark index ${highestHistHwmIndex} exists)`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
          if (parsed.revocationHighWaterMark.headIndex < highestHistHwmIndex) {
            const errorMsg = `[HIGH_WATER_MARK_ROLLBACK_DETECTED] On-disk registry high-water mark (${parsed.revocationHighWaterMark.headIndex}) is behind historical high-water mark (${highestHistHwmIndex})`;
            if (options.failClosed !== false) {
              throw new Error(errorMsg);
            }
            return {
              source: 'PLUGIN_DATA',
              registry: null,
              valid: false,
              error: errorMsg,
              cryptographicValidity: false,
              monotonicValidity: false,
              ancestryContinuity: false
            };
          }
        }
      } catch (hErr) {
        if (
          hErr.message &&
          (
            hErr.message.includes('REGISTRY_ROLLBACK_DETECTED') ||
            hErr.message.includes('HIGH_WATER_MARK_ROLLBACK_DETECTED') ||
            hErr.message.includes('HISTORY_GAP_DETECTED') ||
            hErr.message.includes('REGISTRY_HISTORY_DESYNC_DETECTED') ||
            hErr.message.includes('CHECKPOINT_DELETION_DETECTED')
          )
        ) {
          throw hErr;
        }
      }

      // Check for rollback against established revocations in dir (R06 hardening)
      const checkpointPath = getRevocationCheckpointPath(options);
      const journalPath = getRevocationJournalPath(options);

      // Combination attack defense: if history recorded revocations but journal/checkpoint deleted
      if (highestHistHwmIndex >= 0 && (!fs.existsSync(journalPath) || !fs.existsSync(checkpointPath))) {
        const errorMsg = `[JOURNAL_ROLLBACK_DETECTED] Revocation journal or checkpoint deleted in established installation (historical high-water mark index ${highestHistHwmIndex} exists)`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      let establishedHeadIndex = -1;
      let checkpointRegistryVersion = null;
      if (fs.existsSync(checkpointPath)) {
        try {
          const cp = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
          if (typeof cp.headIndex === 'number' && cp.headIndex >= 0) {
            establishedHeadIndex = cp.headIndex;
          }
          if (typeof cp.registryVersion === 'number') {
            checkpointRegistryVersion = cp.registryVersion;
          }
        } catch (_) {}
      } else if (parsed.registryVersion > 1 || maxHistVersion > 1) {
        // R08-B04: Checkpoint missing in established installation beyond genesis
        const errorMsg = `[CHECKPOINT_DELETION_DETECTED] Checkpoint file missing in established installation (version ${parsed.registryVersion}, max history ${maxHistVersion})`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }

      // R08-B04: Checkpoint version anti-tail-deletion check
      if (checkpointRegistryVersion !== null && parsed.registryVersion < checkpointRegistryVersion) {
        const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] On-disk registry version ${parsed.registryVersion} is behind established checkpoint registryVersion ${checkpointRegistryVersion}`;
        if (options.failClosed !== false) {
          throw new Error(errorMsg);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: errorMsg,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }

      if (establishedHeadIndex < 0 && fs.existsSync(journalPath)) {
        try {
          const stat = fs.statSync(journalPath);
          if (stat.size > 0) {
            establishedHeadIndex = 0;
          }
        } catch (_) {}
      }

      if (establishedHeadIndex >= 0) {
        if (!parsed.revocationHighWaterMark) {
          const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] Replay of Genesis registry over established installation rejected (revocations present up to index ${establishedHeadIndex})`;
          if (options.failClosed !== false) {
            throw new Error(errorMsg);
          }
          return {
            source: 'PLUGIN_DATA',
            registry: null,
            valid: false,
            error: errorMsg,
            cryptographicValidity: false,
            monotonicValidity: false,
            ancestryContinuity: false
          };
        }
        if (parsed.revocationHighWaterMark.headIndex < establishedHeadIndex) {
          const errorMsg = `[HIGH_WATER_MARK_ROLLBACK_DETECTED] On-disk registry high-water mark (${parsed.revocationHighWaterMark.headIndex}) is behind established checkpoint (${establishedHeadIndex})`;
          if (options.failClosed !== false) {
            throw new Error(errorMsg);
          }
          return {
            source: 'PLUGIN_DATA',
            registry: null,
            valid: false,
            error: errorMsg,
            cryptographicValidity: false,
            monotonicValidity: false,
            ancestryContinuity: false
          };
        }
      }

      let effectivePriorRegistry = options.priorRegistry || null;
      if (!effectivePriorRegistry && parsed.registryVersion > 1) {
        // Look up historical prior version in history/ directory
        const priorHistPath = path.join(dir, 'history', `trust-registry.v${parsed.registryVersion - 1}.json`);
        if (fs.existsSync(priorHistPath)) {
          try {
            effectivePriorRegistry = JSON.parse(fs.readFileSync(priorHistPath, 'utf8'));
          } catch (_) {}
        } else if (parsed.registryVersion === 2) {
          // If v2 and history not yet written, use embedded genesis root if matching
          const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
          const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
          const rootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
          effectivePriorRegistry = {
            schemaVersion: '1.0.0',
            registryVersion: 1,
            authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
            activeKeyId: rootId,
            activeKeyFingerprint: rootFp,
            activePublicKeyPem: rootPem,
            keyType: 'ed25519',
            pinnedSince: '2026-10-16T06:55:39.565Z',
            rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
            revokedKeyIds: [],
            keys: [{ keyId: rootId, keyFingerprint: rootFp, publicKeyPem: rootPem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
          };
        }
      }

      const validation = validateTrustRegistry(parsed, {
        ...options,
        priorRegistry: effectivePriorRegistry
      });

      if (!validation.valid) {
        if (options.failClosed !== false) {
          throw new Error(`Corrupt trust registry at ${regPath}: ${validation.error}`);
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: validation.error,
          cryptographicValidity: validation.cryptographicValidity,
          monotonicValidity: validation.monotonicValidity,
          ancestryContinuity: validation.ancestryContinuity
        };
      }

      return {
        source: 'PLUGIN_DATA',
        registry: parsed,
        valid: true,
        path: regPath,
        cryptographicValidity: validation.cryptographicValidity,
        monotonicValidity: validation.monotonicValidity,
        ancestryContinuity: validation.ancestryContinuity
      };
    } catch (err) {
      if (options.failClosed !== false) {
        throw new Error(`Failed to read trust registry from ${regPath}: ${err.message}`);
      }
      return {
        source: 'PLUGIN_DATA',
        registry: null,
        valid: false,
        error: err.message,
        cryptographicValidity: false,
        monotonicValidity: false,
        ancestryContinuity: false
      };
    }
  }

  // Disk registry missing:
  let hasExistingState = false;
  if (fs.existsSync(dir)) {
    try {
      const files = fs.readdirSync(dir).filter(f => !f.startsWith('.tmp.') && !f.endsWith('.lock'));
      if (files.length > 0) {
        hasExistingState = true;
      }
    } catch (_) {}
  }

  if (
    hasExistingState ||
    options.requirePersistentRegistry === true ||
    options.disallowFallback === true ||
    process.env.THREE_LENS_REQUIRE_PERSISTENT_REGISTRY === '1'
  ) {
    const errorMsg = `[PERSISTENT_REGISTRY_MISSING] On-disk trust registry missing from ${regPath} in existing installation (rollback/deletion detected)`;
    if (options.failClosed !== false) {
      throw new Error(errorMsg);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: errorMsg,
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  const fallback = JSON.parse(JSON.stringify(EMBEDDED_ROOT_REGISTRY));
  const expectedMin = typeof options.minRegistryVersion === 'number'
    ? options.minRegistryVersion
    : (process.env.THREE_LENS_MIN_REGISTRY_VERSION ? parseInt(process.env.THREE_LENS_MIN_REGISTRY_VERSION, 10) : 1);

  if (fallback.registryVersion < expectedMin) {
    const errorMsg = `Monotonic regression: registry version ${fallback.registryVersion} < minimum expected ${expectedMin}`;
    if (options.failClosed !== false) {
      throw new Error(`[MONOTONIC_REGRESSION_FAIL_CLOSED] ${errorMsg}`);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: errorMsg,
      cryptographicValidity: true,
      monotonicValidity: false,
      ancestryContinuity: true
    };
  }

  // Validate fallback schema integrity against default root
  const fallbackValidation = validateTrustRegistry(fallback, { minRegistryVersion: 1 });
  if (!fallbackValidation.valid) {
    if (options.failClosed !== false) {
      throw new Error(`Embedded fallback registry fails schema validation: ${fallbackValidation.error}`);
    }
    return {
      source: 'EMBEDDED_FALLBACK',
      registry: null,
      valid: false,
      error: fallbackValidation.error,
      cryptographicValidity: fallbackValidation.cryptographicValidity,
      monotonicValidity: fallbackValidation.monotonicValidity,
      ancestryContinuity: fallbackValidation.ancestryContinuity
    };
  }

  if (options.autoInitialize === true) {
    saveTrustRegistry(fallback, options);
    return {
      source: 'PLUGIN_DATA',
      registry: fallback,
      valid: true,
      path: regPath,
      initialized: true,
      cryptographicValidity: true,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }

  return {
    source: 'EMBEDDED_FALLBACK',
    registry: fallback,
    valid: true,
    path: null,
    cryptographicValidity: true,
    monotonicValidity: true,
    ancestryContinuity: true
  };
}

/**
 * Loads trust registry under governance lock with automatic WAL crash recovery.
 * Resolves R08-B02: Executes exclusively under joint governance lock.
 *
 * @param {object} [options={}]
 * @returns {{ source: 'PLUGIN_DATA'|'EMBEDDED_FALLBACK', registry: object, valid: boolean }}
 */
export function loadTrustRegistry(options = {}) {
  if (options.skipLock === true) {
    recoverAbortedRevocationTransaction(options);
    return doLoadTrustRegistry(options);
  }
  return withGovernanceLock(options, () => {
    recoverAbortedRevocationTransaction(options);
    return doLoadTrustRegistry(options);
  });
}

/**
 * Atomically writes a trust registry to PLUGIN_DATA under mutual exclusion.
 * Resolves M54-P2-F02 (Monotonic check and anti-rollback) and M54-P2-F04 (withFileLock).
 *
 * @param {object} registry
 * @param {object} [options={}]
 * @returns {{ success: boolean, path: string, registryVersion: number }}
 */
export function saveTrustRegistry(registry, options = {}) {
  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(regPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return withGovernanceLock(options, () => {
    recoverAbortedRevocationTransaction(options);
    assertSafeStorageTarget(regPath, options);
    let priorRegistry = null;
    // Check against existing on-disk registry if present
    if (fs.existsSync(regPath)) {
      try {
        const existingRaw = fs.readFileSync(regPath, 'utf8');
        priorRegistry = JSON.parse(existingRaw);

        if (registry.registryVersion < priorRegistry.registryVersion) {
          throw new Error(
            `[REGISTRY_ROLLBACK_DETECTED] Cannot save version ${registry.registryVersion} over existing version ${priorRegistry.registryVersion}`
          );
        }

        // Anti-unrevocation invariant: cannot strip previously revoked keyIds
        if (Array.isArray(priorRegistry.revokedKeyIds)) {
          for (const revokedId of priorRegistry.revokedKeyIds) {
            if (!registry.revokedKeyIds.includes(revokedId)) {
              throw new Error(`[REVOCATION_STRIP_VIOLATION] Cannot un-revoke previously revoked keyId '${revokedId}'`);
            }
          }
        }

        // Anti-rollback / anti-strip invariant for revocationHighWaterMark (R05-B01)
        if (priorRegistry.revocationHighWaterMark) {
          if (!registry.revocationHighWaterMark) {
            throw new Error('[HIGH_WATER_MARK_STRIP_VIOLATION] Cannot strip previously established revocationHighWaterMark');
          }
          if (registry.revocationHighWaterMark.headIndex < priorRegistry.revocationHighWaterMark.headIndex) {
            throw new Error(`[HIGH_WATER_MARK_ROLLBACK_DETECTED] Cannot rollback revocation high-water mark from ${priorRegistry.revocationHighWaterMark.headIndex} to ${registry.revocationHighWaterMark.headIndex}`);
          }
        }
      } catch (err) {
        if (
          err.message.includes('REGISTRY_ROLLBACK_DETECTED') ||
          err.message.includes('REVOCATION_STRIP_VIOLATION') ||
          err.message.includes('HIGH_WATER_MARK_STRIP_VIOLATION') ||
          err.message.includes('HIGH_WATER_MARK_ROLLBACK_DETECTED')
        ) {
          throw err;
        }
        if (options.forceOverwrite !== true) {
          throw new Error(
            `[CORRUPT_PRIOR_REGISTRY_DETECTED] Cannot save registry: existing on-disk registry at ${regPath} is corrupt or unreadable (${err.message})`
          );
        }
      }
    }

    if (!priorRegistry) {
      const histDir = path.join(dir, 'history');
      if (fs.existsSync(histDir)) {
        try {
          const histFiles = fs.readdirSync(histDir).filter(f => /^trust-registry\.v(\d+)\.json$/.test(f));
          let maxHistVersion = 0;
          let latestHistFile = null;
          for (const hf of histFiles) {
            const m = hf.match(/^trust-registry\.v(\d+)\.json$/);
            if (m) {
              const v = parseInt(m[1], 10);
              if (v > maxHistVersion) {
                maxHistVersion = v;
                latestHistFile = hf;
              }
            }
          }
          if (latestHistFile) {
            priorRegistry = JSON.parse(fs.readFileSync(path.join(histDir, latestHistFile), 'utf8'));
            if (registry.registryVersion < priorRegistry.registryVersion) {
              throw new Error(
                `[REGISTRY_ROLLBACK_DETECTED] Cannot save version ${registry.registryVersion} over historical version ${priorRegistry.registryVersion}`
              );
            }
            if (Array.isArray(priorRegistry.revokedKeyIds)) {
              for (const revokedId of priorRegistry.revokedKeyIds) {
                if (!registry.revokedKeyIds.includes(revokedId)) {
                  throw new Error(`[REVOCATION_STRIP_VIOLATION] Cannot un-revoke previously revoked keyId '${revokedId}'`);
                }
              }
            }
            if (priorRegistry.revocationHighWaterMark) {
              if (!registry.revocationHighWaterMark) {
                throw new Error('[HIGH_WATER_MARK_STRIP_VIOLATION] Cannot strip previously established revocationHighWaterMark');
              }
              if (registry.revocationHighWaterMark.headIndex < priorRegistry.revocationHighWaterMark.headIndex) {
                throw new Error(`[HIGH_WATER_MARK_ROLLBACK_DETECTED] Cannot rollback revocation high-water mark from ${priorRegistry.revocationHighWaterMark.headIndex} to ${registry.revocationHighWaterMark.headIndex}`);
              }
            }
          }
        } catch (hErr) {
          if (
            hErr.message.includes('REGISTRY_ROLLBACK_DETECTED') ||
            hErr.message.includes('REVOCATION_STRIP_VIOLATION') ||
            hErr.message.includes('HIGH_WATER_MARK_STRIP_VIOLATION') ||
            hErr.message.includes('HIGH_WATER_MARK_ROLLBACK_DETECTED')
          ) {
            throw hErr;
          }
        }
      }
    }

    // Check against established revocations in dir (R06 hardening)
    const checkpointPath = getRevocationCheckpointPath(options);
    const journalPath = getRevocationJournalPath(options);
    let establishedHeadIndex = -1;
    if (fs.existsSync(checkpointPath)) {
      try {
        const cp = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
        if (typeof cp.headIndex === 'number' && cp.headIndex >= 0) {
          establishedHeadIndex = cp.headIndex;
        }
      } catch (_) {}
    }
    if (establishedHeadIndex < 0 && fs.existsSync(journalPath)) {
      try {
        const stat = fs.statSync(journalPath);
        if (stat.size > 0) establishedHeadIndex = 0;
      } catch (_) {}
    }

    if (establishedHeadIndex >= 0) {
      if (!registry.revocationHighWaterMark) {
        throw new Error(
          `[REGISTRY_ROLLBACK_DETECTED] Cannot save unadorned Genesis registry when revocations have been established (headIndex ${establishedHeadIndex})`
        );
      }
      if (registry.revocationHighWaterMark.headIndex < establishedHeadIndex) {
        throw new Error(
          `[HIGH_WATER_MARK_ROLLBACK_DETECTED] Cannot save registry high-water mark (${registry.revocationHighWaterMark.headIndex}) behind established checkpoint (${establishedHeadIndex})`
        );
      }
    }

    const validation = validateTrustRegistry(registry, { ...options, priorRegistry });
    if (!validation.valid) {
      throw new Error(`Cannot save invalid trust registry: ${validation.error}`);
    }

    const serialized = JSON.stringify(registry, null, 2) + '\n';
    safeWriteFileSync(regPath, serialized, options);

    // Maintain historical registry progression for unbroken ancestry verification (R05-B02)
    const histDir = path.join(dir, 'history');
    if (!fs.existsSync(histDir)) fs.mkdirSync(histDir, { recursive: true });
    safeWriteFileSync(path.join(histDir, `trust-registry.v${registry.registryVersion}.json`), serialized, options);
    if (priorRegistry && priorRegistry.registryVersion) {
      const priorHistPath = path.join(histDir, `trust-registry.v${priorRegistry.registryVersion}.json`);
      if (!fs.existsSync(priorHistPath)) {
        safeWriteFileSync(priorHistPath, JSON.stringify(priorRegistry, null, 2) + '\n', options);
      }
    }

    // Anchor current registry version into checkpoint for anti-tail-deletion anti-rollback (R08-B04)
    let cpData = {
      headIndex: establishedHeadIndex >= 0 ? establishedHeadIndex : -1,
      headDigest: '0'.repeat(64),
      updatedAt: new Date().toISOString(),
      registryVersion: registry.registryVersion
    };
    if (fs.existsSync(checkpointPath)) {
      try {
        const existingCp = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
        cpData = {
          ...existingCp,
          registryVersion: registry.registryVersion
        };
      } catch (_) {}
    }
    safeWriteFileSync(checkpointPath, JSON.stringify(cpData, null, 2) + '\n', options);

    return {
      success: true,
      path: normalizePath(regPath),
      registryVersion: registry.registryVersion
    };
  }, options);
}

/**
 * Loads and validates the hash-chained revocation journal from PLUGIN_DATA.
 * Resolves M54-P2-F01: Mandatory signature verification, root key verification,
 * and rollback/truncation detection via persistent checkpoint and trust registry high-water mark.
 *
 * @param {object} [options={}]
 * @returns {{ valid: boolean, entries: Array<object>, error: string|null, count: number }}
 */
function doLoadRevocationJournal(options = {}) {
  const journalPath = getRevocationJournalPath(options);
  const checkpointPath = getRevocationCheckpointPath(options);

  // Checkpoint audit (F01: Detect deletion / rollback)
  let checkpoint = null;
  if (fs.existsSync(checkpointPath)) {
    try {
      checkpoint = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
      if (typeof checkpoint.headIndex !== 'number' || typeof checkpoint.headDigest !== 'string') {
        const msg = `[CHECKPOINT_CORRUPTION_DETECTED] Checkpoint file missing headIndex or headDigest at ${checkpointPath}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
      }
    } catch (err) {
      const msg = `[CHECKPOINT_CORRUPTION_DETECTED] Failed to parse revocation checkpoint at ${checkpointPath}: ${err.message}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
  }

  // R04-B01: Query trust registry high-water mark
  const trustRegistryLoad = loadTrustRegistry({ ...options, failClosed: false, skipLock: true });
  const registryHwm = (trustRegistryLoad.valid && trustRegistryLoad.registry?.revocationHighWaterMark)
    ? trustRegistryLoad.registry.revocationHighWaterMark
    : null;

  if (!fs.existsSync(journalPath)) {
    if (checkpoint && checkpoint.headIndex >= 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but checkpoint records headIndex ${checkpoint.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    if (registryHwm && typeof registryHwm.headIndex === 'number' && registryHwm.headIndex >= 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but trust registry records revocation high-water mark headIndex ${registryHwm.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    if (typeof options.minJournalEntries === 'number' && options.minJournalEntries > 0) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal file missing but minJournalEntries is ${options.minJournalEntries}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }
    return { valid: true, entries: [], error: null, count: 0, path: journalPath };
  }

  try {
    const content = fs.readFileSync(journalPath, 'utf8');
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);

    // Rollback detection against checkpoint
    if (checkpoint && lines.length < checkpoint.headIndex + 1) {
      const msg = `[JOURNAL_TRUNCATION_DETECTED] Journal has ${lines.length} entries but checkpoint records headIndex ${checkpoint.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
    }

    // Uncommitted tail detection against checkpoint (R05-B03)
    if (checkpoint && lines.length > checkpoint.headIndex + 1) {
      const msg = `[JOURNAL_CORRUPTED_FAIL_CLOSED] [JOURNAL_UNCOMMITTED_TAIL_DETECTED] Journal has ${lines.length} entries exceeding checkpoint headIndex ${checkpoint.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    // Rollback detection against trust registry high-water mark (R04-B01)
    if (registryHwm && typeof registryHwm.headIndex === 'number' && lines.length < registryHwm.headIndex + 1) {
      const msg = `[JOURNAL_TRUNCATION_DETECTED] Journal has ${lines.length} entries but trust registry records headIndex ${registryHwm.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    // Uncommitted tail detection against trust registry high-water mark (R05-B03)
    if (registryHwm && typeof registryHwm.headIndex === 'number' && lines.length > registryHwm.headIndex + 1) {
      const msg = `[JOURNAL_CORRUPTED_FAIL_CLOSED] [JOURNAL_UNCOMMITTED_TAIL_DETECTED] Journal has ${lines.length} entries exceeding trust registry headIndex ${registryHwm.headIndex}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    if (checkpoint && registryHwm && typeof registryHwm.headIndex === 'number') {
      if (checkpoint.headIndex !== registryHwm.headIndex || checkpoint.headDigest !== registryHwm.headDigest) {
        const msg = `[CHECKPOINT_REGISTRY_DESYNC_DETECTED] Checkpoint (index ${checkpoint.headIndex}) desynchronized from trust registry high-water mark (index ${registryHwm.headIndex})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
      }
    }

    if (typeof options.minJournalEntries === 'number' && lines.length < options.minJournalEntries) {
      const msg = `[JOURNAL_ROLLBACK_DETECTED] Journal has ${lines.length} entries, less than expected minimum ${options.minJournalEntries}`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: lines.length, path: journalPath };
    }

    const trustedKeys = new Map();

    if (trustRegistryLoad.valid && trustRegistryLoad.registry) {
      for (const k of trustRegistryLoad.registry.keys || []) {
        if (['ACTIVE_PINNED_ROOT', 'ACTIVE', 'RETIRED'].includes(k.status)) {
          trustedKeys.set(k.keyId, k.publicKeyPem);
        }
      }
    }

    // Historical key lifecycle resolution: load historical public keys from history/
    const histDir = path.join(path.dirname(journalPath), 'history');
    if (fs.existsSync(histDir)) {
      try {
        const histFiles = fs.readdirSync(histDir).filter(f => /^trust-registry\.v(\d+)\.json$/.test(f));
        for (const hf of histFiles) {
          try {
            const hReg = JSON.parse(fs.readFileSync(path.join(histDir, hf), 'utf8'));
            for (const hk of hReg.keys || []) {
              if (hk.keyId && hk.publicKeyPem && !trustedKeys.has(hk.keyId)) {
                trustedKeys.set(hk.keyId, hk.publicKeyPem);
              }
            }
          } catch (_) {}
        }
      } catch (_) {}
    }

    // Always include genesis root anchor
    const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
    const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
    trustedKeys.set(rootId, rootPem);

    const entries = [];
    let expectedPrevDigest = '0'.repeat(64);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch (e) {
        const msg = `Malformed JSON in journal at line ${i + 1}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (parsed.entryIndex !== i) {
        const msg = `Index mismatch at line ${i + 1}: expected ${i}, found ${parsed.entryIndex}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (parsed.prevEntryDigest !== expectedPrevDigest) {
        const msg = `Tamper detected at line ${i + 1}: broken hash chain (expected ${expectedPrevDigest}, found ${parsed.prevEntryDigest})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      if (!parsed.targetId || typeof parsed.targetId !== 'string') {
        const msg = `Missing targetId at line ${i + 1}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      // Mandatory Ed25519 signature verification on read
      if (!parsed.signature || !parsed.signedBy) {
        const msg = `Unsigned revocation record detected at line ${i + 1} (targetId: ${parsed.targetId})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      const signerPem = trustedKeys.get(parsed.signedBy);
      if (!signerPem) {
        const msg = `Signer '${parsed.signedBy}' at line ${i + 1} is not a trusted supervisor key`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      const signPayload = Buffer.from(computeRevocationEntrySignPayload(parsed), 'utf8');
      const isValid = crypto.verify(null, signPayload, signerPem, Buffer.from(parsed.signature, 'hex'));
      if (!isValid) {
        const msg = `Signature verification failed for revocation record at line ${i + 1} (targetId: ${parsed.targetId})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: i };
      }

      entries.push(parsed);
      expectedPrevDigest = sha256Digest(canonicalJsonStringify(parsed));
    }

    // Verify head digest against checkpoint if available
    if (checkpoint && entries.length > 0 && expectedPrevDigest !== checkpoint.headDigest) {
      const msg = `[JOURNAL_HEAD_MISMATCH] Journal head digest does not match checkpoint headDigest`;
      if (options.failClosed !== false) throw new Error(msg);
      return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
    }

    // Verify head digest against trust registry high-water mark (R04-B01)
    if (
      registryHwm &&
      typeof registryHwm.headIndex === 'number' &&
      entries.length > registryHwm.headIndex
    ) {
      const entryAtHwm = entries[registryHwm.headIndex];
      const digestAtHwm = sha256Digest(canonicalJsonStringify(entryAtHwm));
      if (digestAtHwm !== registryHwm.headDigest) {
        const msg = `[JOURNAL_HEAD_MISMATCH] Journal entry at index ${registryHwm.headIndex} digest does not match trust registry high-water mark headDigest`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
      }
    }

    return { valid: true, entries, error: null, count: entries.length, path: journalPath };
  } catch (err) {
    if (options.failClosed !== false) {
      throw new Error(`Failed to load revocation journal: ${err.message}`);
    }
    return { valid: false, entries: [], error: err.message, count: 0 };
  }
}

/**
 * Loads and validates the hash-chained revocation journal from PLUGIN_DATA.
 * Resolves M54-P2-F01 and M54-P2-F04: Reader synchronization via withFileLock,
 * mandatory signature verification, root & retired key verification, and anti-rollback.
 * Resolves R04-B05: Readers acquire mutual exclusion even on non-existent journal file.
 *
 * @param {object} [options={}]
 * @returns {{ valid: boolean, entries: Array<object>, error: string|null, count: number }}
 */
export function loadRevocationJournal(options = {}) {
  if (options.skipLock === true) {
    recoverAbortedRevocationTransaction(options);
    return doLoadRevocationJournal(options);
  }
  return withGovernanceLock(options, () => {
    recoverAbortedRevocationTransaction(options);
    return doLoadRevocationJournal(options);
  });
}

/**
 * Appends an entry to the revocation journal with mandatory Ed25519 signature under mutual exclusion.
 * Resolves M54-P2-F01 and M54-P2-F04.
 * Resolves R04-B01 (Trust Registry High-Water Mark Anchor) and R04-B03 (Symlink/Hardlink Defense).
 * Resolves Round 07 F-03: Write-Ahead Transaction Journal (WAL) for atomic multi-file crash recovery.
 * Resolves Round 07 F-04: Executes under joint withGovernanceLock (.governance.lock).
 *
 * @param {object} entryInput
 * @param {string} entryInput.revocationType
 * @param {string} entryInput.targetId
 * @param {string} [entryInput.reason='MANUAL_REVOCATION']
 * @param {object} options
 * @param {KeyObject|string} options.signerPrivateKey - Mandatory signing private key
 * @param {string} [options.signerKeyId] - Key ID of signer
 * @returns {{ success: boolean, entryIndex: number, entryDigest: string, path: string }}
 */
export function appendRevocationEntry(entryInput, options = {}) {
  if (!entryInput || typeof entryInput !== 'object') {
    throw new Error('entryInput must be an object');
  }

  if (!entryInput.revocationType || !REVOCATION_TYPES[entryInput.revocationType]) {
    throw new Error(`Invalid revocationType: ${entryInput.revocationType}`);
  }

  if (!entryInput.targetId || typeof entryInput.targetId !== 'string') {
    throw new Error('targetId must be a non-empty string');
  }

  if (!options.signerPrivateKey) {
    throw new Error('[MANDATORY_SIGNATURE_REQUIRED] appendRevocationEntry requires options.signerPrivateKey (F01)');
  }

  const journalPath = getRevocationJournalPath(options);
  const checkpointPath = getRevocationCheckpointPath(options);
  const regPath = getTrustRegistryPath(options);
  const dir = path.dirname(journalPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

  return withGovernanceLock(options, () => {
    // Round 07 F-03: Recover any aborted transaction from previous crash
    recoverAbortedRevocationTransaction(options);

    // R04-B03: Check leaf files for symlink and hardlink pollution inside lock
    assertSafeStorageTarget(journalPath, options);
    assertSafeStorageTarget(checkpointPath, options);
    assertSafeStorageTarget(regPath, options);

    let regObj = null;
    if (fs.existsSync(regPath)) {
      const regLoad = loadTrustRegistry({ ...options, failClosed: true, skipLock: true });
      regObj = regLoad.registry;
    } else {
      const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
      const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
      const rootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
      regObj = {
        schemaVersion: '1.0.0',
        registryVersion: 1,
        authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
        activeKeyId: rootId,
        activeKeyFingerprint: rootFp,
        activePublicKeyPem: rootPem,
        keyType: 'ed25519',
        pinnedSince: new Date().toISOString(),
        rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
        revokedKeyIds: [],
        keys: [
          {
            keyId: rootId,
            keyFingerprint: rootFp,
            publicKeyPem: rootPem,
            status: 'ACTIVE_PINNED_ROOT',
            issuedAt: new Date().toISOString()
          }
        ]
      };
    }

    const signedBy = options.signerKeyId || (regObj ? regObj.activeKeyId : DEFAULT_SUPERVISOR_KEY_ID);

    // Validate signer authority for NEW writes (R06 hardening)
    if (regObj) {
      if (Array.isArray(regObj.revokedKeyIds) && regObj.revokedKeyIds.includes(signedBy)) {
        throw new Error(`[REVOKED_SIGNER_REJECTED] Signer '${signedBy}' has been revoked in trust registry`);
      }
      const signerKey = regObj.keys.find(k => k.keyId === signedBy);
      if (!signerKey) {
        throw new Error(`[UNKNOWN_SIGNER_REJECTED] Signer '${signedBy}' is not recognized in trust registry keys`);
      }
      if (signerKey.status !== 'ACTIVE_PINNED_ROOT' && signerKey.status !== 'ACTIVE') {
        throw new Error(`[INACTIVE_SIGNER_REJECTED] Signer '${signedBy}' has status '${signerKey.status}'; only ACTIVE or ACTIVE_PINNED_ROOT keys may issue new revocations`);
      }
      try {
        const testPayload = Buffer.from('three-lens-signer-verification', 'utf8');
        const testSig = crypto.sign(null, testPayload, options.signerPrivateKey);
        const matches = crypto.verify(null, testPayload, signerKey.publicKeyPem, testSig);
        if (!matches) {
          throw new Error('Key mismatch');
        }
      } catch (keyErr) {
        throw new Error(`[KEY_MISMATCH_REJECTED] options.signerPrivateKey does not match public key for '${signedBy}' in trust registry`);
      }
    }

    const journal = loadRevocationJournal({ ...options, failClosed: true, skipLock: true });
    const entryIndex = journal.entries.length;

    let prevEntryDigest = '0'.repeat(64);
    if (entryIndex > 0) {
      prevEntryDigest = sha256Digest(canonicalJsonStringify(journal.entries[entryIndex - 1]));
    }

    const timestamp = options.timestamp || new Date().toISOString();
    const reason = entryInput.reason || 'MANUAL_REVOCATION';

    const unsignedRecord = {
      entryIndex,
      timestamp,
      revocationType: entryInput.revocationType,
      targetId: entryInput.targetId,
      reason,
      prevEntryDigest,
      signedBy
    };

    const signPayload = Buffer.from(computeRevocationEntrySignPayload(unsignedRecord), 'utf8');
    const signature = crypto.sign(null, signPayload, options.signerPrivateKey).toString('hex');

    const record = {
      ...unsignedRecord,
      signature
    };

    const line = JSON.stringify(record) + '\n';

    // R05-B03 & Round 07 F-03: Full transactional multi-file snapshot & WAL marker for crash-safe rollback
    const initialJournalStat = fs.existsSync(journalPath) ? fs.statSync(journalPath) : null;
    const initialJournalSize = initialJournalStat ? initialJournalStat.size : 0;
    const initialJournalExisted = fs.existsSync(journalPath);
    const initialCheckpointRaw = fs.existsSync(checkpointPath) ? fs.readFileSync(checkpointPath) : null;
    const initialCheckpointExisted = fs.existsSync(checkpointPath);
    const initialRegistryRaw = fs.existsSync(regPath) ? fs.readFileSync(regPath) : null;
    const initialRegistryExisted = fs.existsSync(regPath);
    const regHistDir = path.join(path.dirname(regPath), 'history');
    const histPath = regObj ? path.join(regHistDir, `trust-registry.v${regObj.registryVersion}.json`) : null;
    const initialHistRaw = histPath && fs.existsSync(histPath) ? fs.readFileSync(histPath) : null;
    const initialHistExisted = histPath ? fs.existsSync(histPath) : false;

    const txnId = crypto.randomUUID();
    const txnPath = path.join(dir, REVOCATION_TXN_FILE);
    const txnData = {
      txnId,
      status: 'PREPARED',
      createdAt: new Date().toISOString(),
      journalPath,
      initialJournalSize,
      initialJournalExisted,
      checkpointPath,
      initialCheckpointRawBase64: initialCheckpointRaw ? initialCheckpointRaw.toString('base64') : null,
      initialCheckpointExisted,
      regPath,
      initialRegistryRawBase64: initialRegistryRaw ? initialRegistryRaw.toString('base64') : null,
      initialRegistryExisted,
      histPath,
      initialHistRawBase64: initialHistRaw ? initialHistRaw.toString('base64') : null,
      initialHistExisted
    };
    safeWriteFileSync(txnPath, JSON.stringify(txnData, null, 2) + '\n', options);

    try {
      // 1. Safe append to journal with descriptor inspection (R05-B04)
      const fd = safeOpenStorageFile(journalPath, 'a+', 0o600, options);
      try {
        fs.writeSync(fd, line, null, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      if (options._simulateFailureStage === 'POST_JOURNAL_APPEND') {
        throw new Error('[SIMULATED_FAILURE_POST_JOURNAL_APPEND]');
      }

      const entryDigest = sha256Digest(canonicalJsonStringify(record));

      // 2. Safe write checkpoint (R05-B04 & R08-B04)
      const checkpointData = {
        headIndex: entryIndex,
        headDigest: entryDigest,
        updatedAt: record.timestamp,
        registryVersion: regObj ? regObj.registryVersion : 1
      };
      safeWriteFileSync(checkpointPath, JSON.stringify(checkpointData, null, 2) + '\n', options);

      if (options._simulateFailureStage === 'POST_CHECKPOINT_WRITE') {
        throw new Error('[SIMULATED_FAILURE_POST_CHECKPOINT_WRITE]');
      }

      // 3. Anchor cryptographically signed revocation high-water mark into trust registry (R05-B01 & R05-B03)
      const hwmPayload = Buffer.from(canonicalJsonStringify({
        headIndex: entryIndex,
        headDigest: entryDigest,
        updatedAt: record.timestamp,
        authorizedBy: signedBy
      }), 'utf8');
      const hwmSignature = crypto.sign(null, hwmPayload, options.signerPrivateKey).toString('hex');

      regObj.revocationHighWaterMark = {
        headIndex: entryIndex,
        headDigest: entryDigest,
        updatedAt: record.timestamp,
        authorizedBy: signedBy,
        signature: hwmSignature
      };

      if (options._simulateFailureStage === 'REGISTRY_WRITE') {
        throw new Error('[SIMULATED_FAILURE_REGISTRY_WRITE]');
      }

      safeWriteFileSync(regPath, JSON.stringify(regObj, null, 2) + '\n', options);

      if (!fs.existsSync(regHistDir)) fs.mkdirSync(regHistDir, { recursive: true });
      safeWriteFileSync(path.join(regHistDir, `trust-registry.v${regObj.registryVersion}.json`), JSON.stringify(regObj, null, 2) + '\n', options);

      // Successfully committed: remove WAL marker
      try {
        if (fs.existsSync(txnPath)) fs.unlinkSync(txnPath);
      } catch (_) {}

      return {
        success: true,
        entryIndex,
        entryDigest,
        path: normalizePath(journalPath)
      };
    } catch (txErr) {
      // R05-B03 & Round 07 F-03: Complete transactional multi-file rollback
      try {
        if (initialJournalExisted) {
          fs.truncateSync(journalPath, initialJournalSize);
        } else if (fs.existsSync(journalPath)) {
          fs.unlinkSync(journalPath);
        }
        if (initialCheckpointRaw !== null) {
          fs.writeFileSync(checkpointPath, initialCheckpointRaw);
        } else if (fs.existsSync(checkpointPath)) {
          fs.unlinkSync(checkpointPath);
        }
        if (initialRegistryRaw !== null) {
          fs.writeFileSync(regPath, initialRegistryRaw);
        } else if (fs.existsSync(regPath)) {
          fs.unlinkSync(regPath);
        }
        if (initialHistRaw !== null && histPath) {
          fs.writeFileSync(histPath, initialHistRaw);
        } else if (histPath && fs.existsSync(histPath)) {
          fs.unlinkSync(histPath);
        }
        if (fs.existsSync(txnPath)) {
          fs.unlinkSync(txnPath);
        }
      } catch (rollbackErr) {
        try {
          txnData.status = 'CORRUPTED';
          txnData.rollbackError = rollbackErr.message;
          fs.writeFileSync(txnPath, JSON.stringify(txnData, null, 2), 'utf8');
        } catch (_) {}
        throw new Error(`[TRANSACTION_ROLLBACK_FAILED] Original: ${txErr.message}; Rollback: ${rollbackErr.message}`);
      }
      throw txErr;
    }
  }, options);
}

/**
 * Checks whether an ID (keyId, nonce, or ballot fingerprint) has been revoked.
 * Resolves R04-B01: Seamlessly anchors revocation high-water mark from trust registry
 * so dual-file deletion of journal and checkpoint fails closed.
 *
 * @param {string} targetId
 * @param {object} [options={}]
 * @returns {{ revoked: boolean, reason: string|null, entry: object|null }}
 */
export function isRevoked(targetId, options = {}) {
  if (!targetId || typeof targetId !== 'string') {
    return { revoked: false, reason: null, entry: null };
  }

  const regLoad = loadTrustRegistry({ ...options, failClosed: false });
  if (!regLoad.valid) {
    return {
      revoked: true,
      reason: `REGISTRY_CORRUPTED_FAIL_CLOSED: ${regLoad.error || 'unknown error'}`,
      entry: null
    };
  }

  if (regLoad.registry && Array.isArray(regLoad.registry.revokedKeyIds)) {
    if (regLoad.registry.revokedKeyIds.includes(targetId)) {
      return {
        revoked: true,
        reason: 'REVOKED_IN_TRUST_REGISTRY',
        entry: null
      };
    }
  }

  const journalOpts = { ...options, failClosed: false };
  if (
    regLoad.valid &&
    regLoad.registry?.revocationHighWaterMark &&
    typeof regLoad.registry.revocationHighWaterMark.headIndex === 'number'
  ) {
    journalOpts.minJournalEntries = regLoad.registry.revocationHighWaterMark.headIndex + 1;
    journalOpts.expectedHeadDigest = regLoad.registry.revocationHighWaterMark.headDigest;
  }

  let journalLoad;
  try {
    journalLoad = loadRevocationJournal(journalOpts);
  } catch (err) {
    journalLoad = { valid: false, error: err.message };
  }

  if (!journalLoad.valid) {
    return {
      revoked: true,
      reason: `JOURNAL_CORRUPTED_FAIL_CLOSED: ${journalLoad.error || 'unknown error'}`,
      entry: null
    };
  }

  for (const entry of journalLoad.entries) {
    if (entry.targetId === targetId) {
      return {
        revoked: true,
        reason: entry.reason || entry.revocationType,
        entry
      };
    }
  }

  return {
    revoked: false,
    reason: null,
    entry: null
  };
}
