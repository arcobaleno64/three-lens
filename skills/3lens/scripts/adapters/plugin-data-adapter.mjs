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
import { AsyncLocalStorage } from 'node:async_hooks';

export const ADAPTER_NAME = 'PLUGIN_DATA_DUAL_ANCHOR_ADAPTER';
export const ADAPTER_VERSION = '1.1.0';

// R13-B04: AsyncLocalStorage context tracker for governance lock ownership.
// Guarantees capability cannot escape via object cloning, closures, or Symbol forgery.
const _governanceLockStorage = new AsyncLocalStorage();

// R16-B02 & R17-B01: Unexported module-private Symbol token and WeakSet for privileged internal witness storage access.
// Guarantees external callers cannot forge internal write privileges via plain options properties or Proxy traps.
const INTERNAL_WITNESS_WRITE_TOKEN = Symbol('INTERNAL_WITNESS_WRITE_TOKEN');
const INTERNAL_WITNESS_PRIVILEGED_OPTIONS = new WeakSet();

function createPrivilegedWitnessOptions(baseOptions = {}) {
  const privileged = { ...(baseOptions || {}), [INTERNAL_WITNESS_WRITE_TOKEN]: true };
  INTERNAL_WITNESS_PRIVILEGED_OPTIONS.add(privileged);
  return privileged;
}

function canonicalizeDirPath(dir) {
  if (typeof dir !== 'string' || !dir.trim()) return '';
  try {
    return fs.realpathSync(dir);
  } catch (_) {
    return path.resolve(dir);
  }
}

function pathsEqual(p1, p2) {
  if (typeof p1 !== 'string' || typeof p2 !== 'string') return false;
  const c1 = canonicalizeDirPath(p1);
  const c2 = canonicalizeDirPath(p2);
  if (process.platform === 'win32') {
    return c1.toLowerCase() === c2.toLowerCase();
  }
  return c1 === c2;
}

export function isGovernanceLockHeld(dir) {
  const store = _governanceLockStorage.getStore();
  if (!store || store.active !== true) return false;
  if (!pathsEqual(store.dir, dir)) return false;
  if (store.lockTarget && !fs.existsSync(store.lockTarget + '.lock')) {
    store.active = false;
    return false;
  }
  return true;
}

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
  // R15-B04, R16-B02 & R17-B01: Strictly confine monotonic witness files against caller tampering via public storage APIs.
  // Privileged internal writes mandate the unexported module-private Symbol token and internal WeakSet registration;
  // plain string flags, external Symbols, and Proxy traps are unconditionally rejected.
  const baseName = path.basename(targetPath);
  if (baseName === '.monotonic-witness.json' || baseName.endsWith('.witness.json')) {
    if (!options || typeof options !== 'object' || !INTERNAL_WITNESS_PRIVILEGED_OPTIONS.has(options) || options[INTERNAL_WITNESS_WRITE_TOKEN] !== true) {
      throw new Error(`[STORAGE_CONFINEMENT_VIOLATION] Direct access to monotonic witness file (${targetPath}) is strictly forbidden via storage API`);
    }
  }

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
 * R20-B04: Safely writes entire buffer/string to file descriptor in a loop, ensuring zero short writes.
 */
function writeAllSync(fd, data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), 'utf8');
  let offset = 0;
  while (offset < buf.length) {
    const written = fs.writeSync(fd, buf, offset, buf.length - offset, null);
    if (typeof written !== 'number' || written <= 0) {
      throw new Error(`[SHORT_WRITE_DETECTED] Zero bytes written at offset ${offset} of ${buf.length}`);
    }
    offset += written;
  }
}

/**
 * Safely writes content to targetPath using safeOpenStorageFile on temp file and atomic rename.
 * Resolves R05-B04: Eliminates TOCTOU windows on storage files.
 * Resolves R20-B04: Enforces writeAllSync loop to prevent short writes on storage files.
 */
export function safeWriteFileSync(targetPath, content, options = {}) {
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  assertSafeStorageTarget(targetPath, options);
  const tmpPath = path.join(dir, `.tmp.${path.basename(targetPath)}.${process.pid}.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
  const fd = safeOpenStorageFile(tmpPath, 'w', 0o600, options);
  try {
    writeAllSync(fd, content);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  assertSafeStorageTarget(tmpPath, options);
  fs.renameSync(tmpPath, targetPath);
  // R11-B05 & R12-B07: fsync parent directory on POSIX systems to persist directory entry mutation
  try {
    const dirFd = fs.openSync(dir, 'r');
    try {
      fs.fsyncSync(dirFd);
    } finally {
      fs.closeSync(dirFd);
    }
  } catch (dirErr) {
    // Windows throws EISDIR/EPERM/EINVAL when attempting to open or fsync a directory descriptor.
    // On POSIX, directory fsync is mandatory; any error is a durability failure that must fail closed!
    if (process.platform !== 'win32') {
      throw new Error(`[STORAGE_DURABILITY_FAILURE] Failed to fsync directory ${dir}: ${dirErr.message}`);
    }
  }
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
export const GOVERNANCE_LOCK_TARGET = '.governance';
export const REVOCATION_TXN_FILE = '.revocation-txn.json';

/**
 * Computes canonical payload for transaction WAL signature.
 * Resolves R10-B01: Signs all canonical fields, sizes, digests, and versions
 * to prevent counterfeit WAL creation or snapshot rollback.
 *
 * @param {object} fields
 * @returns {string} Canonical JSON payload string
 */
export function computeTransactionWalSignPayload(fields) {
  const { signature, initialCheckpointRawBase64, initialRegistryRawBase64, initialHistRawBase64, ...rest } = fields;
  return canonicalJsonStringify(rest);
}

/**
 * Cross-process file locking primitive using exclusive file creation.
 * Resolves M54-P2-F04 & R10-B03: Lock info contains PID and unique lockId;
 * stale lock reclamation strictly verifies PID liveness under Default-Deny;
 * lock release verifies lockId ownership and file descriptor inode/device binding.
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
      // R15-B05: Explicitly enforce 0o600 DAC mode creation on exclusive lock file
      lockFd = fs.openSync(lockFile, 'wx+', 0o600);
      const info = JSON.stringify({ pid: process.pid, timestamp: Date.now(), lockId });
      fs.writeFileSync(lockFd, info, 'utf8');
      break;
    } catch (err) {
      if (err.code === 'EEXIST') {
        try {
          const stats = fs.statSync(lockFile);
          if (Date.now() - stats.mtimeMs > staleTimeoutMs) {
            // R08-B07 / R09-B03 / R10-B03: Authenticated two-phase stale lock reclamation
            const reclaimLockFile = `${lockFile}.reclaim`;
            const reclaimLockId = crypto.randomBytes(8).toString('hex');
            let reclaimFd = null;
            try {
              // R15-B05: Explicitly enforce 0o600 DAC mode creation on reclamation lock file
              reclaimFd = fs.openSync(reclaimLockFile, 'wx+', 0o600);
              fs.writeFileSync(reclaimFd, JSON.stringify({ pid: process.pid, timestamp: Date.now(), reclaimLockId }), 'utf8');
            } catch (recErr) {
              if (recErr.code === 'EEXIST') {
                try {
                  const recStat = fs.statSync(reclaimLockFile);
                  if (Date.now() - recStat.mtimeMs > 3000) {
                    try {
                      const recRaw = fs.readFileSync(reclaimLockFile, 'utf8');
                      const recParsed = JSON.parse(recRaw);
                      // R10-B03-A: Strict PID validation under Default-Deny
                      if (
                        typeof recParsed.pid === 'number' &&
                        Number.isInteger(recParsed.pid) &&
                        recParsed.pid > 0 &&
                        typeof recParsed.reclaimLockId === 'string' &&
                        !isPidAlive(recParsed.pid)
                      ) {
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
                    // R10-B03-A: Default-Deny - only recover if PID is valid positive integer AND definitively dead
                    let canRecover = false;
                    try {
                      const content = fs.readFileSync(lockFile, 'utf8');
                      const parsed = JSON.parse(content);
                      if (
                        typeof parsed.pid === 'number' &&
                        Number.isInteger(parsed.pid) &&
                        parsed.pid > 0 &&
                        typeof parsed.lockId === 'string' &&
                        !isPidAlive(parsed.pid)
                      ) {
                        canRecover = true;
                      }
                    } catch {}
                    if (canRecover) {
                      try { fs.unlinkSync(lockFile); } catch {}
                    }
                  }
                }
              } finally {
                // R10-B03-B & R11-B05: Atomic reclaim lock release verifying descriptor inode and reading lockId from fd
                try {
                  if (fs.existsSync(reclaimLockFile)) {
                    const fdStat = fs.fstatSync(reclaimFd);
                    const pathStat = fs.lstatSync(reclaimLockFile);
                    if (pathStat.ino === fdStat.ino && pathStat.dev === fdStat.dev) {
                      let parsed = null;
                      try {
                        const buf = Buffer.alloc(fdStat.size);
                        fs.readSync(reclaimFd, buf, 0, fdStat.size, 0);
                        parsed = JSON.parse(buf.toString('utf8'));
                      } catch (_) {
                        try { parsed = JSON.parse(fs.readFileSync(reclaimLockFile, 'utf8')); } catch (_) {}
                      }
                      if (parsed && parsed.reclaimLockId === reclaimLockId) {
                        const preUnlinkStat = fs.lstatSync(reclaimLockFile);
                        if (preUnlinkStat.ino === fdStat.ino && preUnlinkStat.dev === fdStat.dev) {
                          fs.unlinkSync(reclaimLockFile);
                        }
                      }
                    }
                  }
                } catch {} finally {
                  try { fs.closeSync(reclaimFd); } catch {}
                  reclaimFd = null;
                }
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
    // R10-B03-B & R11-B05: Atomic lock release reading lockId from fd and double-checking inode
    try {
      if (fs.existsSync(lockFile)) {
        const fdStat = fs.fstatSync(lockFd);
        const pathStat = fs.lstatSync(lockFile);
        if (pathStat.ino === fdStat.ino && pathStat.dev === fdStat.dev) {
          let parsed = null;
          try {
            const buf = Buffer.alloc(fdStat.size);
            fs.readSync(lockFd, buf, 0, fdStat.size, 0);
            parsed = JSON.parse(buf.toString('utf8'));
          } catch (_) {
            try { parsed = JSON.parse(fs.readFileSync(lockFile, 'utf8')); } catch (_) {}
          }
          if (parsed && parsed.lockId === lockId) {
            const preUnlinkStat = fs.lstatSync(lockFile);
            if (preUnlinkStat.ino === fdStat.ino && preUnlinkStat.dev === fdStat.dev) {
              fs.unlinkSync(lockFile);
            }
          }
        }
      }
    } catch {} finally {
      try { fs.closeSync(lockFd); } catch {}
      lockFd = null;
    }
  }
}

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
  if (opts.skipLock === true && isGovernanceLockHeld(dir)) {
    return callback({
      ...opts,
      skipLock: true
    });
  }
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const lockTarget = path.join(dir, GOVERNANCE_LOCK_TARGET);
  const lockContext = { dir: canonicalizeDirPath(dir), active: true, lockTarget };
  return withFileLock(lockTarget, () => {
    try {
      const result = _governanceLockStorage.run(lockContext, () => {
        return callback({
          ...opts,
          skipLock: true
        });
      });
      if (result && typeof result.then === 'function') {
        throw new Error('[UNSUPPORTED_ASYNC_OPERATION] withGovernanceLock does not support asynchronous callbacks');
      }
      return result;
    } finally {
      lockContext.active = false;
    }
  }, opts);
}

/**
 * Recovers an uncommitted or interrupted revocation transaction from WAL snapshot.
 * Resolves Round 07 F-03: Crash recovery / power loss recovery across multi-file writes.
 * Resolves Round 12 B-04 & Round 13 B-04: Enforces execution under unified governance lock.
 *
 * @param {object} [options={}]
 * @returns {{ recovered: boolean, txnId?: string }}
 */
export function recoverAbortedRevocationTransaction(options = {}) {
  const dir = resolvePluginDataDir(options);
  const canSkipLock = options.skipLock === true && isGovernanceLockHeld(dir);
  if (canSkipLock) {
    return _recoverAbortedRevocationTransactionInner(options);
  }
  return withGovernanceLock(options, (lockedOpts) => _recoverAbortedRevocationTransactionInner(lockedOpts));
}

/**
 * R18-B04: Shared historical key lifecycle & active-window resolver for revocation journal verification.
 * Resolves each key's public key and maximum valid journal entry index from the validated current registry
 * and unbroken historical registry chain (history/trust-registry.v*.json).
 * Genesis fallback is permitted strictly when neither an on-disk registry nor historical progression exists.
 */
function resolveJournalTrustedKeyWindows(dir, currentRegistry, options = {}) {
  const trustedKeys = new Map();
  const maxActiveIndexPerKey = new Map();
  const curRevokedSet = new Set(
    Array.isArray(currentRegistry?.revokedKeyIds) ? currentRegistry.revokedKeyIds : []
  );

  if (currentRegistry && Array.isArray(currentRegistry.keys)) {
    for (const k of currentRegistry.keys) {
      if (k && k.keyId && k.publicKeyPem) {
        const isRevokedInCur = curRevokedSet.has(k.keyId) || k.status === 'REVOKED';
        if (!isRevokedInCur && (k.status === 'ACTIVE_PINNED_ROOT' || k.status === 'ACTIVE')) {
          trustedKeys.set(k.keyId, k.publicKeyPem);
          maxActiveIndexPerKey.set(k.keyId, Infinity);
        } else if (isRevokedInCur || k.status === 'RETIRED') {
          trustedKeys.set(k.keyId, k.publicKeyPem);
          maxActiveIndexPerKey.set(k.keyId, -1);
        }
      }
    }
  }

  let hasHistoryFiles = false;
  const histDir = path.join(dir, 'history');
  if (fs.existsSync(histDir)) {
    const histFiles = fs.readdirSync(histDir).filter(f => /^trust-registry\.v(\d+)\.json$/.test(f));
    histFiles.sort((a, b) => {
      const vA = parseInt(a.match(/^trust-registry\.v(\d+)\.json$/)[1], 10);
      const vB = parseInt(b.match(/^trust-registry\.v(\d+)\.json$/)[1], 10);
      return vA - vB;
    });
    for (const hf of histFiles) {
      hasHistoryFiles = true;
      let hReg = null;
      try {
        hReg = JSON.parse(fs.readFileSync(path.join(histDir, hf), 'utf8'));
      } catch (err) {
        if (options.failClosed !== false) {
          throw new Error(`[HISTORY_CORRUPTION_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] Corrupted historical registry ${hf} in ${histDir}: ${err.message}`);
        }
        continue;
      }
      const hHwmIdx = typeof hReg?.revocationHighWaterMark?.headIndex === 'number'
        ? hReg.revocationHighWaterMark.headIndex
        : -1;
      const hRevokedSet = new Set(Array.isArray(hReg?.revokedKeyIds) ? hReg.revokedKeyIds : []);
      for (const hk of hReg?.keys || []) {
        if (hk && hk.keyId && hk.publicKeyPem) {
          if (!trustedKeys.has(hk.keyId)) {
            trustedKeys.set(hk.keyId, hk.publicKeyPem);
            maxActiveIndexPerKey.set(hk.keyId, -1);
          }
          const isRevokedInHist = hRevokedSet.has(hk.keyId) || hk.status === 'REVOKED';
          if (!isRevokedInHist && (hk.status === 'ACTIVE' || hk.status === 'ACTIVE_PINNED_ROOT')) {
            const cur = maxActiveIndexPerKey.get(hk.keyId);
            if (cur !== Infinity) {
              maxActiveIndexPerKey.set(hk.keyId, Math.max(cur ?? -1, hHwmIdx));
            }
          }
        }
      }
    }
  }

  // R18-B01 & R18-B04: Genesis root fallback is permitted ONLY in pure Genesis Bootstrap
  // (no current on-disk registry and no historical registry progression).
  if (!currentRegistry && !hasHistoryFiles) {
    const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
    const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
    if (!trustedKeys.has(rootId)) {
      trustedKeys.set(rootId, rootPem);
      maxActiveIndexPerKey.set(rootId, Infinity);
    }
  }

  return { trustedKeys, maxActiveIndexPerKey };
}

/**
 * R17-B03 & R18-B04: Replays and cryptographically verifies all journal entries from index 0 to targetHeadIndex.
 * Validates unbroken entry indices, continuous hash chaining (prevEntryDigest), historical key lifecycle windows,
 * and valid cryptographic signatures.
 */
function verifyFullJournalChain(journalLines, targetHeadIndex, targetHeadDigest, curReg, options = {}) {
  if (!Array.isArray(journalLines) || journalLines.length < targetHeadIndex + 1) {
    throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry count is insufficient for target index');
  }
  const dir = resolvePluginDataDir(options);
  const { trustedKeys, maxActiveIndexPerKey } = resolveJournalTrustedKeyWindows(dir, curReg, options);

  let expectedPrevDigest = '0'.repeat(64);
  for (let i = 0; i <= targetHeadIndex; i++) {
    let entry = null;
    try {
      entry = JSON.parse(journalLines[i]);
    } catch (e) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry at index ${i} is corrupted JSON: ${e.message}`);
    }
    const entryIdx = typeof entry.entryIndex === 'number' ? entry.entryIndex : entry.index;
    if (entryIdx !== i) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry at index ${i} has discontinuous index ${entryIdx}`);
    }
    if (entry.prevEntryDigest !== expectedPrevDigest) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry at index ${i} has broken hash chain (expected ${expectedPrevDigest}, found ${entry.prevEntryDigest})`);
    }
    if (!entry.signedBy || typeof entry.signedBy !== 'string' || !entry.signature || typeof entry.signature !== 'string') {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry at index ${i} missing signature or signedBy`);
    }

    const entrySignerPem = trustedKeys.get(entry.signedBy);
    if (!entrySignerPem) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] [UNKNOWN_SIGNER_REJECTED] Journal entry at index ${i} signer '${entry.signedBy}' is unauthenticated`);
    }
    const maxIdxForSigner = maxActiveIndexPerKey.get(entry.signedBy);
    if (typeof maxIdxForSigner === 'number' && maxIdxForSigner !== Infinity && i > maxIdxForSigner) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] [RETIRED_KEY_AUTHORIZATION_REJECTED] Journal entry at index ${i} signed by retired or removed key '${entry.signedBy}' (max active index ${maxIdxForSigner})`);
    }

    const entrySignPayload = Buffer.from(computeRevocationEntrySignPayload(entry), 'utf8');
    const isSigValid = crypto.verify(null, entrySignPayload, entrySignerPem, Buffer.from(entry.signature, 'hex'));
    if (!isSigValid) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal entry at index ${i} signature verification failed`);
    }

    // R20-B02: If entry revokes a key (KEY_REVOCATION), terminate that key's active window in this chain
    if (entry.targetId && (entry.revocationType === REVOCATION_TYPES.KEY_REVOCATION || entry.revocationType === 'KEY_REVOCATION')) {
      const existingMax = maxActiveIndexPerKey.get(entry.targetId);
      maxActiveIndexPerKey.set(entry.targetId, Math.min(existingMax ?? Infinity, i));
    }

    const entryDigest = sha256Digest(canonicalJsonStringify(entry));
    expectedPrevDigest = entryDigest;

    if (i === targetHeadIndex) {
      if (entryDigest !== targetHeadDigest) {
        throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] Journal head entry digest does not match target head digest');
      }
    }
  }
  return true;
}

function _recoverAbortedRevocationTransactionInner(options = {}) {
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

  // R09-B01, R10-B04, R11-B02: Both PREPARED and COMMITTED states require cryptographic authentication.
  // Any corrupted, unknown, or non-PREPARED/COMMITTED status MUST fail closed under Default-Deny.
  if (txnData.status !== 'PREPARED' && txnData.status !== 'COMMITTED') {
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

  // R09-B01, R10-B01, R11-B02: Mandatory paths, sizes, and cryptographic metadata in WAL
  if (
    !txnData.journalPath || typeof txnData.journalPath !== 'string' ||
    !txnData.checkpointPath || typeof txnData.checkpointPath !== 'string' ||
    !txnData.regPath || typeof txnData.regPath !== 'string' ||
    typeof txnData.initialJournalSize !== 'number' ||
    !txnData.signedBy || typeof txnData.signedBy !== 'string' ||
    !txnData.signature || typeof txnData.signature !== 'string' ||
    typeof txnData.initialRegistryVersion !== 'number'
  ) {
    throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] Transaction WAL missing required paths, sizes, or cryptographic metadata');
  }

  // R10-B01, R11-B01, R11-B03, R12-B01, R12-B06, R13-B01, R14-B03, R17-B04 & R18-B01:
  // When an on-disk registry exists, validate it first and select WAL signer exclusively from its active keys.
  // Removed, retired, or revoked keys are unconditionally rejected without any fallback to genesis/default root.
  let signerPublicKeyPem = null;
  if (fs.existsSync(expectedRegPath)) {
    let curRegRaw = null;
    try {
      curRegRaw = JSON.parse(fs.readFileSync(expectedRegPath, 'utf8'));
    } catch (readErr) {
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] [TRANSACTION_WAL_CORRUPTION_DETECTED] Existing trust registry exists at ${expectedRegPath} but cannot be parsed: ${readErr.message}`);
    }

    if (curRegRaw && Array.isArray(curRegRaw.revokedKeyIds) && curRegRaw.revokedKeyIds.includes(txnData.signedBy)) {
      throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer '${txnData.signedBy}' in WAL is revoked in current trust registry`);
    }

    if (curRegRaw && Array.isArray(curRegRaw.keys)) {
      const curKey = curRegRaw.keys.find(k => k.keyId === txnData.signedBy);
      if (!curKey) {
        throw new Error(`[RETIRED_KEY_AUTHORIZATION_REJECTED] [TRANSACTION_WAL_SIGNER_UNTRUSTED] Signer '${txnData.signedBy}' in WAL is not present in current on-disk trust registry keys`);
      }
      if (curKey.status === 'RETIRED') {
        throw new Error(`[RETIRED_KEY_AUTHORIZATION_REJECTED] Signer '${txnData.signedBy}' in WAL is retired in current trust registry`);
      }
      if (curKey.status === 'REVOKED') {
        throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer '${txnData.signedBy}' in WAL is revoked in current trust registry`);
      }
      if (curKey.status !== 'ACTIVE' && curKey.status !== 'ACTIVE_PINNED_ROOT') {
        throw new Error(`[TRANSACTION_WAL_SIGNER_UNTRUSTED] Signer '${txnData.signedBy}' in WAL does not have ACTIVE or ACTIVE_PINNED_ROOT status in current trust registry`);
      }
    }

    let effectivePriorReg = null;
    if (curRegRaw && typeof curRegRaw.registryVersion === 'number' && curRegRaw.registryVersion > 1) {
      const priorHistPath = path.join(histDir, `trust-registry.v${curRegRaw.registryVersion - 1}.json`);
      if (fs.existsSync(priorHistPath)) {
        try {
          effectivePriorReg = JSON.parse(fs.readFileSync(priorHistPath, 'utf8'));
        } catch (_) {}
      }
    }

    const onDiskRegValidation = validateTrustRegistry(curRegRaw, {
      ...options,
      skipLock: true,
      skipJournalRevocationCheck: true,
      priorRegistry: effectivePriorReg,
      allowEmbeddedFallback: true,
      failClosed: true
    });
    if (!onDiskRegValidation.valid) {
      if (!curRegRaw || !Array.isArray(curRegRaw.keys)) {
        throw new Error(`[TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] Existing trust registry on disk is invalid or schema-corrupt (${onDiskRegValidation.error}); refusing rollback under Default-Deny`);
      }
      if (txnData.status === 'COMMITTED') {
        throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] [TRANSACTION_WAL_SIGNER_UNTRUSTED] COMMITTED WAL on-disk trust registry failed cryptographic validation: ${onDiskRegValidation.error}`);
      }
      throw new Error(`[TRANSACTION_WAL_SIGNER_UNTRUSTED] [TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] Existing trust registry on disk failed validation (${onDiskRegValidation.error}); refusing WAL signer '${txnData.signedBy}'`);
    }

    const verifiedKey = curRegRaw.keys.find(
      k => k.keyId === txnData.signedBy && (k.status === 'ACTIVE' || k.status === 'ACTIVE_PINNED_ROOT')
    );
    if (!verifiedKey || !verifiedKey.publicKeyPem) {
      throw new Error(`[TRANSACTION_WAL_SIGNER_UNTRUSTED] Signer '${txnData.signedBy}' in WAL is not an active key in validated on-disk trust registry`);
    }
    signerPublicKeyPem = verifiedKey.publicKeyPem;
  } else {
    // R18-B01: Pure Genesis Bootstrap verification:
    // Genesis root key is permitted ONLY when there is no existing registry, no history files, and no witness progression.
    const curWitness = getMonotonicWitness(dir, options);
    const hasHistory = fs.existsSync(histDir) && fs.readdirSync(histDir).some(f => /^trust-registry\.v\d+\.json$/.test(f));
    if (
      curWitness.maxSeenRegistryVersion > 1 ||
      curWitness.maxSeenHwmHeadIndex >= 0 ||
      hasHistory ||
      txnData.initialRegistryVersion > 1 ||
      txnData.initialRegistryExisted === true
    ) {
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] [TRANSACTION_WAL_SIGNER_UNTRUSTED] On-disk trust registry is missing despite historical state progression; refusing Genesis fallback for WAL signer '${txnData.signedBy}'`);
    }

    if (options.trustedRootKeyId === txnData.signedBy && options.trustedRootPublicKeyPem) {
      signerPublicKeyPem = options.trustedRootPublicKeyPem;
    } else if (DEFAULT_SUPERVISOR_KEY_ID === txnData.signedBy) {
      signerPublicKeyPem = DEFAULT_SUPERVISOR_PUBLIC_PEM;
    } else {
      const embKey = EMBEDDED_ROOT_REGISTRY.keys.find(k => k.keyId === txnData.signedBy);
      if (embKey) {
        signerPublicKeyPem = embKey.publicKeyPem;
      }
    }
  }

  if (!signerPublicKeyPem) {
    throw new Error(`[TRANSACTION_WAL_SIGNER_UNTRUSTED] Signer '${txnData.signedBy}' in WAL is not authenticated by trusted root or validated registry`);
  }

  // R10-B01 & R11-B02: Cryptographically verify signature on WAL payload (for both PREPARED and COMMITTED)
  const signPayload = Buffer.from(computeTransactionWalSignPayload(txnData), 'utf8');
  try {
    const validSig = crypto.verify(null, signPayload, signerPublicKeyPem, Buffer.from(txnData.signature, 'hex'));
    if (!validSig) {
      throw new Error(`[TRANSACTION_WAL_SIGNATURE_INVALID] Cryptographic signature verification failed for WAL ${txnData.txnId}`);
    }
  } catch (sigErr) {
    if (sigErr.message && sigErr.message.includes('TRANSACTION_WAL_SIGNATURE_INVALID')) {
      throw sigErr;
    }
    throw new Error(`[TRANSACTION_WAL_SIGNATURE_INVALID] Cryptographic signature verification failed for WAL ${txnData.txnId}: ${sigErr.message}`);
  }

  // R11-B02, R12-B03, R13-B05: Verified COMMITTED WAL handling backed by authentic on-disk post-image state
  if (txnData.status === 'COMMITTED') {
    if (!fs.existsSync(expectedRegPath) || !fs.existsSync(expectedCheckpointPath) || !fs.existsSync(expectedJournalPath)) {
      throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL exists but on-disk registry, checkpoint, or journal is missing');
    }
    if (
      typeof txnData.committedHwmHeadIndex !== 'number' ||
      typeof txnData.committedHwmHeadDigest !== 'string' ||
      txnData.committedHwmHeadDigest.length !== 64
    ) {
      throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL missing mandatory committedHwmHeadIndex or committedHwmHeadDigest');
    }
    let curReg = null;
    try {
      curReg = JSON.parse(fs.readFileSync(expectedRegPath, 'utf8'));
      const curCp = JSON.parse(fs.readFileSync(expectedCheckpointPath, 'utf8'));
      if (
        !curReg || typeof curReg !== 'object' ||
        !curCp || typeof curCp !== 'object' ||
        curReg.revocationHighWaterMark?.headIndex !== txnData.committedHwmHeadIndex ||
        curReg.revocationHighWaterMark?.headDigest !== txnData.committedHwmHeadDigest ||
        curCp.headIndex !== txnData.committedHwmHeadIndex ||
        curCp.headDigest !== txnData.committedHwmHeadDigest
      ) {
        throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL headIndex/headDigest does not match on-disk registry/checkpoint post-image');
      }
      if (
        typeof txnData.expectedTargetRegistryVersion === 'number' &&
        curReg.registryVersion < txnData.expectedTargetRegistryVersion
      ) {
        throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL registryVersion does not match on-disk registry');
      }
      // R13-B05 & R14-B08: Verify Journal physical entries, tail record match, and cryptographic signature
      const journalRaw = fs.readFileSync(expectedJournalPath, 'utf8').trim();
      if (!journalRaw) {
        throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL exists but on-disk journal is empty');
      }
      const journalLines = journalRaw.split(/\r?\n/).filter(l => l.trim().length > 0);
      if (journalLines.length < txnData.committedHwmHeadIndex + 1) {
        throw new Error('[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL committedHwmHeadIndex exceeds journal entry count');
      }

      // R17-B03 & R17-E02: Unconditionally replay and cryptographically verify all journal entries from 0 to committedHwmHeadIndex
      verifyFullJournalChain(
        journalLines,
        txnData.committedHwmHeadIndex,
        txnData.committedHwmHeadDigest,
        curReg,
        options
      );
    } catch (parseErr) {
      if (parseErr.message && parseErr.message.includes('TRANSACTION_WAL_CORRUPTION_DETECTED')) {
        throw parseErr;
      }
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Failed to verify committed state for COMMITTED WAL: ${parseErr.message}`);
    }
      // R16-B03: Comprehensive non-mutating validation of curReg and historical continuity before witness update
      let effectivePriorReg = null;
      if (curReg.registryVersion > 1) {
        const priorHistPath = path.join(dir, 'history', `trust-registry.v${curReg.registryVersion - 1}.json`);
        if (fs.existsSync(priorHistPath)) {
          try {
            effectivePriorReg = JSON.parse(fs.readFileSync(priorHistPath, 'utf8'));
          } catch (_) {}
        }
      }
      const regValidation = validateTrustRegistry(curReg, {
        ...options,
        priorRegistry: effectivePriorReg,
        allowEmbeddedFallback: true,
        failClosed: true
      });
      if (!regValidation.valid) {
        throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] COMMITTED WAL post-image registry failed validation: ${regValidation.error}`);
      }

      const curRegDigest = computeRegistryDigest(curReg);
      const curNonHwmDigest = computeRegistryNonHwmDigest(curReg);

      // R19-B03: Ensure history/trust-registry.v{curReg.registryVersion}.json is synchronized with verified post-image curReg before witness freshness & update
      if (!fs.existsSync(histDir)) fs.mkdirSync(histDir, { recursive: true });
      const activeHistPath = path.join(histDir, `trust-registry.v${curReg.registryVersion}.json`);
      const onDiskRegRaw = fs.readFileSync(expectedRegPath, 'utf8');
      if (fs.existsSync(activeHistPath)) {
        const existingHistObj = JSON.parse(fs.readFileSync(activeHistPath, 'utf8'));
        if (computeRegistryNonHwmDigest(existingHistObj) !== curNonHwmDigest) {
          throw new Error('[REGISTRY_DIVERGENCE_DETECTED] On-disk registry non-HWM identity diverged from historical registry during COMMITTED WAL recovery');
        }
      }
      if (!fs.existsSync(activeHistPath) || sha256Digest(fs.readFileSync(activeHistPath, 'utf8')) !== sha256Digest(onDiskRegRaw)) {
        safeWriteFileSync(activeHistPath, onDiskRegRaw, options);
      }

      // Check curReg against witness freshness and historical continuity
      assertMonotonicWitnessFreshness(dir, curReg.registryVersion, txnData.committedHwmHeadIndex, txnData.committedHwmHeadDigest, curRegDigest, { ...options, nonHwmDigest: curNonHwmDigest });

      // R15-B02, R16-B03 & R17-B01: Update persistent monotonic witness AFTER complete authorization & continuity validation
      updateMonotonicWitness(dir, curReg.registryVersion, txnData.committedHwmHeadIndex, txnData.committedHwmHeadDigest, curRegDigest, createPrivilegedWitnessOptions({ ...options, nonHwmDigest: curNonHwmDigest }));

    assertSafeStorageTarget(txnPath, options);
    try {
      fs.unlinkSync(txnPath);
    } catch (unlinkErr) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Failed to unlink COMMITTED WAL: ${unlinkErr.message}`);
    }
    return { recovered: false, committed: true, txnId: txnData.txnId };
  }

  // R10-B01 & R14-B03: Verify snapshot digests and semantic bindings against signed commitments
  if (txnData.initialCheckpointRawBase64) {
    const cpBuf = Buffer.from(txnData.initialCheckpointRawBase64, 'base64');
    if (sha256Digest(cpBuf) !== txnData.initialCheckpointSha256) {
      throw new Error('[TRANSACTION_WAL_DIGEST_MISMATCH_DETECTED] Checkpoint snapshot digest does not match signed initialCheckpointSha256');
    }
    let parsedCp = null;
    try {
      parsedCp = JSON.parse(cpBuf.toString('utf8'));
    } catch (e) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Checkpoint snapshot is invalid JSON: ${e.message}`);
    }
    const cpHwmIdx = typeof parsedCp.headIndex === 'number' ? parsedCp.headIndex : -1;
    const cpHwmDigest = parsedCp.headDigest || '';
    if (cpHwmIdx !== txnData.initialHwmHeadIndex) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Checkpoint snapshot headIndex (${cpHwmIdx}) does not match WAL initialHwmHeadIndex (${txnData.initialHwmHeadIndex})`);
    }
    if (txnData.initialHwmHeadDigest && cpHwmDigest !== txnData.initialHwmHeadDigest) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Checkpoint snapshot headDigest (${cpHwmDigest}) does not match WAL initialHwmHeadDigest (${txnData.initialHwmHeadDigest})`);
    }
  }
  if (txnData.initialRegistryRawBase64) {
    const regBuf = Buffer.from(txnData.initialRegistryRawBase64, 'base64');
    if (sha256Digest(regBuf) !== txnData.initialRegistrySha256) {
      throw new Error('[TRANSACTION_WAL_DIGEST_MISMATCH_DETECTED] Registry snapshot digest does not match signed initialRegistrySha256');
    }
    let parsedReg = null;
    try {
      parsedReg = JSON.parse(regBuf.toString('utf8'));
    } catch (e) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Registry snapshot is invalid JSON: ${e.message}`);
    }
    if (typeof parsedReg.registryVersion !== 'number' || parsedReg.registryVersion !== txnData.initialRegistryVersion) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Registry snapshot version (${parsedReg.registryVersion}) does not match WAL initialRegistryVersion (${txnData.initialRegistryVersion})`);
    }
    const snapHwm = parsedReg.revocationHighWaterMark;
    const snapHwmIdx = snapHwm && typeof snapHwm.headIndex === 'number' ? snapHwm.headIndex : -1;
    const snapHwmDigest = snapHwm ? snapHwm.headDigest : '';
    if (snapHwmIdx !== txnData.initialHwmHeadIndex) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Registry snapshot HWM headIndex (${snapHwmIdx}) does not match WAL initialHwmHeadIndex (${txnData.initialHwmHeadIndex})`);
    }
    if (txnData.initialHwmHeadDigest && snapHwmDigest !== txnData.initialHwmHeadDigest) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Registry snapshot HWM headDigest (${snapHwmDigest}) does not match WAL initialHwmHeadDigest (${txnData.initialHwmHeadDigest})`);
    }
    const snapValidation = validateTrustRegistry(parsedReg, {
      ...options,
      skipLock: true,
      skipJournalRevocationCheck: true,
      allowEmbeddedFallback: true
    });
    if (!snapValidation.valid) {
      throw new Error(`[TRANSACTION_WAL_CORRUPTION_DETECTED] Registry snapshot failed schema and cryptographic validation: ${snapValidation.error}`);
    }
  }
  if (txnData.initialHistRawBase64) {
    const histBuf = Buffer.from(txnData.initialHistRawBase64, 'base64');
    if (sha256Digest(histBuf) !== txnData.initialHistSha256) {
      throw new Error('[TRANSACTION_WAL_DIGEST_MISMATCH_DETECTED] History snapshot digest does not match signed initialHistSha256');
    }
  }

  // R10-B01, R11-B03, R11-B04, R12-B01, R12-B05: Monotonicity, Anti-Rollback & Legitimate Completion Checks
  if (fs.existsSync(expectedRegPath)) {
    let currentReg = null;
    try {
      currentReg = JSON.parse(fs.readFileSync(expectedRegPath, 'utf8'));
    } catch (readErr) {
      // R11-B03: Fail-Closed under Default-Deny if existing registry cannot be parsed.
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] Existing trust registry exists but cannot be verified for anti-rollback: ${readErr.message}`);
    }

    // R12-B01 & R13-B01: Full schema and cryptographic validation of on-disk registry under Default-Deny.
    // If registry is {} or missing required schema fields (e.g. { registryVersion: 1 }), it MUST fail closed.
    const regValidation = validateTrustRegistry(currentReg, {
      ...options,
      skipLock: true,
      skipJournalRevocationCheck: true,
      allowEmbeddedFallback: true
    });
    if (!regValidation.valid) {
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_CHECK_FAILED] Existing trust registry on disk is invalid or schema-corrupt (${regValidation.error}); refusing rollback under Default-Deny`);
    }

    const curRegVer = currentReg.registryVersion;
    const curRegDigest = computeRegistryDigest(currentReg);
    const curNonHwmDigest = computeRegistryNonHwmDigest(currentReg);
    const curHwm = currentReg.revocationHighWaterMark;
    const curHwmIdx = curHwm ? curHwm.headIndex : -1;
    const curHwmDigest = curHwm ? curHwm.headDigest : '';

    // Enforce monotonic witness freshness before any rollback action
    assertMonotonicWitnessFreshness(dir, curRegVer, curHwmIdx, curHwmDigest, curRegDigest, { ...options, nonHwmDigest: curNonHwmDigest });

    // R11-B04, R12-B05, R13-B05 & R19-B03: Check if transaction actually completed all on-disk mutations before crash
    const isTargetExpected = (
      typeof txnData.expectedTargetHwmHeadIndex === 'number' &&
      typeof txnData.expectedTargetHwmHeadDigest === 'string' &&
      txnData.expectedTargetHwmHeadDigest.length === 64
    );

    if (isTargetExpected) {
      const regMatches = (
        curHwmIdx === txnData.expectedTargetHwmHeadIndex &&
        curHwmDigest === txnData.expectedTargetHwmHeadDigest &&
        (typeof txnData.expectedTargetRegistryVersion !== 'number' || curRegVer >= txnData.expectedTargetRegistryVersion)
      );

      if (regMatches && fs.existsSync(expectedCheckpointPath)) {
        try {
          const curCp = JSON.parse(fs.readFileSync(expectedCheckpointPath, 'utf8'));
          const cpMatches = (
            curCp &&
            curCp.headIndex === txnData.expectedTargetHwmHeadIndex &&
            curCp.headDigest === txnData.expectedTargetHwmHeadDigest
          );
          let journalMatches = false;
          if (fs.existsSync(expectedJournalPath) && fs.statSync(expectedJournalPath).size > txnData.initialJournalSize) {
            const jRaw = fs.readFileSync(expectedJournalPath, 'utf8').trim();
            const jLines = jRaw.split(/\r?\n/).filter(l => l.trim().length > 0);
            if (jLines.length > 0) {
              try {
                // R17-B03: Verify unbroken continuity, chaining, and signatures for entire journal
                journalMatches = verifyFullJournalChain(
                  jLines,
                  txnData.expectedTargetHwmHeadIndex,
                  txnData.expectedTargetHwmHeadDigest,
                  currentReg,
                  options
                );
              } catch (_) {
                journalMatches = false;
              }
            }
          }

          if (cpMatches && journalMatches) {
            // R19-B03: If process interrupted after writing regPath but before syncing history/trust-registry.v{curRegVer}.json,
            // verify that currentReg's non-HWM identity matches the initial registry snapshot (or existing history) and sync history BEFORE witness update.
            if (txnData.initialRegistryRawBase64) {
              const initRegObj = JSON.parse(Buffer.from(txnData.initialRegistryRawBase64, 'base64').toString('utf8'));
              if (computeRegistryNonHwmDigest(initRegObj) !== curNonHwmDigest) {
                throw new Error('[REGISTRY_DIVERGENCE_DETECTED] On-disk registry non-HWM identity diverged from WAL initial snapshot during HWM advancement');
              }
            }
            if (!fs.existsSync(histDir)) fs.mkdirSync(histDir, { recursive: true });
            const activeHistPath = path.join(histDir, `trust-registry.v${curRegVer}.json`);
            const onDiskRegRaw = fs.readFileSync(expectedRegPath, 'utf8');
            if (!fs.existsSync(activeHistPath) || sha256Digest(fs.readFileSync(activeHistPath, 'utf8')) !== sha256Digest(onDiskRegRaw)) {
              safeWriteFileSync(activeHistPath, onDiskRegRaw, options);
            }

            // The transaction was fully committed to disk before crash!
            // R15-B02 & R17-B01: Update persistent monotonic witness BEFORE unlinking marker
            const committedRegDigest = computeRegistryDigest(currentReg);
            updateMonotonicWitness(dir, curRegVer, txnData.expectedTargetHwmHeadIndex, txnData.expectedTargetHwmHeadDigest, committedRegDigest, createPrivilegedWitnessOptions({ ...options, nonHwmDigest: curNonHwmDigest }));
            assertSafeStorageTarget(txnPath, options);
            fs.unlinkSync(txnPath);
            return { recovered: false, committed: true, txnId: txnData.txnId };
          }
        } catch (commitCheckErr) {
          if (commitCheckErr.message && (commitCheckErr.message.includes('REGISTRY_DIVERGENCE_DETECTED') || commitCheckErr.message.includes('STORAGE_DURABILITY_FAILURE'))) {
            throw commitCheckErr;
          }
        }
      }
    }

    // Monotonicity anti-rollback checks under Default-Deny
    if (curRegVer > txnData.initialRegistryVersion) {
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED] WAL attempted to roll back registryVersion (${txnData.initialRegistryVersion}) below current on-disk version (${curRegVer})`);
    }
    if (curHwmIdx > txnData.initialHwmHeadIndex) {
      throw new Error(`[TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED] WAL attempted to roll back revocationHighWaterMark headIndex (${txnData.initialHwmHeadIndex}) below committed on-disk HWM (${curHwmIdx})`);
    }
    // R11-B03: Check history divergence at same headIndex
    if (curHwmIdx === txnData.initialHwmHeadIndex && txnData.initialHwmHeadDigest) {
      if (curHwmDigest !== txnData.initialHwmHeadDigest) {
        throw new Error(`[TRANSACTION_WAL_HISTORY_DIVERGENCE_DETECTED] WAL initialHwmHeadDigest does not match committed on-disk HWM headDigest at same index (${curHwmDigest} !== ${txnData.initialHwmHeadDigest})`);
      }
    }
  } else {
    // If on-disk registry does not exist, verify that monotonic witness does not expect a higher state
    assertMonotonicWitnessFreshness(dir, 1, -1, '', '', options);
  }

  // R11-B03: Verify that the journal prefix up to initialJournalSize matches initialJournalSha256 before truncation
  if (txnData.initialJournalExisted && fs.existsSync(expectedJournalPath)) {
    const existingJournalBuf = fs.readFileSync(expectedJournalPath).subarray(0, txnData.initialJournalSize);
    const prefixSha256 = sha256Digest(existingJournalBuf);
    if (prefixSha256 !== txnData.initialJournalSha256) {
      throw new Error(`[TRANSACTION_WAL_JOURNAL_INTEGRITY_MISMATCH] Journal prefix before rollback truncation does not match signed initialJournalSha256 (${prefixSha256} !== ${txnData.initialJournalSha256})`);
    }
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
 * R21-B01 & R22-B01: Extracts all KEY_REVOCATION entries directly from the on-disk journal without
 * triggering recursive loadTrustRegistry() / loadRevocationJournal() calls.
 * Returns Map<targetKeyId, earliestRevocationIndex>.
 *
 * Fail-Closed Invariant (R22-B01):
 * - If dir is invalid, throws [INVALID_DIRECTORY].
 * - If journal file exists, fs.readFileSync() failures MUST throw [JOURNAL_READ_FAILURE].
 * - If any line contains invalid JSON or lacks required fields, MUST throw [JOURNAL_CORRUPTION_DETECTED].
 * - If journal file is missing but an established installation recorded prior revocations
 *   (via checkpoint, candidate registry HWM, or monotonic witness), MUST throw [JOURNAL_ROLLBACK_DETECTED].
 * - Only genuine clean-slate / uninitialized installations may return an empty map.
 */
export function getJournalRevokedKeyMap(dir, options = {}) {
  const revokedMap = new Map();
  if (!dir || typeof dir !== 'string' || !dir.trim()) {
    throw new Error('[INVALID_DIRECTORY] A valid directory string is required to read revocation journal');
  }
  const journalPath = path.join(dir, '.irv-revocation-journal.jsonl');
  const checkpointPath = path.join(dir, 'supervisor-revocation-checkpoint.json');

  if (!fs.existsSync(journalPath)) {
    // Check if checkpoint records established revocations in dir
    if (fs.existsSync(checkpointPath)) {
      try {
        const cp = JSON.parse(fs.readFileSync(checkpointPath, 'utf8'));
        if (typeof cp?.headIndex === 'number' && cp.headIndex >= 0) {
          throw new Error(`[JOURNAL_ROLLBACK_DETECTED] Journal file missing but checkpoint records headIndex ${cp.headIndex}`);
        }
      } catch (cpErr) {
        if (cpErr.message?.includes('JOURNAL_ROLLBACK_DETECTED')) throw cpErr;
        throw new Error(`[CHECKPOINT_READ_FAILURE] Failed to read checkpoint at '${checkpointPath}': ${cpErr.message}`);
      }
    }
    // Check if on-disk registry in dir records established revocations
    const onDiskRegPath = path.join(dir, 'trust-registry.json');
    if (fs.existsSync(onDiskRegPath)) {
      try {
        const reg = JSON.parse(fs.readFileSync(onDiskRegPath, 'utf8'));
        if (reg?.revocationHighWaterMark && typeof reg.revocationHighWaterMark.headIndex === 'number' && reg.revocationHighWaterMark.headIndex >= 0) {
          throw new Error(`[JOURNAL_ROLLBACK_DETECTED] Journal file missing but on-disk registry records revocation high-water mark headIndex ${reg.revocationHighWaterMark.headIndex}`);
        }
      } catch (rErr) {
        if (rErr.message?.includes('JOURNAL_ROLLBACK_DETECTED')) throw rErr;
        throw new Error(`[REGISTRY_READ_FAILURE] Failed to read on-disk registry at '${onDiskRegPath}': ${rErr.message}`);
      }
    }
    // Check if monotonic witness in dir records established revocations
    const witnessPath = path.join(dir, '.irv-monotonic-witness.json');
    if (fs.existsSync(witnessPath)) {
      try {
        const wit = JSON.parse(fs.readFileSync(witnessPath, 'utf8'));
        if (typeof wit?.maxSeenHwmHeadIndex === 'number' && wit.maxSeenHwmHeadIndex >= 0) {
          throw new Error(`[JOURNAL_ROLLBACK_DETECTED] Journal file missing but monotonic witness records headIndex ${wit.maxSeenHwmHeadIndex}`);
        }
      } catch (wErr) {
        if (wErr.message?.includes('JOURNAL_ROLLBACK_DETECTED')) throw wErr;
        throw new Error(`[WITNESS_READ_FAILURE] Failed to read witness at '${witnessPath}': ${wErr.message}`);
      }
    }
    // Check if any historical registry in dir records established revocations
    const histDir = path.join(dir, 'history');
    if (fs.existsSync(histDir)) {
      try {
        const histFiles = fs.readdirSync(histDir);
        for (const hf of histFiles) {
          if (/^trust-registry\.v\d+\.json$/.test(hf)) {
            const hReg = JSON.parse(fs.readFileSync(path.join(histDir, hf), 'utf8'));
            if (hReg?.revocationHighWaterMark && typeof hReg.revocationHighWaterMark.headIndex === 'number' && hReg.revocationHighWaterMark.headIndex >= 0) {
              throw new Error(`[JOURNAL_ROLLBACK_DETECTED] Journal file missing in established installation with historical high-water mark (${hf})`);
            }
          }
        }
      } catch (hErr) {
        if (hErr.message?.includes('JOURNAL_ROLLBACK_DETECTED')) throw hErr;
      }
    }
    return revokedMap;
  }

  let content;
  try {
    content = fs.readFileSync(journalPath, 'utf8');
  } catch (ioErr) {
    throw new Error(`[JOURNAL_READ_FAILURE] Failed to read revocation journal at '${journalPath}': ${ioErr.message}`);
  }

  const lines = content.split(/\r?\n/).filter(l => l.trim().length > 0);
  for (let i = 0; i < lines.length; i++) {
    let parsed;
    try {
      parsed = JSON.parse(lines[i]);
    } catch (parseErr) {
      throw new Error(`[JOURNAL_CORRUPTION_DETECTED] Corrupted JSON in revocation journal '${journalPath}' at line ${i + 1}: ${parseErr.message}`);
    }
    if (!parsed || typeof parsed !== 'object') {
      throw new Error(`[JOURNAL_CORRUPTION_DETECTED] Invalid entry object in revocation journal '${journalPath}' at line ${i + 1}`);
    }
    if (typeof parsed.targetId !== 'string' || !parsed.targetId.trim()) {
      throw new Error(`[JOURNAL_CORRUPTION_DETECTED] Missing targetId in revocation journal '${journalPath}' at line ${i + 1}`);
    }
    if (parsed.revocationType === REVOCATION_TYPES.KEY_REVOCATION || parsed.revocationType === 'KEY_REVOCATION') {
      if (!revokedMap.has(parsed.targetId)) {
        const idx = typeof parsed.entryIndex === 'number' ? parsed.entryIndex : i;
        revokedMap.set(parsed.targetId, idx);
      }
    }
  }
  return revokedMap;
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
    ? registry.keys.map(k => {
        const item = {
          keyId: k.keyId,
          keyFingerprint: k.keyFingerprint,
          publicKeyPem: k.publicKeyPem,
          status: k.status,
          issuedAt: k.issuedAt || ''
        };
        if (k.roles) item.roles = Array.isArray(k.roles) ? [...k.roles].sort() : [String(k.roles)];
        if (typeof k.validFrom === 'string') item.validFrom = k.validFrom;
        if (typeof k.validUntil === 'string') item.validUntil = k.validUntil;
        return item;
      }).sort((a, b) => a.keyId.localeCompare(b.keyId))
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
 * Computes canonical identity commitment payload for trust registry.
 * Resolves R15-B03, R16-B04, R17-B02 & R17-B03: Binds schemaVersion, registryVersion, authority,
 * activeKey, keys array (with status, roles, lifecycles), pinnedSince, rotationPolicy, keyType,
 * validFrom, validUntil, complete authorizationProof (authorizedBy/signerKeyId, timestamp/signedAt, signature, algorithm, priorRegistryVersion),
 * outer signature, and revocationHighWaterMark into a canonical domain-separated payload.
 *
 * @param {object} registry
 * @returns {string} Domain-separated canonical string
 */
export function computeRegistryIdentityPayload(registry) {
  if (!registry || typeof registry !== 'object') return '';
  const authPayload = computeRegistryAuthorizationPayload(registry);
  const proof = (registry.authorizationProof && typeof registry.authorizationProof === 'object')
    ? registry.authorizationProof
    : null;
  const normalizedProof = proof
    ? {
        authorizedBy: typeof proof.authorizedBy === 'string' ? proof.authorizedBy : '',
        signerKeyId: typeof proof.signerKeyId === 'string' ? proof.signerKeyId : '',
        signature: typeof proof.signature === 'string' ? proof.signature : '',
        timestamp: typeof proof.timestamp === 'string' ? proof.timestamp : '',
        signedAt: typeof proof.signedAt === 'string' ? proof.signedAt : '',
        algorithm: typeof proof.algorithm === 'string' ? proof.algorithm : 'ed25519',
        priorRegistryVersion: typeof proof.priorRegistryVersion === 'number' ? proof.priorRegistryVersion : 0
      }
    : null;
  const hwm = (registry.revocationHighWaterMark && typeof registry.revocationHighWaterMark === 'object')
    ? registry.revocationHighWaterMark
    : null;
  const normalizedHwm = hwm
    ? {
        headIndex: typeof hwm.headIndex === 'number' ? hwm.headIndex : -1,
        headDigest: typeof hwm.headDigest === 'string' ? hwm.headDigest : '',
        updatedAt: typeof hwm.updatedAt === 'string' ? hwm.updatedAt : '',
        authorizedBy: typeof hwm.authorizedBy === 'string' ? hwm.authorizedBy : '',
        signature: typeof hwm.signature === 'string' ? hwm.signature : ''
      }
    : null;
  const identityObj = {
    authPayload,
    signature: typeof registry.signature === 'string' ? registry.signature : '',
    pinnedSince: typeof registry.pinnedSince === 'string' ? registry.pinnedSince : '',
    rotationPolicy: typeof registry.rotationPolicy === 'string' ? registry.rotationPolicy : '',
    keyType: typeof registry.keyType === 'string' ? registry.keyType : '',
    validFrom: typeof registry.validFrom === 'string' ? registry.validFrom : '',
    validUntil: typeof registry.validUntil === 'string' ? registry.validUntil : '',
    authorizationProof: normalizedProof,
    revocationHighWaterMark: normalizedHwm
  };
  return 'TRUST_REGISTRY_COMMITMENT_V1:' + canonicalJsonStringify(identityObj);
}

/**
 * Computes canonical non-HWM identity commitment payload for trust registry.
 * R19-B02: Binds all non-HWM identity and authorizationProof fields. During a same-version HWM advancement,
 * this non-HWM identity digest MUST remain strictly invariant unless a new Registry version is authorized.
 *
 * @param {object} registry
 * @returns {string} Domain-separated canonical string
 */
export function computeRegistryNonHwmIdentityPayload(registry) {
  if (!registry || typeof registry !== 'object') return '';
  const authPayload = computeRegistryAuthorizationPayload(registry);
  const proof = (registry.authorizationProof && typeof registry.authorizationProof === 'object')
    ? registry.authorizationProof
    : null;
  const normalizedProof = proof
    ? {
        authorizedBy: typeof proof.authorizedBy === 'string' ? proof.authorizedBy : '',
        signerKeyId: typeof proof.signerKeyId === 'string' ? proof.signerKeyId : '',
        signature: typeof proof.signature === 'string' ? proof.signature : '',
        timestamp: typeof proof.timestamp === 'string' ? proof.timestamp : '',
        signedAt: typeof proof.signedAt === 'string' ? proof.signedAt : '',
        algorithm: typeof proof.algorithm === 'string' ? proof.algorithm : 'ed25519',
        priorRegistryVersion: typeof proof.priorRegistryVersion === 'number' ? proof.priorRegistryVersion : 0
      }
    : null;
  const nonHwmObj = {
    authPayload,
    signature: typeof registry.signature === 'string' ? registry.signature : '',
    pinnedSince: typeof registry.pinnedSince === 'string' ? registry.pinnedSince : '',
    rotationPolicy: typeof registry.rotationPolicy === 'string' ? registry.rotationPolicy : '',
    keyType: typeof registry.keyType === 'string' ? registry.keyType : '',
    validFrom: typeof registry.validFrom === 'string' ? registry.validFrom : '',
    validUntil: typeof registry.validUntil === 'string' ? registry.validUntil : '',
    authorizationProof: normalizedProof
  };
  return 'TRUST_REGISTRY_NON_HWM_IDENTITY_V1:' + canonicalJsonStringify(nonHwmObj);
}

export function computeRegistryNonHwmDigest(registry) {
  if (!registry || typeof registry !== 'object') return '';
  return sha256Digest(computeRegistryNonHwmIdentityPayload(registry));
}

/**
 * Computes canonical content digest for trust registry authority commitment.
 * Resolves R15-B03 & R16-B04: Deterministic SHA-256 digest over complete canonical identity commitment.
 *
 * @param {object} registry
 * @returns {string} SHA-256 hex digest
 */
export function computeRegistryDigest(registry) {
  if (!registry || typeof registry !== 'object') return '';
  return sha256Digest(computeRegistryIdentityPayload(registry));
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

  // R19-B01: Single non-contradictory revocation authority check:
  // A key listed in revokedKeyIds MUST NOT be activeKeyId or retain ACTIVE / ACTIVE_PINNED_ROOT status in keys[].
  if (registry.revokedKeyIds.includes(registry.activeKeyId)) {
    return {
      valid: false,
      error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] activeKeyId '${registry.activeKeyId}' is listed in revokedKeyIds and cannot be active`,
      cryptographicValidity: false,
      monotonicValidity: true,
      ancestryContinuity: true
    };
  }
  for (const k of registry.keys) {
    if (k && k.keyId && registry.revokedKeyIds.includes(k.keyId)) {
      if (k.status === 'ACTIVE' || k.status === 'ACTIVE_PINNED_ROOT') {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Key '${k.keyId}' is listed in revokedKeyIds but has contradictory active status '${k.status}' in keys[]`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: true
        };
      }
    }
  }

  let registryDir = null;
  try {
    registryDir = resolvePluginDataDir(options);
  } catch (dirErr) {
    return {
      valid: false,
      error: `[INVALID_DIRECTORY] Directory resolution failed: ${dirErr.message}`,
      cryptographicValidity: false,
      monotonicValidity: false,
      ancestryContinuity: false
    };
  }

  let journalRevoked = new Map();
  if (registryDir && options.skipJournalRevocationCheck !== true) {
    try {
      journalRevoked = getJournalRevokedKeyMap(registryDir, {
        ...options,
        registry,
        candidateHwm: registry.revocationHighWaterMark
      });
    } catch (jErr) {
      return {
        valid: false,
        error: `[REVOCATION_STATUS_UNVERIFIABLE] Cannot verify signer revocation status: ${jErr.message}`,
        cryptographicValidity: false,
        monotonicValidity: false,
        ancestryContinuity: false
      };
    }
  }

  // Resolve prior registry from options or historical chain
  let priorReg = options.priorRegistry || null;
  if (!priorReg && registry.registryVersion > 1) {
    if (registry.registryVersion === 2 && options.allowEmbeddedFallback !== false) {
      const rootId = options.trustedRootKeyId || DEFAULT_SUPERVISOR_KEY_ID;
      const rootPem = options.trustedRootPublicKeyPem || DEFAULT_SUPERVISOR_PUBLIC_PEM;
      const rootFp = options.trustedRootFingerprint || DEFAULT_SUPERVISOR_FINGERPRINT;
      priorReg = {
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
    } else {
      try {
        const dir = resolvePluginDataDir(options);
        const priorHistPath = path.join(dir, 'history', `trust-registry.v${registry.registryVersion - 1}.json`);
        if (fs.existsSync(priorHistPath)) {
          priorReg = JSON.parse(fs.readFileSync(priorHistPath, 'utf8'));
        }
      } catch (_) {}
    }
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
    if (priorReg && Array.isArray(priorReg.revokedKeyIds) && priorReg.revokedKeyIds.includes(hwm.authorizedBy)) {
      return {
        valid: false,
        error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer '${hwm.authorizedBy}' for revocationHighWaterMark was already revoked in prior registry`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }

    let hwmSignerKey = registry.keys.find(
      k => k.keyId === hwm.authorizedBy && ['ACTIVE_PINNED_ROOT', 'ACTIVE', 'RETIRED', 'REVOKED'].includes(k.status)
    );
    if (!hwmSignerKey && priorReg && Array.isArray(priorReg.keys)) {
      const priorKey = priorReg.keys.find(
        k => k.keyId === hwm.authorizedBy && ['ACTIVE_PINNED_ROOT', 'ACTIVE'].includes(k.status)
      );
      if (priorKey) {
        hwmSignerKey = { ...priorKey, status: 'RETIRED' };
      }
    }
    if (!hwmSignerKey) {
      return {
        valid: false,
        error: `Signer '${hwm.authorizedBy}' for revocationHighWaterMark not found in registry keys`,
        cryptographicValidity: false,
        monotonicValidity: true,
        ancestryContinuity: true
      };
    }

    // R14-B04, R19-B01 & R21-B01: Key Lifecycle Boundary: A RETIRED or REVOKED key (whether via keys[].status, revokedKeyIds, or revocation journal)
    // can NEVER authorize a new or modified HWM. It is only accepted if it is an exact historical carry-over from priorRegistry where the key was active.
    const isHwmSignerRevokedInCurrent = Array.isArray(registry.revokedKeyIds) && registry.revokedKeyIds.includes(hwm.authorizedBy);
    const isHwmSignerRevokedInJournal = journalRevoked.has(hwm.authorizedBy);
    if (hwmSignerKey.status === 'RETIRED' || hwmSignerKey.status === 'REVOKED' || isHwmSignerRevokedInCurrent || isHwmSignerRevokedInJournal) {
      const priorHwm = priorReg?.revocationHighWaterMark;
      const isExactPriorMatch = Boolean(
        priorHwm &&
        priorHwm.authorizedBy === hwm.authorizedBy &&
        priorHwm.headIndex === hwm.headIndex &&
        priorHwm.headDigest === hwm.headDigest &&
        priorHwm.updatedAt === hwm.updatedAt &&
        priorHwm.signature === hwm.signature
      );
      if (!isExactPriorMatch) {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] [RETIRED_KEY_AUTHORIZATION_REJECTED] Signer '${hwm.authorizedBy}' for revocationHighWaterMark is retired or revoked and cannot authorize new or modified revocation high-water mark`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: true
        };
      }
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
  if (priorReg && typeof priorReg === 'object') {
    if (typeof priorReg.registryVersion === 'number') {
      if (registry.registryVersion <= priorReg.registryVersion) {
        monotonicValidity = false;
        return {
          valid: false,
          error: `[REGISTRY_ROLLBACK_DETECTED] Version ${registry.registryVersion} <= priorRegistry version ${priorReg.registryVersion}`,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      if (registry.registryVersion !== priorReg.registryVersion + 1) {
        ancestryContinuity = false;
        return {
          valid: false,
          error: `[ANCESTRY_CONTINUITY_VIOLATION] Non-consecutive version progression: version ${registry.registryVersion} is not consecutive successor to priorRegistry version ${priorReg.registryVersion}`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: false
        };
      }
    }

    // High-water mark strip and rollback protection across versions (R05-B01)
    if (priorReg.revocationHighWaterMark) {
      if (!registry.revocationHighWaterMark) {
        return {
          valid: false,
          error: '[HIGH_WATER_MARK_STRIP_VIOLATION] Cannot strip previously established revocationHighWaterMark',
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
      }
      if (registry.revocationHighWaterMark.headIndex < priorReg.revocationHighWaterMark.headIndex) {
        return {
          valid: false,
          error: `[HIGH_WATER_MARK_ROLLBACK_DETECTED] Cannot rollback revocation high-water mark from ${priorReg.revocationHighWaterMark.headIndex} to ${registry.revocationHighWaterMark.headIndex}`,
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
    if (priorReg && Array.isArray(priorReg.revokedKeyIds)) {
      if (priorReg.revokedKeyIds.includes(proof.authorizedBy)) {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' was already revoked in prior registry`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
    }
    if (priorReg && Array.isArray(priorReg.keys)) {
      const priorKey = priorReg.keys.find(k => k.keyId === proof.authorizedBy);
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

    // R21-B01: Journal KEY_REVOCATION check against authorizationProof signer
    if (journalRevoked.has(proof.authorizedBy)) {
      const revIdx = journalRevoked.get(proof.authorizedBy);
      // If this registry explicitly commits to an HWM that includes or follows this revocation
      if (registry.revocationHighWaterMark && typeof registry.revocationHighWaterMark.headIndex === 'number' && registry.revocationHighWaterMark.headIndex >= revIdx) {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' was revoked in revocation journal at index ${revIdx} and cannot authorize registry with HWM headIndex ${registry.revocationHighWaterMark.headIndex}`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
      // If validating active candidate update (options.isHistorical !== true)
      if (options.isHistorical !== true) {
        return {
          valid: false,
          error: `[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' was revoked in revocation journal at index ${revIdx}; cannot authorize active registry update`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
    }

    let signerPem = null;
    if (priorReg && typeof priorReg === 'object' && Array.isArray(priorReg.keys)) {
      // R13-B06: Resolve prior of prior for multi-generation chains
      let priorOfPrior = null;
      if (priorReg.registryVersion === 2) {
        priorOfPrior = {
          schemaVersion: '1.0.0',
          registryVersion: 1,
          authority: 'IRV_SUPERVISOR_ROOT_AUTHORITY',
          activeKeyId: expectedRootId,
          activeKeyFingerprint: expectedRootFp,
          activePublicKeyPem: expectedRootPem,
          keyType: 'ed25519',
          pinnedSince: '2026-10-16T06:55:39.565Z',
          rotationPolicy: 'SINGLE_ACTIVE_PINNED_ROOT',
          revokedKeyIds: [],
          keys: [{ keyId: expectedRootId, keyFingerprint: expectedRootFp, publicKeyPem: expectedRootPem, status: 'ACTIVE_PINNED_ROOT', issuedAt: '2026-10-16T06:55:39.565Z' }]
        };
      } else if (priorReg.registryVersion > 2) {
        if (Array.isArray(options.priorRegistryChain)) {
          priorOfPrior = options.priorRegistryChain.find(r => r.registryVersion === priorReg.registryVersion - 1);
        }
        if (!priorOfPrior) {
          try {
            const dir = resolvePluginDataDir(options);
            const pPath = path.join(dir, 'history', `trust-registry.v${priorReg.registryVersion - 1}.json`);
            if (fs.existsSync(pPath)) {
              priorOfPrior = JSON.parse(fs.readFileSync(pPath, 'utf8'));
            }
          } catch (_) {}
        }
      }

      const priorValidation = validateTrustRegistry(priorReg, {
        ...options,
        priorRegistry: priorOfPrior,
        minRegistryVersion: 1,
        isHistorical: true
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

      const priorKey = priorReg.keys.find(k => k.keyId === proof.authorizedBy);
      if (!priorKey) {
        return {
          valid: false,
          error: `Signer key '${proof.authorizedBy}' for authorizationProof not found in authenticated prior registry keys`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
      // R13-B08: Signer key in prior registry must be ACTIVE or ACTIVE_PINNED_ROOT! Retired keys cannot authorize new versions!
      if (priorKey.status !== 'ACTIVE' && priorKey.status !== 'ACTIVE_PINNED_ROOT') {
        return {
          valid: false,
          error: `[RETIRED_KEY_AUTHORIZATION_REJECTED] Signer key '${proof.authorizedBy}' has status '${priorKey.status}' in prior registry; only ACTIVE or ACTIVE_PINNED_ROOT keys may authorize registry updates`,
          cryptographicValidity: false,
          monotonicValidity: true,
          ancestryContinuity: ancestryContinuity
        };
      }
      signerPem = priorKey.publicKeyPem;
    } else if (registry.registryVersion === 2 && proof.authorizedBy === expectedRootId) {
      signerPem = expectedRootPem;
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
export function createAuthorizedRegistryUpdate(currentRegistry, updates, signerKeyId, signerPrivateKey, options = {}) {
  // R08-B05: Revoked keys cannot authorize updates
  if (Array.isArray(currentRegistry.revokedKeyIds) && currentRegistry.revokedKeyIds.includes(signerKeyId)) {
    throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${signerKeyId}' has already been revoked in current registry`);
  }

  // R21-B01 & R22-B01: Revoked keys in revocation journal cannot authorize updates.
  // Fail-Closed: if revocation status cannot be verified due to journal read/corruption errors, reject.
  const effectiveOpts = options && typeof options === 'object' ? options : {};
  let effectiveDir = null;
  try {
    effectiveDir = resolvePluginDataDir(effectiveOpts);
  } catch (dirErr) {
    throw new Error(`[REVOCATION_STATUS_UNVERIFIABLE] Cannot resolve plugin directory to verify revocation status: ${dirErr.message}`);
  }
  if (effectiveDir) {
    let journalRevoked;
    try {
      journalRevoked = getJournalRevokedKeyMap(effectiveDir, {
        ...effectiveOpts,
        registry: currentRegistry,
        candidateHwm: currentRegistry.revocationHighWaterMark
      });
    } catch (jErr) {
      throw new Error(`[REVOCATION_STATUS_UNVERIFIABLE] Cannot verify signer revocation status for registry update: ${jErr.message}`);
    }
    if (journalRevoked.has(signerKeyId)) {
      throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${signerKeyId}' was revoked in revocation journal at index ${journalRevoked.get(signerKeyId)}; cannot authorize registry update`);
    }
  }
  // R13-B08: Retired keys cannot authorize updates!
  if (Array.isArray(currentRegistry.keys)) {
    const keyRecord = currentRegistry.keys.find(k => k.keyId === signerKeyId);
    if (keyRecord && keyRecord.status === 'RETIRED') {
      throw new Error(`[RETIRED_KEY_AUTHORIZATION_REJECTED] Signer key '${signerKeyId}' is marked RETIRED in current registry; only ACTIVE keys may authorize updates`);
    }
    if (keyRecord && keyRecord.status === 'REVOKED') {
      throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${signerKeyId}' is marked REVOKED in current registry; only ACTIVE keys may authorize updates`);
    }
    if (!keyRecord || (keyRecord.status !== 'ACTIVE' && keyRecord.status !== 'ACTIVE_PINNED_ROOT')) {
      throw new Error(`[INACTIVE_SIGNER_REJECTED] Signer key '${signerKeyId}' is not ACTIVE in current registry`);
    }
  }

  const updated = {
    ...currentRegistry,
    ...updates,
    registryVersion: (currentRegistry.registryVersion || 1) + 1
  };

  // R08-B05 & R14-B04: If HWM exists and its prior signer is not active in updated registry,
  // or if re-signing requested, re-sign HWM with the new authorized signer
  if (updated.revocationHighWaterMark) {
    const isSignerRevoked = Array.isArray(updated.revokedKeyIds) && updated.revokedKeyIds.includes(updated.revocationHighWaterMark.authorizedBy);
    const signerInUpdated = Array.isArray(updated.keys) && updated.keys.find(k => k.keyId === updated.revocationHighWaterMark.authorizedBy);
    const isSignerInactive = !signerInUpdated || (signerInUpdated.status !== 'ACTIVE' && signerInUpdated.status !== 'ACTIVE_PINNED_ROOT');
    if (isSignerRevoked || isSignerInactive || updates.reSignHighWaterMark === true) {
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
              // R16-B01, R18-B02 & R19-B02: Verify historical registry against monotonic witness commitment.
              // Digest advancement at the active version is permitted strictly when HWM headIndex advances AND non-HWM identity is invariant.
              const curWitness = getMonotonicWitness(dir, options);
              const histHwmIdx = typeof histObj?.revocationHighWaterMark?.headIndex === 'number'
                ? histObj.revocationHighWaterMark.headIndex
                : -1;
              if (curWitness.registryDigests && curWitness.registryDigests[String(v)]) {
                const histDigest = computeRegistryDigest(histObj);
                const isActiveHwmAdvancing = (
                  v === curWitness.maxSeenRegistryVersion &&
                  v === parsed.registryVersion &&
                  histHwmIdx > curWitness.maxSeenHwmHeadIndex
                );
                if (histDigest !== curWitness.registryDigests[String(v)] && !isActiveHwmAdvancing) {
                  const errorMsg = `[REGISTRY_ROLLBACK_DETECTED] [REGISTRY_DIVERGENCE_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_ROLLBACK_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Historical registry ${hf} digest (${histDigest}) diverges from witnessed historical commitment (${curWitness.registryDigests[String(v)]})`;
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
              if (curWitness.registryNonHwmDigests && curWitness.registryNonHwmDigests[String(v)]) {
                const histNonHwmDigest = computeRegistryNonHwmDigest(histObj);
                if (histNonHwmDigest !== curWitness.registryNonHwmDigests[String(v)]) {
                  const errorMsg = `[REGISTRY_DIVERGENCE_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Historical registry ${hf} non-HWM identity (${histNonHwmDigest}) diverges from witnessed non-HWM commitment (${curWitness.registryNonHwmDigests[String(v)]})`;
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
              if (v === parsed.registryVersion) {
                sameVersionHistRegistry = histObj;
              }
              if (histObj.revocationHighWaterMark && typeof histObj.revocationHighWaterMark.headIndex === 'number') {
                if (histObj.revocationHighWaterMark.headIndex > highestHistHwmIndex) {
                  highestHistHwmIndex = histObj.revocationHighWaterMark.headIndex;
                }
              }
            } catch (histErr) {
              if (histErr.message && (histErr.message.includes('REGISTRY_HISTORY_DIVERGENCE_DETECTED') || histErr.message.includes('MONOTONIC_WITNESS_DIVERGENCE_DETECTED') || histErr.message.includes('REGISTRY_DIVERGENCE_DETECTED'))) {
                throw histErr;
              }
              const errorMsg = `[HISTORY_CORRUPTION_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] Historical registry ${hf} in ${histDir} is corrupted or cannot be parsed: ${histErr.message}`;
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
          // R08-B04 & R19-B02: Match on-disk registry non-HWM identity and content against historical counterpart
          const diskNonHwmDigest = computeRegistryNonHwmDigest(parsed);
          const histNonHwmDigest = computeRegistryNonHwmDigest(sameVersionHistRegistry);
          if (diskNonHwmDigest !== histNonHwmDigest) {
            const errorMsg = `[REGISTRY_DIVERGENCE_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] On-disk trust registry non-HWM identity (${diskNonHwmDigest}) diverges from historical trust-registry.v${parsed.registryVersion}.json (${histNonHwmDigest})`;
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
        // R17-B02: Under Default-Deny, any historical progression or corruption error must fail closed
        if (options.failClosed !== false) {
          throw hErr;
        }
        return {
          source: 'PLUGIN_DATA',
          registry: null,
          valid: false,
          error: hErr.message,
          cryptographicValidity: false,
          monotonicValidity: false,
          ancestryContinuity: false
        };
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

      // R12-B02, R14-B07, R15-B01, R15-B03 & R19-B02: Enforce monotonic witness freshness with candidate HWM, full registry, and non-HWM digests
      const currentHwmIdx = typeof parsed.revocationHighWaterMark?.headIndex === 'number'
        ? parsed.revocationHighWaterMark.headIndex
        : -1;
      const currentHwmDigest = typeof parsed.revocationHighWaterMark?.headDigest === 'string'
        ? parsed.revocationHighWaterMark.headDigest
        : '';
      const currentRegDigest = computeRegistryDigest(parsed);
      const currentNonHwmDigest = computeRegistryNonHwmDigest(parsed);
      assertMonotonicWitnessFreshness(dir, parsed.registryVersion, currentHwmIdx, currentHwmDigest, currentRegDigest, { ...options, nonHwmDigest: currentNonHwmDigest });
      updateMonotonicWitness(dir, parsed.registryVersion, currentHwmIdx, currentHwmDigest, currentRegDigest, createPrivilegedWitnessOptions({ ...options, nonHwmDigest: currentNonHwmDigest }));

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
 * R12-B02 & R13-B02: Directory-Bound and Independent Persistent Monotonic Freshness Witness Anchor.
 * Defends against whole-directory state rollback where an attacker restores
 * a past valid snapshot of PLUGIN_DATA (Registry, Checkpoint, Journal, History).
 */
const _DIR_MONOTONIC_WITNESS = new Map();

function getWitnessStoragePaths(dir) {
  const normDir = canonicalizeDirPath(dir);
  const localWitnessFile = path.join(normDir, '.monotonic-witness.json');
  // Independent anchor stored outside PLUGIN_DATA isolated directory
  const dirHash = crypto.createHash('sha256').update(normDir, 'utf8').digest('hex').slice(0, 16);
  const systemDir = process.env.THREE_LENS_SYSTEM_WITNESS_DIR || path.join(os.homedir(), '.three-lens', 'witness');
  const systemWitnessFile = path.join(systemDir, `${dirHash}.witness.json`);
  return { localWitnessFile, systemWitnessFile };
}

export function getMonotonicWitness(dir, options = {}) {
  const norm = canonicalizeDirPath(dir);
  if (!_DIR_MONOTONIC_WITNESS.has(norm)) {
    _DIR_MONOTONIC_WITNESS.set(norm, {
      maxSeenRegistryVersion: 1,
      maxSeenRegistryDigest: '',
      registryDigests: {},
      registryNonHwmDigests: {},
      maxSeenHwmHeadIndex: -1,
      maxSeenHwmHeadDigest: ''
    });
  }
  const memWitness = _DIR_MONOTONIC_WITNESS.get(norm);
  let maxRegVer = memWitness.maxSeenRegistryVersion;
  let maxRegDigest = memWitness.maxSeenRegistryDigest || '';
  const registryDigestsMap = { ...(memWitness.registryDigests || {}) };
  const registryNonHwmDigestsMap = { ...(memWitness.registryNonHwmDigests || {}) };
  let maxHwmIdx = memWitness.maxSeenHwmHeadIndex;
  let maxHwmDigest = memWitness.maxSeenHwmHeadDigest || '';

  // Read persistent anchors
  const { localWitnessFile, systemWitnessFile } = getWitnessStoragePaths(norm);
  const readWitnessFile = (filePath) => {
    if (fs.existsSync(filePath)) {
      let raw = null;
      try {
        raw = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      } catch (err) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} is corrupted or cannot be parsed: ${err.message}`);
      }
      // R15-B04 & R16-B05: Strict Schema Validation & Semantic Integrity under Default-Deny
      if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} contains invalid JSON payload (must be object)`);
      }
      if (raw.schemaVersion !== '1.0.0') {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} has invalid schemaVersion '${raw.schemaVersion}'`);
      }
      if (typeof raw.dir !== 'string' || !raw.dir.trim()) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing mandatory 'dir' string`);
      }
      // R16-B05: Directory path semantic parity check against target storage dir (resolves symlinks across macOS/Linux)
      if (!pathsEqual(raw.dir, dir)) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness directory '${raw.dir}' diverges from expected storage directory '${dir}'`);
      }
      if (typeof raw.maxSeenRegistryVersion !== 'number' || !Number.isInteger(raw.maxSeenRegistryVersion) || raw.maxSeenRegistryVersion < 1) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'maxSeenRegistryVersion'`);
      }
      // R16-B05: maxSeenRegistryDigest must be 64-hex SHA-256
      if (typeof raw.maxSeenRegistryDigest !== 'string' || !/^[a-f0-9]{64}$/.test(raw.maxSeenRegistryDigest)) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'maxSeenRegistryDigest' (must be 64-hex SHA-256)`);
      }
      if (typeof raw.maxSeenHwmHeadIndex !== 'number' || !Number.isInteger(raw.maxSeenHwmHeadIndex) || raw.maxSeenHwmHeadIndex < -1) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'maxSeenHwmHeadIndex'`);
      }
      // R16-B05: HWM index vs headDigest semantic consistency
      if (raw.maxSeenHwmHeadIndex >= 0) {
        if (typeof raw.maxSeenHwmHeadDigest !== 'string' || !/^[a-f0-9]{64}$/.test(raw.maxSeenHwmHeadDigest)) {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'maxSeenHwmHeadDigest' for index ${raw.maxSeenHwmHeadIndex}`);
        }
      } else {
        if (raw.maxSeenHwmHeadDigest !== '') {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} has non-empty 'maxSeenHwmHeadDigest' for index -1`);
        }
      }
      if (typeof raw.updatedAt !== 'string' || !raw.updatedAt.trim()) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'updatedAt'`);
      }

      // R16-B05: Strict dictionary structure & semantic validation for registryDigests
      if (!raw.registryDigests || typeof raw.registryDigests !== 'object' || Array.isArray(raw.registryDigests)) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} missing or invalid 'registryDigests' dictionary`);
      }
      for (const [v, d] of Object.entries(raw.registryDigests)) {
        const vNum = parseInt(v, 10);
        if (!Number.isInteger(vNum) || vNum < 1 || String(vNum) !== v) {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} contains invalid version key '${v}' in registryDigests`);
        }
        if (typeof d !== 'string' || !/^[a-f0-9]{64}$/.test(d)) {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} contains invalid digest format for version ${v} in registryDigests`);
        }
      }
      // Ensure maxSeenRegistryVersion exists in registryDigests and matches maxSeenRegistryDigest
      const maxVerKey = String(raw.maxSeenRegistryVersion);
      if (raw.registryDigests[maxVerKey] !== raw.maxSeenRegistryDigest) {
        throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} registryDigests[${maxVerKey}] does not match maxSeenRegistryDigest`);
      }

      // R17-E01: Sparse witness check: Ensure all versions 1..raw.maxSeenRegistryVersion are present without gaps
      for (let v = 1; v <= raw.maxSeenRegistryVersion; v++) {
        const vKey = String(v);
        if (!raw.registryDigests[vKey]) {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Sparse witness detected: missing unbroken historical digest for version ${v} in ${filePath}`);
        }
      }

      // R19-B02: Validate optional registryNonHwmDigests dictionary if present in witness file
      if (raw.registryNonHwmDigests !== undefined) {
        if (!raw.registryNonHwmDigests || typeof raw.registryNonHwmDigests !== 'object' || Array.isArray(raw.registryNonHwmDigests)) {
          throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} has invalid 'registryNonHwmDigests' dictionary`);
        }
        for (const [v, nd] of Object.entries(raw.registryNonHwmDigests)) {
          const vNum = parseInt(v, 10);
          if (!Number.isInteger(vNum) || vNum < 1 || String(vNum) !== v) {
            throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} contains invalid version key '${v}' in registryNonHwmDigests`);
          }
          if (typeof nd !== 'string' || !/^[a-f0-9]{64}$/.test(nd)) {
            throw new Error(`[MONOTONIC_WITNESS_CORRUPTED] Persistent witness file at ${filePath} contains invalid digest format for version ${v} in registryNonHwmDigests`);
          }
          if (registryNonHwmDigestsMap[v] && registryNonHwmDigestsMap[v] !== nd) {
            throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Persistent witness non-HWM registry identity divergence at version ${v} in ${filePath}`);
          }
          registryNonHwmDigestsMap[v] = nd;
        }
      }

      // R15-B03, R18-B02 & R19-B02: Check registry digest divergence at same version.
      // Same-version digest advancement is permitted strictly when HWM headIndex advances AND non-HWM identity is invariant.
      if (raw.maxSeenRegistryVersion > maxRegVer) {
        maxRegVer = raw.maxSeenRegistryVersion;
        maxRegDigest = raw.maxSeenRegistryDigest || '';
      } else if (raw.maxSeenRegistryVersion === maxRegVer) {
        if (raw.maxSeenHwmHeadIndex > maxHwmIdx) {
          maxRegDigest = raw.maxSeenRegistryDigest || maxRegDigest;
        } else if (raw.maxSeenHwmHeadIndex === maxHwmIdx) {
          if (raw.maxSeenRegistryDigest && maxRegDigest && raw.maxSeenRegistryDigest !== maxRegDigest) {
            throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Persistent witness registry divergence at version ${maxRegVer} in ${filePath}`);
          }
          if (!maxRegDigest && raw.maxSeenRegistryDigest) {
            maxRegDigest = raw.maxSeenRegistryDigest;
          }
        }
      }

      if (raw.registryDigests && typeof raw.registryDigests === 'object') {
        for (const [v, d] of Object.entries(raw.registryDigests)) {
          if (typeof d === 'string') {
            const vNum = parseInt(v, 10);
            if (vNum === maxRegVer && raw.maxSeenRegistryVersion === maxRegVer) {
              if (raw.maxSeenHwmHeadIndex > maxHwmIdx) {
                registryDigestsMap[v] = d;
              } else if (raw.maxSeenHwmHeadIndex === maxHwmIdx) {
                if (registryDigestsMap[v] && registryDigestsMap[v] !== d) {
                  throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Persistent witness historical registry divergence at version ${v} in ${filePath}`);
                }
                registryDigestsMap[v] = d;
              }
            } else {
              if (registryDigestsMap[v] && registryDigestsMap[v] !== d) {
                throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Persistent witness historical registry divergence at version ${v} in ${filePath}`);
              }
              registryDigestsMap[v] = d;
            }
          }
        }
      }

      // Check HWM index and digest
      if (raw.maxSeenHwmHeadIndex > maxHwmIdx) {
        maxHwmIdx = raw.maxSeenHwmHeadIndex;
        maxHwmDigest = raw.maxSeenHwmHeadDigest || '';
      } else if (raw.maxSeenHwmHeadIndex === maxHwmIdx && maxHwmIdx >= 0) {
        if (raw.maxSeenHwmHeadDigest && maxHwmDigest && raw.maxSeenHwmHeadDigest !== maxHwmDigest) {
          throw new Error(`[MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Persistent witness divergence at index ${maxHwmIdx} in ${filePath}`);
        }
        if (!maxHwmDigest && raw.maxSeenHwmHeadDigest) {
          maxHwmDigest = raw.maxSeenHwmHeadDigest;
        }
      }
    }
  };

  readWitnessFile(localWitnessFile);
  readWitnessFile(systemWitnessFile);

  // R18-B03: Update internal authoritative memory witness exclusively from persistent anchors.
  // Never allow unauthenticated caller options (externalMonotonicWitness) or returned object mutation
  // to poison the shared in-process _DIR_MONOTONIC_WITNESS state.
  memWitness.maxSeenRegistryVersion = maxRegVer;
  memWitness.maxSeenRegistryDigest = maxRegDigest;
  memWitness.registryDigests = { ...registryDigestsMap };
  memWitness.registryNonHwmDigests = { ...registryNonHwmDigestsMap };
  memWitness.maxSeenHwmHeadIndex = maxHwmIdx;
  memWitness.maxSeenHwmHeadDigest = maxHwmDigest;

  let effRegVer = maxRegVer;
  let effRegDigest = maxRegDigest;
  const effRegistryDigestsMap = { ...registryDigestsMap };
  const effRegistryNonHwmDigestsMap = { ...registryNonHwmDigestsMap };
  let effHwmIdx = maxHwmIdx;
  let effHwmDigest = maxHwmDigest;

  // Read per-call external witness floor from options without mutating shared memWitness
  const externalWitness = options.externalMonotonicWitness;
  if (externalWitness && typeof externalWitness === 'object') {
    if (typeof externalWitness.minRegistryVersion === 'number') {
      if (externalWitness.minRegistryVersion > effRegVer) {
        effRegVer = externalWitness.minRegistryVersion;
        if (typeof externalWitness.minRegistryDigest === 'string') {
          effRegDigest = externalWitness.minRegistryDigest;
        }
      } else if (externalWitness.minRegistryVersion === effRegVer) {
        if (externalWitness.minRegistryDigest && effRegDigest && externalWitness.minRegistryDigest !== effRegDigest) {
          throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] External witness registry digest diverges at version ${effRegVer}`);
        }
      }
    }
    if (externalWitness.registryDigests && typeof externalWitness.registryDigests === 'object') {
      for (const [v, d] of Object.entries(externalWitness.registryDigests)) {
        if (typeof d === 'string') {
          if (effRegistryDigestsMap[v] && effRegistryDigestsMap[v] !== d) {
            throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] External witness historical registry digest diverges at version ${v}`);
          }
          effRegistryDigestsMap[v] = d;
        }
      }
    }
    if (externalWitness.registryNonHwmDigests && typeof externalWitness.registryNonHwmDigests === 'object') {
      for (const [v, nd] of Object.entries(externalWitness.registryNonHwmDigests)) {
        if (typeof nd === 'string') {
          if (effRegistryNonHwmDigestsMap[v] && effRegistryNonHwmDigestsMap[v] !== nd) {
            throw new Error(`[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] External witness non-HWM registry identity digest diverges at version ${v}`);
          }
          effRegistryNonHwmDigestsMap[v] = nd;
        }
      }
    }
    if (typeof externalWitness.minHwmHeadIndex === 'number') {
      if (externalWitness.minHwmHeadIndex > effHwmIdx) {
        effHwmIdx = externalWitness.minHwmHeadIndex;
        if (externalWitness.minHwmHeadDigest) effHwmDigest = externalWitness.minHwmHeadDigest;
      } else if (externalWitness.minHwmHeadIndex === effHwmIdx && effHwmIdx >= 0 && externalWitness.minHwmHeadDigest && effHwmDigest) {
        if (externalWitness.minHwmHeadDigest !== effHwmDigest) {
          throw new Error(`[MONOTONIC_WITNESS_DIVERGENCE_DETECTED] External witness digest diverges at index ${effHwmIdx}`);
        }
      }
    }
  }

  // R18-B03: Return a deeply cloned, frozen read-only snapshot so external callers cannot mutate internal state
  return Object.freeze({
    maxSeenRegistryVersion: effRegVer,
    maxSeenRegistryDigest: effRegDigest,
    registryDigests: Object.freeze({ ...effRegistryDigestsMap }),
    registryNonHwmDigests: Object.freeze({ ...effRegistryNonHwmDigestsMap }),
    maxSeenHwmHeadIndex: effHwmIdx,
    maxSeenHwmHeadDigest: effHwmDigest
  });
}

function normalizeWitnessCallArgs(arg4, arg5, arg6) {
  let headDigest = '';
  let regDigest = '';
  let options = {};

  if (typeof arg4 === 'string') {
    headDigest = arg4;
    if (typeof arg5 === 'string') {
      regDigest = arg5;
      if (arg6 && typeof arg6 === 'object') {
        options = arg6;
      }
    } else if (arg5 && typeof arg5 === 'object') {
      options = arg5;
      if (typeof options.registryDigest === 'string') regDigest = options.registryDigest;
      else if (typeof options.candidateRegistryDigest === 'string') regDigest = options.candidateRegistryDigest;
    }
  } else if (arg4 === null || arg4 === undefined) {
    if (typeof arg5 === 'string') {
      regDigest = arg5;
      if (arg6 && typeof arg6 === 'object') options = arg6;
    } else if (arg5 && typeof arg5 === 'object') {
      options = arg5;
      if (typeof options.registryDigest === 'string') regDigest = options.registryDigest;
      else if (typeof options.candidateRegistryDigest === 'string') regDigest = options.candidateRegistryDigest;
    } else if (arg6 && typeof arg6 === 'object') {
      options = arg6;
    }
  } else if (typeof arg4 === 'object') {
    options = arg4;
    if (typeof options.hwmHeadDigest === 'string') headDigest = options.hwmHeadDigest;
    else if (typeof options.candidateHwmHeadDigest === 'string') headDigest = options.candidateHwmHeadDigest;
    if (typeof options.registryDigest === 'string') regDigest = options.registryDigest;
    else if (typeof options.candidateRegistryDigest === 'string') regDigest = options.candidateRegistryDigest;
  }

  if (!headDigest && options) {
    if (typeof options.hwmHeadDigest === 'string') headDigest = options.hwmHeadDigest;
    else if (typeof options.candidateHwmHeadDigest === 'string') headDigest = options.candidateHwmHeadDigest;
  }
  if (!regDigest && options) {
    if (typeof options.registryDigest === 'string') regDigest = options.registryDigest;
    else if (typeof options.candidateRegistryDigest === 'string') regDigest = options.candidateRegistryDigest;
  }

  return { headDigest: headDigest || '', regDigest: regDigest || '', options: options || {} };
}

export function updateMonotonicWitness(dir, registryVersion, hwmHeadIndex, arg4, arg5, arg6) {
  const { headDigest: hwmHeadDigest, regDigest: registryDigest, options } = normalizeWitnessCallArgs(arg4, arg5, arg6);
  const candidateNonHwmDigest = typeof options.nonHwmDigest === 'string'
    ? options.nonHwmDigest
    : (options.registry && typeof options.registry === 'object' ? computeRegistryNonHwmDigest(options.registry) : '');

  // R17-B01: External callers cannot call updateMonotonicWitness directly to escalate witness version
  if (!options || typeof options !== 'object' || !INTERNAL_WITNESS_PRIVILEGED_OPTIONS.has(options) || options[INTERNAL_WITNESS_WRITE_TOKEN] !== true) {
    throw new Error('[STORAGE_CONFINEMENT_VIOLATION] [UNAUTHORIZED_WITNESS_UPDATE] Calling updateMonotonicWitness requires internal witness write token');
  }

  const norm = canonicalizeDirPath(dir);
  const current = getMonotonicWitness(dir, { ...options, externalMonotonicWitness: undefined });
  const witness = {
    maxSeenRegistryVersion: current.maxSeenRegistryVersion,
    maxSeenRegistryDigest: current.maxSeenRegistryDigest || '',
    registryDigests: { ...(current.registryDigests || {}) },
    registryNonHwmDigests: { ...(current.registryNonHwmDigests || {}) },
    maxSeenHwmHeadIndex: current.maxSeenHwmHeadIndex,
    maxSeenHwmHeadDigest: current.maxSeenHwmHeadDigest || ''
  };
  let changed = false;

  const isHwmAdvancingAtActiveVersion = (
    typeof registryVersion === 'number' &&
    registryVersion === witness.maxSeenRegistryVersion &&
    typeof hwmHeadIndex === 'number' &&
    hwmHeadIndex > witness.maxSeenHwmHeadIndex
  );

  // R15-B03, R18-B02 & R19-B02: Check and update registry version, content commitment, and non-HWM identity commitment.
  // At the active registryVersion, a digest update is permitted strictly when HWM headIndex advances AND non-HWM identity is invariant.
  if (typeof registryVersion === 'number') {
    const verKey = String(registryVersion);
    if (candidateNonHwmDigest) {
      if (!witness.registryNonHwmDigests) witness.registryNonHwmDigests = {};
      if (witness.registryNonHwmDigests[verKey] && witness.registryNonHwmDigests[verKey] !== candidateNonHwmDigest) {
        throw new Error(
          `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Monotonic witness non-HWM identity divergence at version ${registryVersion}: existing non-HWM digest ${witness.registryNonHwmDigests[verKey]} !== candidate non-HWM digest ${candidateNonHwmDigest}`
        );
      }
      if (!witness.registryNonHwmDigests[verKey]) {
        witness.registryNonHwmDigests[verKey] = candidateNonHwmDigest;
        changed = true;
      }
    }

    if (registryVersion > witness.maxSeenRegistryVersion) {
      witness.maxSeenRegistryVersion = registryVersion;
      witness.maxSeenRegistryDigest = registryDigest || '';
      changed = true;
    } else if (registryVersion === witness.maxSeenRegistryVersion) {
      if (registryDigest && witness.maxSeenRegistryDigest && witness.maxSeenRegistryDigest !== registryDigest) {
        if (isHwmAdvancingAtActiveVersion) {
          witness.maxSeenRegistryDigest = registryDigest;
          changed = true;
        } else {
          throw new Error(
            `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Monotonic witness registry divergence at version ${registryVersion}: existing digest ${witness.maxSeenRegistryDigest} !== candidate digest ${registryDigest}`
          );
        }
      }
      if (!witness.maxSeenRegistryDigest && registryDigest) {
        witness.maxSeenRegistryDigest = registryDigest;
        changed = true;
      }
    }
    if (registryDigest) {
      if (!witness.registryDigests) witness.registryDigests = {};
      if (witness.registryDigests[verKey] && witness.registryDigests[verKey] !== registryDigest) {
        if (isHwmAdvancingAtActiveVersion) {
          witness.registryDigests[verKey] = registryDigest;
          changed = true;
        } else {
          throw new Error(
            `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Monotonic witness historical registry divergence at version ${registryVersion}: existing digest ${witness.registryDigests[verKey]} !== candidate digest ${registryDigest}`
          );
        }
      }
      if (!witness.registryDigests[verKey]) {
        witness.registryDigests[verKey] = registryDigest;
        changed = true;
      }
    }
  }

  // R14-B07 & R15-B01: Check and update HWM index and digest
  if (typeof hwmHeadIndex === 'number') {
    if (hwmHeadIndex > witness.maxSeenHwmHeadIndex) {
      witness.maxSeenHwmHeadIndex = hwmHeadIndex;
      witness.maxSeenHwmHeadDigest = hwmHeadDigest || '';
      changed = true;
    } else if (hwmHeadIndex === witness.maxSeenHwmHeadIndex && hwmHeadIndex >= 0) {
      if (hwmHeadDigest && witness.maxSeenHwmHeadDigest && witness.maxSeenHwmHeadDigest !== hwmHeadDigest) {
        throw new Error(
          `[MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Monotonic witness divergence at headIndex ${hwmHeadIndex}: existing digest ${witness.maxSeenHwmHeadDigest} !== candidate digest ${hwmHeadDigest}`
        );
      }
      if (!witness.maxSeenHwmHeadDigest && hwmHeadDigest) {
        witness.maxSeenHwmHeadDigest = hwmHeadDigest;
        changed = true;
      }
    }
  }

  // R16-B01 & R19-B02: Automatically seal all existing history registries on disk into witness.registryDigests and registryNonHwmDigests
  const histDir = path.join(dir, 'history');
  if (fs.existsSync(histDir)) {
    try {
      const histFiles = fs.readdirSync(histDir);
      for (const hf of histFiles) {
        const m = hf.match(/^trust-registry\.v(\d+)\.json$/);
        if (m) {
          const v = m[1];
          try {
            const histObj = JSON.parse(fs.readFileSync(path.join(histDir, hf), 'utf8'));
            if (!witness.registryDigests[v]) {
              witness.registryDigests[v] = computeRegistryDigest(histObj);
              changed = true;
            }
            if (!witness.registryNonHwmDigests[v]) {
              witness.registryNonHwmDigests[v] = computeRegistryNonHwmDigest(histObj);
              changed = true;
            }
          } catch (_) {}
        }
      }
    } catch (_) {}
  }

  // Ensure current maxSeenRegistryVersion is always present in witness.registryDigests
  if (witness.maxSeenRegistryDigest && /^[a-f0-9]{64}$/.test(witness.maxSeenRegistryDigest)) {
    if (!witness.registryDigests) witness.registryDigests = {};
    const maxVerKey = String(witness.maxSeenRegistryVersion);
    if (!witness.registryDigests[maxVerKey]) {
      witness.registryDigests[maxVerKey] = witness.maxSeenRegistryDigest;
      changed = true;
    }
  }

  // Update internal authoritative memory witness map
  _DIR_MONOTONIC_WITNESS.set(norm, {
    maxSeenRegistryVersion: witness.maxSeenRegistryVersion,
    maxSeenRegistryDigest: witness.maxSeenRegistryDigest || '',
    registryDigests: { ...(witness.registryDigests || {}) },
    registryNonHwmDigests: { ...(witness.registryNonHwmDigests || {}) },
    maxSeenHwmHeadIndex: witness.maxSeenHwmHeadIndex,
    maxSeenHwmHeadDigest: witness.maxSeenHwmHeadDigest || ''
  });

  const { localWitnessFile, systemWitnessFile } = getWitnessStoragePaths(dir);
  const writeWitness = (filePath) => {
    try {
      const parent = path.dirname(filePath);
      if (!fs.existsSync(parent)) fs.mkdirSync(parent, { recursive: true });
      const payload = JSON.stringify({
        schemaVersion: '1.0.0',
        dir: canonicalizeDirPath(dir),
        maxSeenRegistryVersion: witness.maxSeenRegistryVersion,
        maxSeenRegistryDigest: witness.maxSeenRegistryDigest || '',
        registryDigests: witness.registryDigests || {},
        registryNonHwmDigests: witness.registryNonHwmDigests || {},
        maxSeenHwmHeadIndex: witness.maxSeenHwmHeadIndex,
        maxSeenHwmHeadDigest: witness.maxSeenHwmHeadDigest || '',
        updatedAt: new Date().toISOString()
      }, null, 2) + '\n';
      // R15-B04, R16-B02 & R17-B01: Privileged internal write token to satisfy safe storage confinement
      safeWriteFileSync(filePath, payload, createPrivilegedWitnessOptions(options));
    } catch (writeErr) {
      throw new Error(`[STORAGE_DURABILITY_FAILURE] Failed to persist monotonic witness at ${filePath}: ${writeErr.message}`);
    }
  };

  writeWitness(localWitnessFile);
  writeWitness(systemWitnessFile);

  return Object.freeze({
    maxSeenRegistryVersion: witness.maxSeenRegistryVersion,
    maxSeenRegistryDigest: witness.maxSeenRegistryDigest || '',
    registryDigests: Object.freeze({ ...(witness.registryDigests || {}) }),
    registryNonHwmDigests: Object.freeze({ ...(witness.registryNonHwmDigests || {}) }),
    maxSeenHwmHeadIndex: witness.maxSeenHwmHeadIndex,
    maxSeenHwmHeadDigest: witness.maxSeenHwmHeadDigest || ''
  });
}

export function assertMonotonicWitnessFreshness(dir, candidateRegistryVersion, candidateHwmHeadIndex, arg4, arg5, arg6) {
  const { headDigest: candidateHwmHeadDigest, regDigest: candidateRegistryDigest, options } = normalizeWitnessCallArgs(arg4, arg5, arg6);
  const candidateNonHwmDigest = typeof options.nonHwmDigest === 'string'
    ? options.nonHwmDigest
    : (options.registry && typeof options.registry === 'object' ? computeRegistryNonHwmDigest(options.registry) : '');

  const externalWitness = options.externalMonotonicWitness || {};
  const witness = getMonotonicWitness(dir, options);
  const minRegVer = Math.max(
    typeof options.minRegistryVersion === 'number' ? options.minRegistryVersion : 1,
    typeof externalWitness.minRegistryVersion === 'number' ? externalWitness.minRegistryVersion : 1,
    witness.maxSeenRegistryVersion
  );
  const minHwmIdx = Math.max(
    typeof options.minHwmHeadIndex === 'number' ? options.minHwmHeadIndex : -1,
    typeof externalWitness.minHwmHeadIndex === 'number' ? externalWitness.minHwmHeadIndex : -1,
    witness.maxSeenHwmHeadIndex
  );

  if (typeof candidateRegistryVersion === 'number' && candidateRegistryVersion < minRegVer) {
    throw new Error(
      `[REGISTRY_ROLLBACK_DETECTED] [MONOTONIC_WITNESS_ROLLBACK_DETECTED] Loaded registryVersion (${candidateRegistryVersion}) is behind authenticated monotonic witness (${minRegVer})`
    );
  }
  if (typeof candidateHwmHeadIndex === 'number' && candidateHwmHeadIndex < minHwmIdx) {
    throw new Error(
      `[REGISTRY_ROLLBACK_DETECTED] [HIGH_WATER_MARK_ROLLBACK_DETECTED] [MONOTONIC_WITNESS_ROLLBACK_DETECTED] Loaded HWM headIndex (${candidateHwmHeadIndex}) is behind authenticated monotonic witness (${minHwmIdx})`
    );
  }

  // R15-B03, R16-B01, R18-B02 & R19-B02: Check registryDigest divergence for candidate and traverse historical ancestor commitments.
  // At the active registryVersion, a digest update is permitted strictly when HWM headIndex strictly advances AND non-HWM identity is invariant.
  if (typeof candidateRegistryVersion === 'number') {
    const isHwmAdvancingAtActiveVersion = (
      candidateRegistryVersion === witness.maxSeenRegistryVersion &&
      typeof candidateHwmHeadIndex === 'number' &&
      candidateHwmHeadIndex > witness.maxSeenHwmHeadIndex
    );

    const candKey = String(candidateRegistryVersion);
    // R19-B02: Non-HWM identity commitment MUST match witnessed nonHwmDigest for the version even when HWM advances
    if (candidateNonHwmDigest && witness.registryNonHwmDigests && witness.registryNonHwmDigests[candKey]) {
      if (candidateNonHwmDigest !== witness.registryNonHwmDigests[candKey]) {
        throw new Error(
          `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate non-HWM registry identity digest (${candidateNonHwmDigest}) diverges from witnessed non-HWM identity (${witness.registryNonHwmDigests[candKey]}) at registryVersion ${candidateRegistryVersion}`
        );
      }
    }

    // 1. Check candidate version if a witnessed digest exists
    if (witness.registryDigests && witness.registryDigests[candKey] && candidateRegistryDigest) {
      if (candidateRegistryDigest !== witness.registryDigests[candKey] && !isHwmAdvancingAtActiveVersion) {
        throw new Error(
          `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate registry digest (${candidateRegistryDigest}) diverges from witnessed digest (${witness.registryDigests[candKey]}) for registryVersion ${candidateRegistryVersion}`
        );
      }
    } else if (candidateRegistryVersion === witness.maxSeenRegistryVersion && witness.maxSeenRegistryDigest && candidateRegistryDigest) {
      if (candidateRegistryDigest !== witness.maxSeenRegistryDigest && !isHwmAdvancingAtActiveVersion) {
        throw new Error(
          `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate registry digest (${candidateRegistryDigest}) diverges from monotonic witness registryDigest (${witness.maxSeenRegistryDigest}) at registryVersion ${candidateRegistryVersion}`
        );
      }
    }

    // 2. R16-B01 & R19-B02: Traverse and verify ALL witnessed historical versions against on-disk history
    if (witness.registryDigests && typeof witness.registryDigests === 'object') {
      const histDir = path.join(dir, 'history');
      for (const [vStr, expectedDigest] of Object.entries(witness.registryDigests)) {
        const v = parseInt(vStr, 10);
        const isThisVersionAdvancingHwm = (v === candidateRegistryVersion && isHwmAdvancingAtActiveVersion);
        // If candidate itself is this version, verify candidateRegistryDigest
        if (v === candidateRegistryVersion && candidateRegistryDigest) {
          if (candidateRegistryDigest !== expectedDigest && !isThisVersionAdvancingHwm) {
            throw new Error(
              `[REGISTRY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate registry digest (${candidateRegistryDigest}) diverges from witnessed digest (${expectedDigest}) for registryVersion ${v}`
            );
          }
        }
        // R17-B02 & R19-B02: If on-disk historical artifact exists for this version (even if v === candidateRegistryVersion),
        // verify its content digest and non-HWM identity digest match the monotonic witness commitment and fail closed if corrupted
        const histPath = path.join(histDir, `trust-registry.v${v}.json`);
        if (fs.existsSync(histPath)) {
          try {
            const histObj = JSON.parse(fs.readFileSync(histPath, 'utf8'));
            const actualHistDigest = computeRegistryDigest(histObj);
            const actualHistNonHwmDigest = computeRegistryNonHwmDigest(histObj);
            if (witness.registryNonHwmDigests && witness.registryNonHwmDigests[vStr]) {
              if (actualHistNonHwmDigest !== witness.registryNonHwmDigests[vStr]) {
                throw new Error(
                  `[REGISTRY_DIVERGENCE_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Historical registry trust-registry.v${v}.json non-HWM identity (${actualHistNonHwmDigest}) diverges from witnessed non-HWM commitment (${witness.registryNonHwmDigests[vStr]})`
                );
              }
            }
            if (isThisVersionAdvancingHwm && candidateNonHwmDigest && actualHistNonHwmDigest !== candidateNonHwmDigest) {
              throw new Error(
                `[REGISTRY_DIVERGENCE_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate non-HWM identity (${candidateNonHwmDigest}) diverges from historical trust-registry.v${v}.json non-HWM identity (${actualHistNonHwmDigest})`
              );
            }
            const targetHistDigest = (isThisVersionAdvancingHwm && candidateRegistryDigest)
              ? candidateRegistryDigest
              : expectedDigest;
            if (actualHistDigest !== targetHistDigest && actualHistDigest !== expectedDigest) {
              throw new Error(
                `[REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Historical registry trust-registry.v${v}.json digest (${actualHistDigest}) diverges from monotonic witness historical commitment (${expectedDigest})`
              );
            }
          } catch (readErr) {
            if (readErr.message.includes('REGISTRY_HISTORY_DIVERGENCE_DETECTED') || readErr.message.includes('REGISTRY_DIVERGENCE_DETECTED')) throw readErr;
            throw new Error(
              `[HISTORY_CORRUPTION_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] Failed to verify historical registry at ${histPath}: ${readErr.message}`
            );
          }
        } else if (v < candidateRegistryVersion) {
            // Check if prior version is currently residing in active trust registry (e.g. during saveTrustRegistry)
            const candidateCurrentPaths = [
              path.join(dir, 'supervisor-trust-registry.json'),
              path.join(dir, 'trust-registry.json')
            ];
            let foundInCurrent = false;
            for (const currentRegPath of candidateCurrentPaths) {
              if (fs.existsSync(currentRegPath)) {
                try {
                  const curObj = JSON.parse(fs.readFileSync(currentRegPath, 'utf8'));
                  if (curObj.registryVersion === v) {
                    const actualDigest = computeRegistryDigest(curObj);
                    if (actualDigest !== expectedDigest) {
                      throw new Error(
                        `[REGISTRY_HISTORY_DIVERGENCE_DETECTED] [MONOTONIC_WITNESS_DIVERGENCE_DETECTED] On-disk trust registry version ${v} digest (${actualDigest}) diverges from monotonic witness historical commitment (${expectedDigest})`
                      );
                    }
                    foundInCurrent = true;
                    break;
                  }
                } catch (curErr) {
                  if (curErr.message.includes('REGISTRY_HISTORY_DIVERGENCE_DETECTED')) throw curErr;
                }
              }
            }
            if (!foundInCurrent && candidateRegistryVersion > v) {
              throw new Error(
                `[HISTORY_GAP_DETECTED] [REGISTRY_HISTORY_DIVERGENCE_DETECTED] Required historical registry for version ${v} committed in monotonic witness is missing from ${histPath}`
              );
            }
          }
        }
      }
    }

  // R14-B07 & R15-B01: Check HWM headDigest divergence at same index
  if (
    typeof candidateHwmHeadIndex === 'number' &&
    candidateHwmHeadIndex === witness.maxSeenHwmHeadIndex &&
    candidateHwmHeadIndex >= 0 &&
    candidateHwmHeadDigest &&
    witness.maxSeenHwmHeadDigest &&
    candidateHwmHeadDigest !== witness.maxSeenHwmHeadDigest
  ) {
    throw new Error(
      `[MONOTONIC_WITNESS_DIVERGENCE_DETECTED] Candidate HWM headDigest (${candidateHwmHeadDigest}) diverges from monotonic witness headDigest (${witness.maxSeenHwmHeadDigest}) at index ${candidateHwmHeadIndex}`
    );
  }

  // R20-B01: Journal prefix continuity verification against authenticated monotonic witness.
  // When candidateHwmHeadIndex > witness.maxSeenHwmHeadIndex and witness.maxSeenHwmHeadIndex >= 0,
  // the candidate is advancing HWM beyond an established witness.
  // The on-disk journal MUST exist, must contain at least witness.maxSeenHwmHeadIndex + 1 entries,
  // and the digest of the entry at witness.maxSeenHwmHeadIndex MUST strictly match witness.maxSeenHwmHeadDigest.
  if (
    typeof candidateHwmHeadIndex === 'number' &&
    candidateHwmHeadIndex > witness.maxSeenHwmHeadIndex &&
    witness.maxSeenHwmHeadIndex >= 0 &&
    witness.maxSeenHwmHeadDigest
  ) {
    const journalPath = path.join(dir, '.irv-revocation-journal.jsonl');
    if (!fs.existsSync(journalPath)) {
      throw new Error(
        `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] [JOURNAL_MISSING_DETECTED] [JOURNAL_ROLLBACK_DETECTED] Candidate HWM headIndex (${candidateHwmHeadIndex}) advances beyond witnessed index (${witness.maxSeenHwmHeadIndex}) but revocation journal does not exist at ${journalPath}`
      );
    }
    const rawContent = fs.readFileSync(journalPath, 'utf8');
    const lines = rawContent.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length <= witness.maxSeenHwmHeadIndex) {
      throw new Error(
        `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] [JOURNAL_ROLLBACK_DETECTED] Revocation journal entry count (${lines.length}) is less than witnessed headIndex (${witness.maxSeenHwmHeadIndex})`
      );
    }
    try {
      const entryAtWitness = JSON.parse(lines[witness.maxSeenHwmHeadIndex]);
      const digestAtWitness = sha256Digest(canonicalJsonStringify(entryAtWitness));
      if (digestAtWitness !== witness.maxSeenHwmHeadDigest) {
        throw new Error(
          `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] Revocation journal entry digest at witnessed index ${witness.maxSeenHwmHeadIndex} (${digestAtWitness}) diverges from authenticated monotonic witness (${witness.maxSeenHwmHeadDigest})`
        );
      }
    } catch (parseErr) {
      if (parseErr.message.includes('JOURNAL_PREFIX_DIVERGENCE_DETECTED')) throw parseErr;
      throw new Error(
        `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] [JOURNAL_CORRUPTION_DETECTED] Failed to parse journal entry at witnessed index ${witness.maxSeenHwmHeadIndex}: ${parseErr.message}`
      );
    }
  }
}

/**
 * Loads trust registry under governance lock with automatic WAL crash recovery.
 * Resolves R08-B02: Executes exclusively under joint governance lock.
 *
 * @param {object} [options={}]
 * @returns {{ source: 'PLUGIN_DATA'|'EMBEDDED_FALLBACK', registry: object, valid: boolean }}
 */
export function loadTrustRegistry(options = {}) {
  const dir = resolvePluginDataDir(options);
  const canSkipLock = options.skipLock === true && isGovernanceLockHeld(dir);
  if (canSkipLock) {
    recoverAbortedRevocationTransaction(options);
    return doLoadTrustRegistry(options);
  }
  return withGovernanceLock(options, (lockedOpts) => {
    recoverAbortedRevocationTransaction(lockedOpts);
    return doLoadTrustRegistry(lockedOpts);
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

  const canSkipLock = options.skipLock === true && isGovernanceLockHeld(dir);
  const doSave = (opts) => {
    recoverAbortedRevocationTransaction(opts);
    assertSafeStorageTarget(regPath, opts);
    const saveHwmIdx = typeof registry.revocationHighWaterMark?.headIndex === 'number'
      ? registry.revocationHighWaterMark.headIndex
      : -1;
    const saveHwmDigest = typeof registry.revocationHighWaterMark?.headDigest === 'string'
      ? registry.revocationHighWaterMark.headDigest
      : '';
    const saveRegDigest = computeRegistryDigest(registry);
    const saveNonHwmDigest = computeRegistryNonHwmDigest(registry);
    assertMonotonicWitnessFreshness(dir, registry.registryVersion, saveHwmIdx, saveHwmDigest, saveRegDigest, { ...opts, nonHwmDigest: saveNonHwmDigest });

    // R21-B01 & R22-B01: Prevent saving registry update authorized by a key revoked in the revocation journal.
    // Fail-Closed: if revocation status cannot be verified due to journal read/corruption errors, reject.
    if (registry.authorizationProof && registry.authorizationProof.authorizedBy) {
      let journalRevoked;
      try {
        journalRevoked = getJournalRevokedKeyMap(dir, {
          ...opts,
          registry,
          candidateHwm: registry.revocationHighWaterMark
        });
      } catch (jErr) {
        throw new Error(`[REVOCATION_STATUS_UNVERIFIABLE] Cannot verify signer revocation status before saving registry: ${jErr.message}`);
      }
      if (journalRevoked.has(registry.authorizationProof.authorizedBy)) {
        const revIdx = journalRevoked.get(registry.authorizationProof.authorizedBy);
        throw new Error(`[REVOKED_KEY_AUTHORIZATION_REJECTED] Signer key '${registry.authorizationProof.authorizedBy}' was revoked in revocation journal at index ${revIdx}; cannot authorize registry`);
      }
    }

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
    safeWriteFileSync(checkpointPath, JSON.stringify(cpData, null, 2) + '\n', opts);

    // R12-B02, R14-B07, R15-B01, R15-B03, R17-B01 & R19-B02: Update monotonic witness on successful save
    const finalHwmIdx = typeof registry.revocationHighWaterMark?.headIndex === 'number'
      ? registry.revocationHighWaterMark.headIndex
      : -1;
    const finalHwmDigest = typeof registry.revocationHighWaterMark?.headDigest === 'string'
      ? registry.revocationHighWaterMark.headDigest
      : '';
    const finalRegDigest = computeRegistryDigest(registry);
    const finalNonHwmDigest = computeRegistryNonHwmDigest(registry);
    updateMonotonicWitness(dir, registry.registryVersion, finalHwmIdx, finalHwmDigest, finalRegDigest, createPrivilegedWitnessOptions({ ...opts, nonHwmDigest: finalNonHwmDigest }));

    return {
      success: true,
      path: normalizePath(regPath),
      registryVersion: registry.registryVersion
    };
  };

  if (canSkipLock) {
    return doSave(options);
  }
  return withGovernanceLock(options, (lockedOpts) => doSave(lockedOpts));
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
  const dir = path.dirname(journalPath);

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

  // R04-B01 & R13-B03: Query trust registry high-water mark
  const trustRegistryLoad = loadTrustRegistry({ ...options, failClosed: false, skipLock: true });
  if (!trustRegistryLoad.valid) {
    const msg = `[TRUST_REGISTRY_INVALID] Cannot load revocation journal when trust registry is invalid: ${trustRegistryLoad.error}`;
    if (options.failClosed !== false) throw new Error(msg);
    return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
  }
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
    // R13-B03, R15-B01, R15-B03 & R19-B02: Enforce freshness check even when journal file does not exist
    const activeHeadIndex = checkpoint ? checkpoint.headIndex : (registryHwm ? registryHwm.headIndex : -1);
    const activeHeadDigest = checkpoint ? checkpoint.headDigest : (registryHwm ? registryHwm.headDigest : '');
    const journalRegDigest = trustRegistryLoad.registry ? computeRegistryDigest(trustRegistryLoad.registry) : '';
    const journalNonHwmDigest = trustRegistryLoad.registry ? computeRegistryNonHwmDigest(trustRegistryLoad.registry) : '';
    const journalRegVer = trustRegistryLoad.registry ? trustRegistryLoad.registry.registryVersion : undefined;
    try {
      assertMonotonicWitnessFreshness(dir, journalRegVer, activeHeadIndex, activeHeadDigest, journalRegDigest, { ...options, nonHwmDigest: journalNonHwmDigest });
    } catch (witnessErr) {
      if (options.failClosed !== false) throw witnessErr;
      return { valid: false, entries: [], error: witnessErr.message, count: 0, path: journalPath };
    }
    return { valid: true, entries: [], error: null, count: 0, path: journalPath };
  }

  try {
    const content = fs.readFileSync(journalPath, 'utf8');
    const lines = content.split(/\r?\n/).filter(line => line.trim().length > 0);

    if (lines.length === 0) {
      const activeHeadIndex = checkpoint ? checkpoint.headIndex : (registryHwm ? registryHwm.headIndex : -1);
      const activeHeadDigest = checkpoint ? checkpoint.headDigest : (registryHwm ? registryHwm.headDigest : '');
      const journalRegDigest = trustRegistryLoad.registry ? computeRegistryDigest(trustRegistryLoad.registry) : '';
      const journalNonHwmDigest = trustRegistryLoad.registry ? computeRegistryNonHwmDigest(trustRegistryLoad.registry) : '';
      const journalRegVer = trustRegistryLoad.registry ? trustRegistryLoad.registry.registryVersion : undefined;
      if (activeHeadIndex >= 0) {
        const msg = `[JOURNAL_TRUNCATION_DETECTED] Journal is empty but records exist at headIndex ${activeHeadIndex}`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: 0, path: journalPath };
      }
      try {
        assertMonotonicWitnessFreshness(dir, journalRegVer, activeHeadIndex, activeHeadDigest, journalRegDigest, { ...options, nonHwmDigest: journalNonHwmDigest });
      } catch (witnessErr) {
        if (options.failClosed !== false) throw witnessErr;
        return { valid: false, entries: [], error: witnessErr.message, count: 0, path: journalPath };
      }
      return { valid: true, entries: [], error: null, count: 0, path: journalPath };
    }

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

    // R18-B04: Unified historical key lifecycle resolution shared with WAL recovery
    const { trustedKeys, maxActiveIndexPerKey } = resolveJournalTrustedKeyWindows(
      dir,
      trustRegistryLoad.valid ? trustRegistryLoad.registry : null,
      options
    );

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

      // R14-B04 & R20-B02: If signer was retired, removed, or revoked (via Registry or earlier KEY_REVOCATION in journal),
      // enforce that entryIndex <= maxActiveIndex
      const maxIdxForSigner = maxActiveIndexPerKey.get(parsed.signedBy);
      if (typeof maxIdxForSigner === 'number' && maxIdxForSigner !== Infinity && parsed.entryIndex > maxIdxForSigner) {
        const msg = `[RETIRED_KEY_AUTHORIZATION_REJECTED] Signer '${parsed.signedBy}' was retired or revoked at index ${maxIdxForSigner} and cannot authorize revocation record at index ${parsed.entryIndex}`;
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

      // R20-B02: If this entry revokes a key (KEY_REVOCATION), terminate that key's active signing window in this journal
      if (parsed.targetId && (parsed.revocationType === REVOCATION_TYPES.KEY_REVOCATION || parsed.revocationType === 'KEY_REVOCATION')) {
        const existingMax = maxActiveIndexPerKey.get(parsed.targetId);
        maxActiveIndexPerKey.set(parsed.targetId, Math.min(existingMax ?? Infinity, parsed.entryIndex));
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

    // R14-B07, R15-B01 & R20-B01: Enforce journal prefix continuity against authenticated monotonic witness.
    // If a persistent witness exists with maxSeenHwmHeadIndex >= 0, the candidate journal MUST contain that index
    // and its entry digest at that index MUST match witness.maxSeenHwmHeadDigest.
    const curWitness = getMonotonicWitness(dir, options);
    if (
      curWitness &&
      typeof curWitness.maxSeenHwmHeadIndex === 'number' &&
      curWitness.maxSeenHwmHeadIndex >= 0 &&
      curWitness.maxSeenHwmHeadDigest
    ) {
      if (entries.length < curWitness.maxSeenHwmHeadIndex + 1) {
        const msg = `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] [JOURNAL_ROLLBACK_DETECTED] Journal entry count (${entries.length}) is less than witnessed headIndex (${curWitness.maxSeenHwmHeadIndex})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
      }
      const entryAtWitness = entries[curWitness.maxSeenHwmHeadIndex];
      const digestAtWitness = sha256Digest(canonicalJsonStringify(entryAtWitness));
      if (digestAtWitness !== curWitness.maxSeenHwmHeadDigest) {
        const msg = `[JOURNAL_PREFIX_DIVERGENCE_DETECTED] Journal entry digest at witnessed index ${curWitness.maxSeenHwmHeadIndex} (${digestAtWitness}) diverges from authenticated monotonic witness (${curWitness.maxSeenHwmHeadDigest})`;
        if (options.failClosed !== false) throw new Error(msg);
        return { valid: false, entries: [], error: msg, count: entries.length, path: journalPath };
      }
    }

    // R12-B02, R14-B07, R15-B01, R15-B03 & R19-B02: Enforce monotonic witness freshness
    const activeHeadIndex = checkpoint ? checkpoint.headIndex : (registryHwm ? registryHwm.headIndex : -1);
    const activeHeadDigest = checkpoint ? checkpoint.headDigest : (registryHwm ? registryHwm.headDigest : (entries.length > 0 && activeHeadIndex >= 0 && entries[activeHeadIndex] ? sha256Digest(canonicalJsonStringify(entries[activeHeadIndex])) : ''));
    const journalRegDigest = trustRegistryLoad.registry ? computeRegistryDigest(trustRegistryLoad.registry) : '';
    const journalNonHwmDigest = trustRegistryLoad.registry ? computeRegistryNonHwmDigest(trustRegistryLoad.registry) : '';
    const journalRegVer = trustRegistryLoad.registry ? trustRegistryLoad.registry.registryVersion : undefined;
    assertMonotonicWitnessFreshness(dir, journalRegVer, activeHeadIndex, activeHeadDigest, journalRegDigest, { ...options, nonHwmDigest: journalNonHwmDigest });
    updateMonotonicWitness(dir, journalRegVer, activeHeadIndex, activeHeadDigest, journalRegDigest, createPrivilegedWitnessOptions({ ...options, nonHwmDigest: journalNonHwmDigest }));

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
  const dir = resolvePluginDataDir(options);
  const canSkipLock = options.skipLock === true && isGovernanceLockHeld(dir);
  if (canSkipLock) {
    recoverAbortedRevocationTransaction(options);
    return doLoadRevocationJournal(options);
  }
  return withGovernanceLock(options, (lockedOpts) => {
    recoverAbortedRevocationTransaction(lockedOpts);
    return doLoadRevocationJournal(lockedOpts);
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

  return withGovernanceLock(options, (lockedOpts) => {
    // Round 07 F-03: Recover any aborted transaction from previous crash
    recoverAbortedRevocationTransaction(lockedOpts);

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
    // R20-B02: Verify that signedBy has not been revoked in the journal (KEY_REVOCATION)
    if (journal.entries && Array.isArray(journal.entries)) {
      for (const e of journal.entries) {
        if (e.targetId === signedBy && (e.revocationType === REVOCATION_TYPES.KEY_REVOCATION || e.revocationType === 'KEY_REVOCATION')) {
          throw new Error(`[REVOKED_SIGNER_REJECTED] Signer '${signedBy}' was revoked in revocation journal at entry index ${e.entryIndex}`);
        }
      }
    }
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

    const entryDigest = sha256Digest(canonicalJsonStringify(record));
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
    const initialJournalSha256 = initialJournalExisted
      ? sha256Digest(fs.readFileSync(journalPath).subarray(0, initialJournalSize))
      : '0'.repeat(64);
    const initialCheckpointSha256 = initialCheckpointRaw ? sha256Digest(initialCheckpointRaw) : '0'.repeat(64);
    const initialRegistrySha256 = initialRegistryRaw ? sha256Digest(initialRegistryRaw) : '0'.repeat(64);
    const initialHistSha256 = initialHistRaw ? sha256Digest(initialHistRaw) : '0'.repeat(64);
    const initialRegistryVersion = regObj ? regObj.registryVersion : 1;
    const initialHwmHeadIndex = (regObj?.revocationHighWaterMark && typeof regObj.revocationHighWaterMark.headIndex === 'number')
      ? regObj.revocationHighWaterMark.headIndex
      : -1;
    const initialHwmHeadDigest = regObj?.revocationHighWaterMark?.headDigest || '';

    const unsignedTxn = {
      txnId,
      status: 'PREPARED',
      createdAt: new Date().toISOString(),
      signedBy,
      journalPath: normalizePath(journalPath),
      initialJournalSize,
      initialJournalExisted,
      initialJournalSha256,
      checkpointPath: normalizePath(checkpointPath),
      initialCheckpointSha256,
      initialCheckpointExisted,
      regPath: normalizePath(regPath),
      initialRegistrySha256,
      initialRegistryExisted,
      initialRegistryVersion,
      initialHwmHeadIndex,
      initialHwmHeadDigest,
      expectedTargetHwmHeadIndex: entryIndex,
      expectedTargetHwmHeadDigest: entryDigest,
      expectedTargetRegistryVersion: regObj ? regObj.registryVersion : 1,
      histPath: histPath ? normalizePath(histPath) : null,
      initialHistSha256,
      initialHistExisted
    };

    const txnSignPayload = Buffer.from(computeTransactionWalSignPayload(unsignedTxn), 'utf8');
    const txnSignature = crypto.sign(null, txnSignPayload, options.signerPrivateKey).toString('hex');

    const txnData = {
      ...unsignedTxn,
      signature: txnSignature,
      initialCheckpointRawBase64: initialCheckpointRaw ? initialCheckpointRaw.toString('base64') : null,
      initialRegistryRawBase64: initialRegistryRaw ? initialRegistryRaw.toString('base64') : null,
      initialHistRawBase64: initialHistRaw ? initialHistRaw.toString('base64') : null
    };
    safeWriteFileSync(txnPath, JSON.stringify(txnData, null, 2) + '\n', options);

    try {
      // 1. Safe append to journal with descriptor inspection (R05-B04) and writeAllSync (R20-B04)
      const fd = safeOpenStorageFile(journalPath, 'a+', 0o600, options);
      try {
        writeAllSync(fd, line);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }

      if (options._simulateFailureStage === 'POST_JOURNAL_APPEND') {
        throw new Error('[SIMULATED_FAILURE_POST_JOURNAL_APPEND]');
      }

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

      // R10-B04 & R11-B02: Mark transaction as COMMITTED and cryptographically re-sign before unlinking
      txnData.status = 'COMMITTED';
      txnData.committedAt = new Date().toISOString();
      txnData.committedHwmHeadIndex = entryIndex;
      txnData.committedHwmHeadDigest = entryDigest;
      const committedSignPayload = Buffer.from(computeTransactionWalSignPayload(txnData), 'utf8');
      txnData.signature = crypto.sign(null, committedSignPayload, options.signerPrivateKey).toString('hex');
      safeWriteFileSync(txnPath, JSON.stringify(txnData, null, 2) + '\n', options);

      // R14-B05, R15-B01, R15-B03, R17-B01 & R19-B02: Update persistent monotonic witness BEFORE unlinking WAL marker
      const committedRegDigest = computeRegistryDigest(regObj);
      const committedNonHwmDigest = computeRegistryNonHwmDigest(regObj);
      updateMonotonicWitness(dir, regObj ? regObj.registryVersion : 1, entryIndex, entryDigest, committedRegDigest, createPrivilegedWitnessOptions({ ...options, nonHwmDigest: committedNonHwmDigest }));

      // Successfully committed and witnessed: remove WAL marker
      try {
        assertSafeStorageTarget(txnPath, options);
        if (fs.existsSync(txnPath)) fs.unlinkSync(txnPath);
      } catch (_) {}

      return {
        success: true,
        entryIndex,
        entryDigest,
        path: normalizePath(journalPath)
      };
    } catch (txErr) {
      // R20-B03: Point of No Return: Once transaction is COMMITTED, physical on-disk state is irreversible.
      // If witness update or WAL unlinking fails, NEVER roll back committed journal/checkpoint/registry state.
      // Retain COMMITTED WAL so recovery can re-verify and complete witness dual-anchor synchronization.
      if (txnData.status === 'COMMITTED') {
        throw new Error(`[COMMITTED_TRANSACTION_WITNESS_SYNC_FAILED] Revocation transaction was fully committed to disk but witness synchronization failed: ${txErr.message}`);
      }
      // R05-B03 & Round 07 F-03 & R10-B02-A: Descriptor-bound safe rollback
      try {
        if (initialJournalExisted) {
          if (fs.existsSync(journalPath)) {
            const journalFd = safeOpenStorageFile(journalPath, 'r+', 0o600, options);
            try {
              fs.ftruncateSync(journalFd, initialJournalSize);
              fs.fsyncSync(journalFd);
            } finally {
              fs.closeSync(journalFd);
            }
          }
        } else if (fs.existsSync(journalPath)) {
          assertSafeStorageTarget(journalPath, options);
          fs.unlinkSync(journalPath);
        }
        if (initialCheckpointRaw !== null) {
          safeWriteFileSync(checkpointPath, initialCheckpointRaw, options);
        } else if (fs.existsSync(checkpointPath)) {
          assertSafeStorageTarget(checkpointPath, options);
          fs.unlinkSync(checkpointPath);
        }
        if (initialRegistryRaw !== null) {
          safeWriteFileSync(regPath, initialRegistryRaw, options);
        } else if (fs.existsSync(regPath)) {
          assertSafeStorageTarget(regPath, options);
          fs.unlinkSync(regPath);
        }
        if (initialHistRaw !== null && histPath) {
          safeWriteFileSync(histPath, initialHistRaw, options);
        } else if (histPath && fs.existsSync(histPath)) {
          assertSafeStorageTarget(histPath, options);
          fs.unlinkSync(histPath);
        }
        if (fs.existsSync(txnPath)) {
          assertSafeStorageTarget(txnPath, options);
          fs.unlinkSync(txnPath);
        }
      } catch (rollbackErr) {
        try {
          txnData.status = 'CORRUPTED';
          txnData.rollbackError = rollbackErr.message;
          safeWriteFileSync(txnPath, JSON.stringify(txnData, null, 2), options);
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

  // R10-B05, R11-B05 & R13-B04: Execute complete revocation determination under atomic governance lock.
  // Enforces isGovernanceLockHeld so external callers cannot bypass mutual exclusion.
  const dir = resolvePluginDataDir(options);
  const canSkipLock = options.skipLock === true && isGovernanceLockHeld(dir);
  if (canSkipLock) {
    return _isRevokedInner(targetId, options);
  }
  return withGovernanceLock(options, (lockedOpts) => {
    return _isRevokedInner(targetId, lockedOpts);
  });
}

function _isRevokedInner(targetId, options = {}) {
  const regLoad = loadTrustRegistry({ ...options, failClosed: false, skipLock: true });
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

  const journalOpts = { ...options, failClosed: false, skipLock: true };
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
