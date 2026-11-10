#!/usr/bin/env node
/**
 * path-containment.mjs
 * Authoritative Trusted Computing Base (TCB) module for path boundaries and safe I/O.
 *
 * Enforces:
 * 1. Lexical path containment algebra (path.relative, preventing .. escapes,
 *    drive-letter confusion, and sibling-prefix collisions like scratch/context-evil).
 * 2. Symlink-aware canonical realpath containment (CWE-59 defense), failing closed
 *    on dangling links, inaccessible paths, or boundary escapes.
 * 3. Descriptor-bound, TOCTOU-resistant file reading (open -> fstat -> realpath
 *    containment + 64-bit dev/ino identity binding -> readSync from descriptor ->
 *    closeSync) to mitigate time-of-check to time-of-use filesystem race conditions
 *    (CodeQL js/file-system-race).
 *
 * Zero external npm dependencies. Pure Node.js builtins.
 */

import fs from 'node:fs';
import path from 'node:path';

/**
 * Validates that candidatePath does not escape rootDir via directory traversal.
 * Uses strict containment algebra instead of prefix string matching.
 *
 * @param {string} rootDir - Base directory that must contain the candidate path.
 * @param {string} candidatePath - Target path to test.
 * @returns {boolean} True if candidatePath is within rootDir; false otherwise.
 */
export function isPathContained(rootDir, candidatePath) {
  if (!rootDir || !candidatePath || typeof rootDir !== 'string' || typeof candidatePath !== 'string') {
    return false;
  }

  // Deny raw traversal sequences explicitly
  if (
    candidatePath.includes('..\\') ||
    candidatePath.includes('../') ||
    candidatePath === '..' ||
    candidatePath.endsWith('/..') ||
    candidatePath.endsWith('\\..')
  ) {
    return false;
  }

  const resolvedRoot = path.resolve(rootDir);
  const resolvedCandidate = path.isAbsolute(candidatePath)
    ? path.resolve(candidatePath)
    : path.resolve(resolvedRoot, candidatePath);

  const rel = path.relative(resolvedRoot, resolvedCandidate);
  return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

/**
 * Symlink-aware containment check (CWE-59 defense).
 * Resolves both rootDir and candidatePath through fs.realpathSync before checking containment.
 * Fails closed (returns false) if the path cannot be resolved (dangling symlink, permission error).
 *
 * @param {string} rootDir - Base directory that must contain the resolved target.
 * @param {string} candidatePath - Target path or symlink to test.
 * @returns {boolean} True if canonical target is within rootDir; false otherwise.
 */
export function isRealPathContained(rootDir, candidatePath) {
  if (!rootDir || !candidatePath || typeof rootDir !== 'string' || typeof candidatePath !== 'string') {
    return false;
  }

  try {
    const rootReal = fs.realpathSync(path.resolve(rootDir));
    const candidateResolved = path.isAbsolute(candidatePath)
      ? path.resolve(candidatePath)
      : path.resolve(path.resolve(rootDir), candidatePath);
    const candidateReal = fs.realpathSync(candidateResolved);
    const rel = path.relative(rootReal, candidateReal);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  } catch {
    // Default-deny: an unresolvable path (dangling link, inaccessible, etc.) cannot be proven safe
    return false;
  }
}

/**
 * Asserts that candidatePath is strictly contained within rootDir.
 *
 * @param {string} rootDir - Authorized root boundary.
 * @param {string} candidatePath - Candidate file path.
 * @param {string} [label='Path'] - Label for error reporting.
 * @returns {{ valid: boolean, error?: string }}
 */
export function assertContainedPath(rootDir, candidatePath, label = 'Path') {
  if (!isPathContained(rootDir, candidatePath)) {
    return { valid: false, error: `${label} escapes root boundary (lexical check): '${candidatePath}'` };
  }
  if (fs.existsSync(candidatePath) && !isRealPathContained(rootDir, candidatePath)) {
    return { valid: false, error: `${label} escapes root boundary (realpath symlink check): '${candidatePath}'` };
  }
  return { valid: true };
}

/**
 * Reads a file contained within rootDir via a dedicated file descriptor, binding
 * the post-open realpath containment check to the opened descriptor's identity.
 *
 * Sequence:
 * 1. Lexical boundary assertion (isPathContained).
 * 2. If allowSymlinks is false, lstat check rejects symbolic links.
 * 3. Open dedicated file descriptor (fs.openSync, with O_NOFOLLOW when allowSymlinks is false and supported by OS).
 * 4. Inspect opened file handle via fs.fstatSync (asserts isFile and size limit).
 * 5. Verify fs.realpathSync containment on target and bind the opened descriptor's
 *    64-bit device/file-ID identity (fstatSync bigint dev/ino) to statSync(realPath, { bigint: true })
 *    (and pre-open lstatSync when allowSymlinks is false), failing closed on mismatch or zero identity.
 *    Guarantee & platform limits: on POSIX and Windows NTFS/ReFS (via libuv GetFileInformationByHandle),
 *    64-bit dev/ino uniquely identifies the opened file and detects post-open path swaps (e.g. symlink
 *    to regular file replacement between open and realpath). On filesystems that do not report stable
 *    non-zero file IDs (ino === 0n or dev === 0n), identity binding cannot be proven and fails closed.
 * 6. Read content directly from file descriptor into buffer via fs.readSync.
 * 7. Guaranteed closeSync in finally block.
 *
 * @param {string} rootDir - Enclosing boundary directory.
 * @param {string} candidatePath - File path to read.
 * @param {object} [options={}] - Options.
 * @param {string|null} [options.encoding='utf8'] - Output encoding (null for Buffer).
 * @param {boolean} [options.allowSymlinks=false] - Whether to permit symlinks.
 * @param {number} [options.maxSizeBytes=10485760] - Max allowable size (default 10MB).
 * @returns {{ ok: boolean, content: string|Buffer|null, size?: number, realPath?: string, stat?: fs.Stats, error?: string }}
 */
export function safeReadFileContained(rootDir, candidatePath, options = {}) {
  const {
    encoding = 'utf8',
    allowSymlinks = false,
    maxSizeBytes = 10 * 1024 * 1024
  } = options;

  if (!rootDir || !candidatePath || typeof rootDir !== 'string' || typeof candidatePath !== 'string') {
    return { ok: false, error: 'Invalid rootDir or candidatePath parameter', content: null, stat: null };
  }

  // 1. Lexical boundary assertion
  if (!isPathContained(rootDir, candidatePath)) {
    return { ok: false, error: `Path escapes root directory (lexical check): '${candidatePath}'`, content: null, stat: null };
  }

  const resolvedRoot = path.resolve(rootDir);
  const resolvedPath = path.isAbsolute(candidatePath)
    ? path.resolve(candidatePath)
    : path.resolve(resolvedRoot, candidatePath);

  // 2. Symlink rejection on declared path if symlinks not allowed
  let preOpenLstatBig = null;
  if (!allowSymlinks) {
    try {
      preOpenLstatBig = fs.lstatSync(resolvedPath, { bigint: true });
      if (preOpenLstatBig.isSymbolicLink()) {
        return { ok: false, error: `File is a symbolic link; symlinks are rejected under default-deny: '${candidatePath}'`, content: null, stat: null };
      }
    } catch (err) {
      return { ok: false, error: `Failed inspecting file status: ${err.message}`, content: null, stat: null };
    }
  }

  // 3. Open file descriptor to anchor the target against substitution races
  let fd = null;
  const openFlags = !allowSymlinks && typeof fs.constants?.O_NOFOLLOW === 'number'
    ? (fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW)
    : 'r';
  try {
    fd = fs.openSync(resolvedPath, openFlags);
  } catch (err) {
    return { ok: false, error: `Failed opening file: ${err.message}`, content: null, stat: null };
  }

  try {
    // 4. Inspect opened file descriptor directly via fstat
    const fstat = fs.fstatSync(fd);
    if (!fstat.isFile()) {
      return { ok: false, error: `Target is not a regular file: '${candidatePath}'`, content: null, stat: null };
    }

    if (maxSizeBytes && fstat.size > maxSizeBytes) {
      return { ok: false, error: `File size (${fstat.size} bytes) exceeds maximum bound (${maxSizeBytes} bytes)`, content: null, stat: null };
    }

    // 5. Assert realpath containment on opened file and bind descriptor identity
    let realPath;
    try {
      realPath = fs.realpathSync(resolvedPath);
    } catch (err) {
      return { ok: false, error: `Failed resolving realpath: ${err.message}`, content: null, stat: null };
    }

    if (!isRealPathContained(resolvedRoot, realPath)) {
      return { ok: false, error: `Resolved target realpath escapes root directory: '${realPath}'`, content: null, stat: null };
    }

    let fdStatBig;
    let realStatBig;
    try {
      fdStatBig = fs.fstatSync(fd, { bigint: true });
      realStatBig = fs.statSync(realPath, { bigint: true });
    } catch (err) {
      return { ok: false, error: `Failed verifying file descriptor identity: ${err.message}`, content: null, stat: null };
    }

    if (
      fdStatBig.ino === 0n ||
      realStatBig.ino === 0n ||
      fdStatBig.dev === 0n ||
      realStatBig.dev === 0n ||
      fdStatBig.dev !== realStatBig.dev ||
      fdStatBig.ino !== realStatBig.ino ||
      (preOpenLstatBig !== null && (fdStatBig.dev !== preOpenLstatBig.dev || fdStatBig.ino !== preOpenLstatBig.ino))
    ) {
      return {
        ok: false,
        error: `File descriptor identity mismatch between opened handle and resolved realpath: '${candidatePath}'`,
        content: null,
        stat: null
      };
    }

    // 6. Read content directly from file descriptor
    const buffer = Buffer.alloc(fstat.size);
    let bytesRead = 0;
    while (bytesRead < fstat.size) {
      const chunk = fs.readSync(fd, buffer, bytesRead, fstat.size - bytesRead, bytesRead);
      if (chunk === 0) break;
      bytesRead += chunk;
    }

    const content = encoding ? buffer.subarray(0, bytesRead).toString(encoding) : buffer.subarray(0, bytesRead);
    return {
      ok: true,
      content,
      realPath: realPath.replace(/\\/g, '/'),
      stat: fstat,
      size: bytesRead
    };
  } catch (err) {
    return { ok: false, error: `Failed reading file content: ${err.message}`, content: null, stat: null };
  } finally {
    if (fd !== null) {
      try {
        fs.closeSync(fd);
      } catch {}
    }
  }
}
