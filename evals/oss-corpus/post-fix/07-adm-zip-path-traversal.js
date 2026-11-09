/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f64004fefb894c523a7143e8a88ebe6c84df25) and hardened
 * with directory separator boundary check, dangling symlink, hardlink traversal, and O_NOFOLLOW defenses (R07-F06 & R08-F06).
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryName, content) {
  const resolvedTargetDir = path.resolve(targetDir);
  const target = path.resolve(resolvedTargetDir, entryName);
  const boundaryPrefix = resolvedTargetDir.endsWith(path.sep) ? resolvedTargetDir : resolvedTargetDir + path.sep;
  if (!target.startsWith(boundaryPrefix) && target !== resolvedTargetDir) {
    throw new Error(`INVALID_FILENAME: ${entryName}`); // CVE-2018-1002204 path containment guard
  }

  // R07-F06 & R08-F06 Defense: Prevent write escalation through pre-existing dangling symlinks,
  // valid symlinks, or hardlinks within targetDir. NEVER use existsSync() which follows
  // symlinks and returns false for dangling symlinks! All filesystem exceptions fail closed.
  let curr = target;
  while (curr.startsWith(boundaryPrefix) || curr === resolvedTargetDir) {
    const stat = fs.lstatSync(curr, { throwIfNoEntry: false });
    if (stat) {
      if (stat.isSymbolicLink()) {
        throw new Error(`SECURITY_ERROR: Symlink path component detected at ${curr}`);
      }
      if (stat.isFile() && stat.nlink > 1) {
        throw new Error(`SECURITY_ERROR: Hardlink path component detected at ${curr}`);
      }
    }
    if (curr === resolvedTargetDir) break;
    curr = path.dirname(curr);
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });

  // Direct target pre-write check
  const targetStat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (targetStat && targetStat.isSymbolicLink()) {
    throw new Error(`SECURITY_ERROR: Refusing to write through symlink target at ${target}`);
  }

  // R08-F06 Defense: Atomic open with O_NOFOLLOW to neutralize TOCTOU symlink race conditions
  const openFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | (fs.constants.O_NOFOLLOW || 0);
  const fd = fs.openSync(target, openFlags, 0o644);
  try {
    fs.writeFileSync(fd, content);
  } finally {
    fs.closeSync(fd);
  }
  return target;
}
