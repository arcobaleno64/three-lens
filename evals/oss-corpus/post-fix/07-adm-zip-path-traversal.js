/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f64004fefb894c523a7143e8a88ebe6c84df25) and hardened
 * with directory separator boundary check, dangling symlink, hardlink traversal,
 * O_NOFOLLOW defenses, isolated staging directory, and atomic rename (R07-F06, R08-F06 & R09-F03).
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

  // R09-F03 Defense: Verify realpath of parent directory to prevent ancestor symlink redirection
  const realParent = fs.realpathSync(path.dirname(target));
  if (!realParent.startsWith(boundaryPrefix) && realParent !== resolvedTargetDir) {
    throw new Error(`SECURITY_ERROR: Ancestor directory escapes target root: ${realParent}`);
  }

  // Direct target pre-write check
  const targetStat = fs.lstatSync(target, { throwIfNoEntry: false });
  if (targetStat) {
    if (targetStat.isSymbolicLink()) {
      throw new Error(`SECURITY_ERROR: Refusing to write through symlink target at ${target}`);
    }
    if (targetStat.isFile() && targetStat.nlink > 1) {
      throw new Error(`SECURITY_ERROR: Hardlink target detected at ${target}`);
    }
  }

  // R09-F03 Defense: Write payload to an isolated staging directory on the same filesystem,
  // then atomically move into place after verifying ancestor symlink invariants.
  const stageDir = fs.mkdtempSync(path.join(resolvedTargetDir, '.admzip-stage-'));
  const stageFile = path.join(stageDir, 'payload.bin');
  const openFlags = fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL | (fs.constants.O_NOFOLLOW || 0);

  try {
    const fd = fs.openSync(stageFile, openFlags, 0o644);
    try {
      fs.writeFileSync(fd, content);
    } finally {
      fs.closeSync(fd);
    }

    // Re-verify ancestors immediately prior to atomic move
    let verifyCurr = path.dirname(target);
    while (verifyCurr.startsWith(boundaryPrefix) || verifyCurr === resolvedTargetDir) {
      const s = fs.lstatSync(verifyCurr, { throwIfNoEntry: false });
      if (!s || s.isSymbolicLink()) {
        throw new Error(`SECURITY_ERROR: Ancestor directory symlink detected at ${verifyCurr}`);
      }
      if (verifyCurr === resolvedTargetDir) break;
      verifyCurr = path.dirname(verifyCurr);
    }

    // Atomic move into final location
    fs.renameSync(stageFile, target);

    // Fail-closed post-move boundary verification
    const realFinal = fs.realpathSync(target);
    if (!realFinal.startsWith(boundaryPrefix)) {
      try { fs.unlinkSync(target); } catch {}
      throw new Error(`SECURITY_ERROR: Target escaped boundary after atomic placement: ${realFinal}`);
    }
  } finally {
    try {
      if (fs.existsSync(stageDir)) {
        fs.rmSync(stageDir, { recursive: true, force: true });
      }
    } catch {}
  }

  return target;
}
