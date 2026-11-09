/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f64004fefb894c523a7143e8a88ebe6c84df25) and hardened
 * with directory separator boundary check and symlink traversal defense (R06-F05).
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

  // R06-F05 Defense: Prevent write escalation through pre-existing symlinks within targetDir
  let curr = target;
  while (curr.startsWith(boundaryPrefix) || curr === resolvedTargetDir) {
    if (fs.existsSync(curr)) {
      const stat = fs.lstatSync(curr);
      if (stat.isSymbolicLink()) {
        throw new Error(`SECURITY_ERROR: Symlink path component detected at ${curr}`);
      }
    }
    if (curr === resolvedTargetDir) break;
    curr = path.dirname(curr);
  }

  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return target;
}
