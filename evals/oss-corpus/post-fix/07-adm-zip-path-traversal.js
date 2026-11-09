/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f64004fefb894c523a7143e8a88ebe6c84df25) and hardened
 * with directory separator boundary check to prevent sibling directory prefix bypass (/tmp/safe_evil).
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
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return target;
}
