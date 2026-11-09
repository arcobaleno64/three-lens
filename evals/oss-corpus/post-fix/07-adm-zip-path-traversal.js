/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f6400) by asserting destination starts with targetDir.
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryName, content) {
  const resolvedTargetDir = path.resolve(targetDir);
  const target = path.resolve(resolvedTargetDir, entryName);
  if (!target.startsWith(resolvedTargetDir + path.sep) && target !== resolvedTargetDir) {
    throw new Error(`INVALID_FILENAME: ${entryName}`); // CVE-2018-1002204 official fix
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return target;
}
