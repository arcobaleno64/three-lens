/**
 * Remediated slice of adm-zip (CVE-2018-1002204)
 * Fixed in adm-zip 0.4.9 (commit 62f64004fefb894c523a7143e8a88ebe6c84df25) by asserting destination starts with targetDir.
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryName, content) {
  const target = path.resolve(targetDir, entryName);
  if (!target.startsWith(targetDir)) {
    throw new Error(`INVALID_FILENAME: ${entryName}`); // CVE-2018-1002204 official fix
  }
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return target;
}
