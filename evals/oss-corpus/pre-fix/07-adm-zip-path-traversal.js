/**
 * Authentic slice of adm-zip (CVE-2018-1002204)
 * Zip-Slip directory traversal in adm-zip before 0.4.9 on file extraction.
 */
import path from 'node:path';
import fs from 'node:fs';

export function extractEntry(targetDir, entryName, content) {
  // Vulnerable: path.resolve concatenates entryName without directory containment assertion
  const target = path.resolve(targetDir, entryName);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, content);
  return target;
}
