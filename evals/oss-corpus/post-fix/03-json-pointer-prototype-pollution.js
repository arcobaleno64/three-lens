/**
 * Remediated slice of json-pointer (CVE-2020-7709)
 * Fixed in json-pointer 0.6.1 (PR #34 / commit 1dbd1ed) by skipping dangerous prototype keys.
 */
export function set(obj, pointer, value) {
  const parts = pointer.split('/').slice(1);
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (part === '__proto__' || part === 'constructor' || part === 'prototype') {
      continue; // CVE-2020-7709 official fix (PR #34)
    }
    if (current[part] === undefined) {
      current[part] = {};
    }
    current = current[part];
  }
  const last = parts[parts.length - 1];
  current[last] = value;
  return obj;
}
