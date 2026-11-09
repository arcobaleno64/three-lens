/**
 * Remediated slice of minimist (CVE-2020-7598 & CVE-2021-44906)
 * Remediated by checking for __proto__, constructor, and prototype in setKey.
 */
export function setKey(obj, keys, value) {
  let o = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    const key = keys[i];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return; // Mitigation
    if (o[key] === undefined) o[key] = {};
    o = o[key];
  }
  const lastKey = keys[keys.length - 1];
  if (lastKey === '__proto__' || lastKey === 'constructor' || lastKey === 'prototype') return; // Mitigation
  o[lastKey] = value;
}

export function parseArgs(args) {
  const flags = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const parts = arg.slice(2).split('=');
      const keys = parts[0].split('.');
      const val = parts[1] === undefined ? true : parts[1];
      setKey(flags, keys, val);
    }
  }
  return flags;
}
