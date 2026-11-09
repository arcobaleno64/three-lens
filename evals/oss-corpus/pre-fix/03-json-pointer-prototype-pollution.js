/**
 * Authentic slice of json-pointer (CVE-2020-7709)
 * Prototype Pollution in json-pointer before 0.6.1 via set().
 */
export function set(obj, pointer, value) {
  const parts = pointer.split('/').slice(1);
  let current = obj;
  for (let i = 0; i < parts.length - 1; i++) {
    const part = parts[i];
    if (current[part] === undefined) {
      current[part] = {};
    }
    current = current[part];
  }
  const last = parts[parts.length - 1];
  current[last] = value;
  return obj;
}
