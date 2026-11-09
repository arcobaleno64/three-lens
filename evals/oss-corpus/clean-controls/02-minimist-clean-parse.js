/**
 * Clean Negative Control: Minimist clean option parsing
 * Upstream: https://github.com/minimistjs/minimist.git
 * Commit: 6457d7440a47f329c12c4a5abfbce211c4235b93
 * Non-vulnerable option flag parser with zero prototype access.
 */
export function parseCleanArgs(args = []) {
  const flags = Object.create(null);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg.startsWith('--')) {
      const key = arg.slice(2);
      if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
        continue;
      }
      flags[key] = true;
    }
  }
  return flags;
}
