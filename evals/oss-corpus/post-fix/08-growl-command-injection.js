/**
 * Remediated slice of node-growl (CVE-2017-16042)
 * Fixed in growl 1.9.3 (commit d71177d5331c9de4658aca62e0ac921f178b0669) by using spawn() with argument array.
 */
import { spawn } from 'node:child_process';

export function notify(msg, options = {}, fn) {
  const args = [];
  if (options.title) args.push(options.title);
  args.push(msg);
  // Remediated: passes arguments as array to spawn(), avoiding shell command injection
  const cmd = 'growlnotify';
  return spawn(cmd, args);
}
