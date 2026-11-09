/**
 * Authentic slice of node-growl (CVE-2017-16042)
 * Command Injection in growl before 1.10.2 via exec() string concatenation.
 */
import { exec } from 'node:child_process';

export function notify(msg, options = {}, fn) {
  const args = ['growlnotify'];
  if (options.title) args.push(options.title);
  args.push(msg);
  // Vulnerable: concatenates arguments into shell command string passed to exec
  exec(args.join(' '), fn);
}
