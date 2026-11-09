/**
 * Clean Negative Control: node-tar header mode validation
 * Upstream: https://github.com/npm/node-tar.git
 * Commit: 9f2b84f3e69f88325a7a3e7e22129a65d5dfa701
 * Strict bounded numeric octal parser.
 */
export function parseNumeric(buf, offset, length) {
  let val = 0;
  const end = offset + length;
  for (let i = offset; i < end; i++) {
    const b = buf[i];
    if (b === 0 || b === 0x20) break;
    if (b < 0x30 || b > 0x37) {
      throw new Error('Invalid octal digit in tar header');
    }
    val = (val << 3) | (b - 0x30);
  }
  return val;
}
