/**
 * Clean Negative Control: Lodash clamp function
 * Upstream: https://github.com/lodash/lodash.git
 * Commit: 4a4f6d895521e64e5659846b0a8f7c9e0a0559f2
 * Non-vulnerable, mature utility function.
 */
export function clamp(number, lower, upper) {
  number = +number;
  lower = +lower;
  upper = +upper;
  lower = lower === lower ? lower : 0;
  upper = upper === upper ? upper : 0;
  if (number === number) {
    number = number <= upper ? number : upper;
    number = number >= lower ? number : lower;
  }
  return number;
}
