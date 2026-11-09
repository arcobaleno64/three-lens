/**
 * scripts/adapters/internal/test-root-capability.mjs
 * Private, unexported internal module for test harness capability exchange (R09-F01).
 * NOT exported by package.json and strictly NOT exposed via public adapter exports.
 */
import { AsyncLocalStorage } from 'node:async_hooks';

export const TEST_SUPERVISOR_ROOT_TOKEN = Symbol('TEST_SUPERVISOR_ROOT_TOKEN');

export const testKeyStorage = new AsyncLocalStorage();

/**
 * Executes a function within a scoped test execution context utilizing an alternative supervisor root key.
 * Strictly restricted to node:test execution contexts with the unexported capability token.
 * Normal callers of acp-adapter cannot access this capability.
 * @template T
 * @param {symbol} token
 * @param {string} pem
 * @param {() => T} fn
 * @returns {T}
 */
export function withTestSupervisorRootKey(token, pem, fn) {
  if (token !== TEST_SUPERVISOR_ROOT_TOKEN) {
    throw new Error('Unauthorized: invalid test capability token');
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('withTestSupervisorRootKey is strictly prohibited in production environments');
  }
  const isTestRunner = Boolean(
    process.env.NODE_TEST_CONTEXT ||
    process.argv.some(a => typeof a === 'string' && a.includes('--test')) ||
    process.execArgv.some(a => typeof a === 'string' && a.includes('--test'))
  );
  if (!isTestRunner) {
    throw new Error('withTestSupervisorRootKey is strictly restricted to node:test runner execution contexts');
  }
  if (!pem || typeof pem !== 'string') {
    throw new TypeError('Test supervisor root key must be a non-empty PEM string');
  }
  return testKeyStorage.run(pem, fn);
}
