#!/usr/bin/env node
/**
 * scripts/adapters/acp-transport-adapter.mjs
 * Milestone 5.4 Phase 1 (M54-P1-F04 / R13-F04-01):
 * Native Agent Client Protocol (ACP) Transport Prioritization and Governance Adapter.
 *
 * Requirements:
 * 1. Prioritize Native ACP: Selects native `agy acp --stdio` (Antigravity ACP Server 1.5.1)
 *    as HIGHEST priority over custom bridge layers and legacy fallback.
 * 2. Fail-Closed Handshake Governance: Validates JSON-RPC 2.0 initialize handshake
 *    including protocolVersion, server identity, and required agent capabilities.
 * 3. Safe Fallback & Confinement: On handshake failure or timeout, safely terminates fail-closed
 *    or transitions to hermetic fallback only if explicitly authorized.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync, spawn } from 'node:child_process';

export const ACP_PROTOCOL_VERSION = 1;
export const ACP_PROTOCOL_NAME = 'ACP_STDIO_JSONRPC_V1';

export const TRANSPORT_PRIORITIES = Object.freeze({
  NATIVE_ACP: 1,       // Highest priority
  ISOLATED_STDIO: 2,   // Secondary fallback
  NONE: 99             // Fail-closed / Disabled
});

export const TRANSPORT_STATUS = Object.freeze({
  ACTIVE: 'ACTIVE',                 // Live persistent session with bidirectional communication
  PROBE_VERIFIED: 'PROBE_VERIFIED', // One-time handshake probe verified
  FALLBACK: 'FALLBACK',             // Degraded to isolated stdio
  TERMINATED: 'TERMINATED',         // Active session has terminated/disconnected
  FAILED: 'FAILED'                  // Failed closed
});

/**
 * Validates an ACP JSON-RPC 2.0 handshake initialization response.
 *
 * @param {object|string} rawResponse - Handshake response payload
 * @param {object} [options={}] - Validation options
 * @param {number|string} [options.expectedId] - Expected JSON-RPC request ID
 * @returns {{ valid: boolean, capabilities: object|null, agentInfo: object|null, error: string|null }}
 */
export function validateAcpHandshake(rawResponse, options = {}) {
  if (!rawResponse) {
    return { valid: false, capabilities: null, agentInfo: null, error: 'Empty ACP handshake response' };
  }

  let parsed = rawResponse;
  if (typeof rawResponse === 'string') {
    try {
      parsed = JSON.parse(rawResponse.trim());
    } catch (err) {
      return { valid: false, capabilities: null, agentInfo: null, error: `Malformed JSON-RPC handshake: ${err.message}` };
    }
  }

  if (typeof parsed !== 'object' || parsed === null) {
    return { valid: false, capabilities: null, agentInfo: null, error: 'Invalid JSON-RPC payload: expected object' };
  }

  if (parsed.jsonrpc !== '2.0') {
    return { valid: false, capabilities: null, agentInfo: null, error: `Unsupported JSON-RPC version: ${parsed.jsonrpc}` };
  }

  if (options.expectedId !== undefined && parsed.id !== options.expectedId) {
    return {
      valid: false,
      capabilities: null,
      agentInfo: null,
      error: `JSON-RPC response ID mismatch: expected ${options.expectedId}, got ${parsed.id}`
    };
  }

  if (parsed.error) {
    const errMsg = typeof parsed.error === 'string' ? parsed.error : (parsed.error.message || JSON.stringify(parsed.error));
    return { valid: false, capabilities: null, agentInfo: null, error: `Server returned JSON-RPC error: ${errMsg}` };
  }

  const result = parsed.result;
  if (!result || typeof result !== 'object') {
    return { valid: false, capabilities: null, agentInfo: null, error: 'Missing result object in initialize response' };
  }

  if (result.protocolVersion !== ACP_PROTOCOL_VERSION) {
    return {
      valid: false,
      capabilities: null,
      agentInfo: null,
      error: `Protocol version mismatch: expected ${ACP_PROTOCOL_VERSION}, got ${result.protocolVersion}`
    };
  }

  // Gate 0 (R14-F04-02): Strict Server Identity Verification
  // agentInfo with non-empty string name and version is required under Default-Deny
  const agentInfo = result.agentInfo;
  if (
    !agentInfo ||
    typeof agentInfo !== 'object' ||
    typeof agentInfo.name !== 'string' ||
    !agentInfo.name.trim() ||
    typeof agentInfo.version !== 'string' ||
    !agentInfo.version.trim()
  ) {
    return {
      valid: false,
      capabilities: null,
      agentInfo: null,
      error: 'Missing or invalid agentInfo in initialize result: non-empty name and version are strictly required'
    };
  }

  const caps = result.agentCapabilities;
  if (!caps || typeof caps !== 'object') {
    return { valid: false, capabilities: null, agentInfo: null, error: 'Missing agentCapabilities in initialize result' };
  }

  // Gate 0 (R14-F04-02): Verify core native capabilities (non-empty prompt and session capabilities)
  const promptCaps = caps.promptCapabilities;
  const sessionCaps = caps.sessionCapabilities || caps.session_capabilities;

  if (!promptCaps || typeof promptCaps !== 'object' || Object.keys(promptCaps).length === 0) {
    return {
      valid: false,
      capabilities: null,
      agentInfo: null,
      error: 'Incomplete native ACP capabilities profile: promptCapabilities must declare active capabilities'
    };
  }

  if (!sessionCaps || typeof sessionCaps !== 'object' || Object.keys(sessionCaps).length === 0) {
    return {
      valid: false,
      capabilities: null,
      agentInfo: null,
      error: 'Incomplete native ACP capabilities profile: sessionCapabilities must declare active capabilities'
    };
  }

  return {
    valid: true,
    capabilities: caps,
    agentInfo,
    authMethods: result.authMethods || [],
    error: null
  };
}

/**
 * Resolves the active execution transport following the Native ACP Prioritization policy.
 *
 * @param {object} [options={}]
 * @param {boolean} [options.enableNativeAcp=true] - Whether native ACP is enabled
 * @param {object|string} [options.probeResponse=null] - Pre-probed handshake response
 * @param {number|string} [options.expectedId] - Expected JSON-RPC request ID
 * @param {boolean} [options.allowFallback=false] - Whether fallback to isolated stdio is permitted on failure
 * @param {boolean} [options.probeOnly=false] - Whether this is an ephemeral verification probe rather than an active session
 * @returns {{ transport: string, priority: number, protocol: string, status: string, agentInfo?: object, capabilities?: object, error: string|null }}
 */
export function resolveTransport(options = {}) {
  const {
    enableNativeAcp = true,
    probeResponse = null,
    expectedId = undefined,
    allowFallback = false,
    probeOnly = false
  } = options;

  // 1. Highest Priority: Native ACP
  if (enableNativeAcp) {
    if (probeResponse) {
      const validation = validateAcpHandshake(probeResponse, { expectedId });
      if (validation.valid) {
        return {
          transport: 'NATIVE_ACP',
          priority: TRANSPORT_PRIORITIES.NATIVE_ACP,
          protocol: ACP_PROTOCOL_NAME,
          status: probeOnly ? TRANSPORT_STATUS.PROBE_VERIFIED : TRANSPORT_STATUS.ACTIVE,
          agentInfo: validation.agentInfo,
          capabilities: validation.capabilities,
          error: null
        };
      }

      // Handshake failed under Default-Deny
      if (!allowFallback) {
        return {
          transport: 'NONE',
          priority: TRANSPORT_PRIORITIES.NONE,
          protocol: 'UNKNOWN',
          status: TRANSPORT_STATUS.FAILED,
          error: `Native ACP handshake failed: ${validation.error} (Fail-Closed)`
        };
      }

      // Fallback permitted
      return {
        transport: 'ISOLATED_STDIO',
        priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
        protocol: 'HERMETIC_STDIO_V1',
        status: TRANSPORT_STATUS.FALLBACK,
        fallbackReason: validation.error,
        error: null
      };
    }

    // Native ACP enabled but no probe response available -> requires probe
    if (!allowFallback) {
      return {
        transport: 'NONE',
        priority: TRANSPORT_PRIORITIES.NONE,
        protocol: 'UNKNOWN',
        status: TRANSPORT_STATUS.FAILED,
        error: 'Native ACP enabled but unverified; handshake probe required (Fail-Closed)'
      };
    }
  }

  // 2. Secondary Fallback: Isolated Stdio
  if (allowFallback) {
    return {
      transport: 'ISOLATED_STDIO',
      priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
      protocol: 'HERMETIC_STDIO_V1',
      status: TRANSPORT_STATUS.ACTIVE,
      error: null
    };
  }

  // Fail-Closed
  return {
    transport: 'NONE',
    priority: TRANSPORT_PRIORITIES.NONE,
    protocol: 'UNKNOWN',
    status: TRANSPORT_STATUS.FAILED,
    error: 'No compliant transport available (Fail-Closed)'
  };
}

/**
 * Actively probes the native ACP server by spawning `agy acp --stdio`
 * and conducting a real JSON-RPC 2.0 initialize handshake.
 *
 * Gate 0 (R15-F04-01): Decouples handshake validation from process exit code.
 * Standard ACP servers are persistent daemons that do not terminate after initialize.
 * Stdout is parsed first for a valid handshake response even if spawnSync timed out.
 *
 * @param {object} [options={}]
 * @param {string} [options.agyBin] - Antigravity executable path
 * @param {string[]} [options.args] - CLI arguments (default ['acp', '--stdio'])
 * @param {number} [options.timeoutMs=5000] - Handshake timeout in ms
 * @param {boolean} [options.allowFallback=false] - Whether fallback to isolated stdio is allowed
 * @returns {object} Transport resolution object with status 'PROBE_VERIFIED' on success
 */
export function probeNativeAcpServer(options = {}) {
  const {
    agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy',
    args = ['acp', '--stdio'],
    timeoutMs = 5000,
    allowFallback = false
  } = options;

  const initPayload = JSON.stringify({
    jsonrpc: '2.0',
    id: 1,
    method: 'initialize',
    params: {
      protocolVersion: ACP_PROTOCOL_VERSION,
      clientInfo: { name: 'agy-security-audit', version: '1.0.0' },
      capabilities: {}
    }
  }) + '\n';

  let spawnRes;
  try {
    spawnRes = spawnSync(agyBin, args, {
      input: initPayload,
      encoding: 'utf8',
      timeout: timeoutMs,
      stdio: ['pipe', 'pipe', 'pipe']
    });
  } catch (err) {
    return resolveTransport({
      enableNativeAcp: false,
      allowFallback,
      error: `Failed to spawn ACP binary: ${err.message}`
    });
  }

  // Gate 0 (R15-F04-01): Check stdout first for valid handshake response.
  // Persistent ACP servers do not exit after responding, resulting in timeout (ETIMEDOUT / SIGTERM).
  // If stdout contains a valid initialize response, the probe is verified.
  const rawStdout = spawnRes.stdout ? spawnRes.stdout.toString() : '';
  const lines = rawStdout.trim().split(/\r?\n/).filter(Boolean);
  const responseLine = lines.find(l => l.includes('"jsonrpc"') && (l.includes('"result"') || l.includes('"error"'))) || lines[0];

  if (responseLine) {
    const validation = validateAcpHandshake(responseLine, { expectedId: 1 });
    if (validation.valid) {
      return {
        transport: 'NATIVE_ACP',
        priority: TRANSPORT_PRIORITIES.NATIVE_ACP,
        protocol: ACP_PROTOCOL_NAME,
        status: TRANSPORT_STATUS.PROBE_VERIFIED,
        agentInfo: validation.agentInfo,
        capabilities: validation.capabilities,
        probeType: 'EPHEMERAL_STDIO_PROBE',
        error: null
      };
    }
  }

  // If stdout did not contain a valid handshake, handle process error or exit code under Default-Deny
  const reason = spawnRes.error
    ? spawnRes.error.message
    : (spawnRes.stderr?.trim() || (spawnRes.status !== 0 ? `Exit code ${spawnRes.status}` : 'No valid handshake received'));

  if (allowFallback) {
    return {
      transport: 'ISOLATED_STDIO',
      priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
      protocol: 'HERMETIC_STDIO_V1',
      status: TRANSPORT_STATUS.FALLBACK,
      fallbackReason: `Native ACP probe execution failed: ${reason}`,
      error: null
    };
  }

  return {
    transport: 'NONE',
    priority: TRANSPORT_PRIORITIES.NONE,
    protocol: 'UNKNOWN',
    status: TRANSPORT_STATUS.FAILED,
    error: `Native ACP probe execution failed: ${reason} (Fail-Closed)`
  };
}

/**
 * Asynchronously probes native ACP server with non-blocking stream listening.
 * Completes as soon as the first JSON-RPC handshake line arrives, without waiting
 * for the server process to exit or reach timeout.
 *
 * @param {object} [options={}]
 * @returns {Promise<object>} Transport resolution with status 'PROBE_VERIFIED'
 */
export async function probeNativeAcpServerAsync(options = {}) {
  const {
    agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy',
    args = ['acp', '--stdio'],
    timeoutMs = 5000,
    allowFallback = false
  } = options;

  return new Promise((resolve) => {
    let settled = false;
    let timer = null;
    let child = null;

    const cleanup = () => {
      if (timer) clearTimeout(timer);
      if (child && !child.killed) {
        try { child.kill('SIGTERM'); } catch {}
      }
    };

    const fail = (reason) => {
      if (settled) return;
      settled = true;
      cleanup();

      if (allowFallback) {
        resolve({
          transport: 'ISOLATED_STDIO',
          priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
          protocol: 'HERMETIC_STDIO_V1',
          status: TRANSPORT_STATUS.FALLBACK,
          fallbackReason: `Native ACP async probe failed: ${reason}`,
          error: null
        });
      } else {
        resolve({
          transport: 'NONE',
          priority: TRANSPORT_PRIORITIES.NONE,
          protocol: 'UNKNOWN',
          status: TRANSPORT_STATUS.FAILED,
          error: `Native ACP async probe failed: ${reason} (Fail-Closed)`
        });
      }
    };

    try {
      child = spawn(agyBin, args, {
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (err) {
      return fail(`Failed to spawn ACP binary: ${err.message}`);
    }

    // Drain stderr continuously to prevent pipe buffer backpressure during async probe (Codex P2)
    if (child.stderr) {
      child.stderr.on('data', () => {});
    }

    timer = setTimeout(() => {
      fail(`Handshake timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    child.on('error', (err) => {
      fail(err.message);
    });

    let buffer = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      if (settled) return;
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        const validation = validateAcpHandshake(line, { expectedId: 1 });
        if (validation.valid) {
          settled = true;
          cleanup();
          return resolve({
            transport: 'NATIVE_ACP',
            priority: TRANSPORT_PRIORITIES.NATIVE_ACP,
            protocol: ACP_PROTOCOL_NAME,
            status: TRANSPORT_STATUS.PROBE_VERIFIED,
            agentInfo: validation.agentInfo,
            capabilities: validation.capabilities,
            probeType: 'NON_BLOCKING_STREAM_PROBE',
            error: null
          });
        } else if (line.includes('"error"')) {
          return fail(`Server returned error: ${validation.error}`);
        }
      }
    });

    child.on('exit', (code, sig) => {
      if (!settled) {
        fail(`ACP server exited prematurely with code ${code}, signal ${sig}`);
      }
    });

    const initPayload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: ACP_PROTOCOL_VERSION,
        clientInfo: { name: 'agy-security-audit', version: '1.0.0' },
        capabilities: {}
      }
    }) + '\n';

    try {
      child.stdin.write(initPayload);
    } catch (err) {
      fail(`Failed to write initialize payload: ${err.message}`);
    }
  });
}

/**
 * Asynchronously establishes a persistent, active Native ACP session.
 * Keeps the server process running, maintains a bidirectional request/response dispatcher,
 * and dynamically tracks server exit invalidation across the session lifecycle (R16-F04-01).
 *
 * @param {object} [options={}]
 * @returns {Promise<object>} Active transport session with status 'ACTIVE'
 */
export async function connectNativeAcpTransport(options = {}) {
  const {
    agyBin = process.platform === 'win32' ? 'agy.exe' : 'agy',
    args = ['acp', '--stdio'],
    timeoutMs = 5000,
    allowFallback = false
  } = options;

  return new Promise((resolve) => {
    let handshakeSettled = false;
    let timer = null;
    let child = null;
    let sessionStatus = TRANSPORT_STATUS.FAILED;
    let nextRequestId = 2;
    const pendingRequests = new Map();
    const messageListeners = new Set();
    const closeListeners = new Set();

    // Gate 0 (R17-F04-02): Unified at-most-once close notification across all termination pathways
    let hasNotifiedClose = false;
    const notifyCloseOnce = (event) => {
      if (hasNotifiedClose) return;
      hasNotifiedClose = true;
      for (const cb of closeListeners) {
        try { cb(event); } catch {}
      }
    };

    const failHandshake = (reason) => {
      if (handshakeSettled) return;
      handshakeSettled = true;
      if (timer) clearTimeout(timer);
      sessionStatus = TRANSPORT_STATUS.FAILED;
      if (child && !child.killed) {
        try { child.kill('SIGTERM'); } catch {}
      }

      if (allowFallback) {
        resolve({
          transport: 'ISOLATED_STDIO',
          priority: TRANSPORT_PRIORITIES.ISOLATED_STDIO,
          protocol: 'HERMETIC_STDIO_V1',
          status: TRANSPORT_STATUS.FALLBACK,
          fallbackReason: `Native ACP connection failed: ${reason}`,
          error: null
        });
      } else {
        resolve({
          transport: 'NONE',
          priority: TRANSPORT_PRIORITIES.NONE,
          protocol: 'UNKNOWN',
          status: TRANSPORT_STATUS.FAILED,
          error: `Native ACP connection failed: ${reason} (Fail-Closed)`
        });
      }
    };

    try {
      child = spawn(agyBin, args, {
        stdio: ['pipe', 'pipe', 'pipe']
      });
    } catch (err) {
      return failHandshake(`Failed to spawn ACP binary: ${err.message}`);
    }

    // Drain stderr continuously to prevent pipe buffer backpressure (Codex P2)
    if (child.stderr) {
      child.stderr.on('data', () => {});
    }

    // Handle asynchronous errors on stdin stream to prevent unhandled EPIPE crash (Codex P2)
    if (child.stdin) {
      child.stdin.on('error', (err) => {
        sessionStatus = TRANSPORT_STATUS.TERMINATED;
        for (const [id, req] of pendingRequests.entries()) {
          req.reject(new Error(`ACP stdin error: ${err.message}`));
        }
        pendingRequests.clear();
        notifyCloseOnce({ code: null, signal: null, reason: `ACP stdin error: ${err.message}`, origin: 'error' });
      });
    }

    timer = setTimeout(() => {
      failHandshake(`Connection handshake timed out after ${timeoutMs}ms`);
    }, timeoutMs);

    // Dynamic Server Exit & Invalidation Governance across full lifecycle (R16-F04-01 / R17-F04-02):
    child.on('exit', (code, sig) => {
      sessionStatus = TRANSPORT_STATUS.TERMINATED;
      const termMsg = `ACP server terminated with exit code ${code}, signal ${sig}`;

      // Reject all pending in-flight requests immediately fail-closed
      for (const [id, req] of pendingRequests.entries()) {
        req.reject(new Error(`Channel terminated: ${termMsg}`));
      }
      pendingRequests.clear();

      if (!handshakeSettled) {
        failHandshake(`ACP server exited prematurely with code ${code}, signal ${sig}`);
      } else {
        notifyCloseOnce({ code: code ?? 0, signal: sig || null, reason: termMsg, origin: 'exit' });
      }
    });

    child.on('error', (err) => {
      sessionStatus = TRANSPORT_STATUS.TERMINATED;
      for (const [id, req] of pendingRequests.entries()) {
        req.reject(new Error(`Channel error: ${err.message}`));
      }
      pendingRequests.clear();

      if (!handshakeSettled) {
        failHandshake(err.message);
      } else {
        notifyCloseOnce({ code: 1, signal: null, reason: `Channel error: ${err.message}`, origin: 'error' });
      }
    });

    let buffer = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      buffer += chunk;
      const lines = buffer.split(/\r?\n/);
      buffer = lines.pop();

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        let parsed = null;
        try {
          parsed = JSON.parse(trimmed);
        } catch {
          continue;
        }

        // 1. Handshake Phase
        if (!handshakeSettled) {
          const validation = validateAcpHandshake(parsed, { expectedId: 1 });
          if (validation.valid) {
            handshakeSettled = true;
            if (timer) clearTimeout(timer);
            sessionStatus = TRANSPORT_STATUS.ACTIVE;

            const session = {
              transport: 'NATIVE_ACP',
              priority: TRANSPORT_PRIORITIES.NATIVE_ACP,
              protocol: ACP_PROTOCOL_NAME,
              get status() { return sessionStatus; },
              agentInfo: validation.agentInfo,
              capabilities: validation.capabilities,
              process: child,
              isActive: () => sessionStatus === TRANSPORT_STATUS.ACTIVE && !child.killed,
              // Direct message sending (Fail-Closed if not active)
              send: (message) => {
                if (sessionStatus !== TRANSPORT_STATUS.ACTIVE || child.killed) {
                  throw new Error(`Cannot send message: ACP transport is not active (status: ${sessionStatus})`);
                }
                const payload = typeof message === 'string' ? message : JSON.stringify(message);
                child.stdin.write(payload.endsWith('\n') ? payload : payload + '\n');
              },
              // Bidirectional JSON-RPC Request/Response (R16-F04-01)
              request: (method, params = {}, reqTimeoutMs = 5000) => {
                if (sessionStatus !== TRANSPORT_STATUS.ACTIVE || child.killed) {
                  return Promise.reject(new Error(`Cannot send request: ACP transport is not active (status: ${sessionStatus})`));
                }
                const reqId = nextRequestId++;
                return new Promise((resolveReq, rejectReq) => {
                  const reqTimer = setTimeout(() => {
                    pendingRequests.delete(reqId);
                    rejectReq(new Error(`ACP request '${method}' (id: ${reqId}) timed out after ${reqTimeoutMs}ms`));
                  }, reqTimeoutMs);

                  pendingRequests.set(reqId, {
                    resolve: (val) => { clearTimeout(reqTimer); resolveReq(val); },
                    reject: (err) => { clearTimeout(reqTimer); rejectReq(err); }
                  });

                  try {
                    const payload = JSON.stringify({
                      jsonrpc: '2.0',
                      id: reqId,
                      method,
                      params
                    }) + '\n';
                    child.stdin.write(payload);
                  } catch (err) {
                    clearTimeout(reqTimer);
                    pendingRequests.delete(reqId);
                    rejectReq(err);
                  }
                });
              },
              onMessage: (listener) => {
                messageListeners.add(listener);
                return () => messageListeners.delete(listener);
              },
              onClose: (listener) => {
                closeListeners.add(listener);
                return () => closeListeners.delete(listener);
              },
              close: (reason = 'client_close') => {
                sessionStatus = TRANSPORT_STATUS.TERMINATED;
                for (const [id, req] of pendingRequests.entries()) {
                  req.reject(new Error('ACP session closed by client'));
                }
                pendingRequests.clear();
                notifyCloseOnce({ code: 0, signal: null, reason: `ACP session closed by client: ${reason}`, origin: 'client' });
                if (!child.killed) {
                  try { child.kill('SIGTERM'); } catch {}
                }
              },
              error: null
            };

            return resolve(session);
          } else if (parsed && parsed.error) {
            return failHandshake(`Server returned error: ${validation.error}`);
          }
        } else {
          // 2. Active Session Dispatching Phase (R16-F04-01 / R17-F04-01)
          if (parsed && typeof parsed === 'object') {
            // Check if this is a response to a pending request (has id and no method; method indicates a reverse request from server)
            const isResponse = parsed.id !== undefined && parsed.method === undefined;
            if (isResponse && pendingRequests.has(parsed.id)) {
              const req = pendingRequests.get(parsed.id);
              pendingRequests.delete(parsed.id);

              // Gate 0 (R17-F04-01): Strict JSON-RPC 2.0 response verification
              if (parsed.jsonrpc !== '2.0') {
                req.reject(new Error(`Invalid JSON-RPC protocol version in response: expected '2.0', got '${parsed.jsonrpc}'`));
              } else if (parsed.error !== undefined) {
                const errMsg = typeof parsed.error === 'string'
                  ? parsed.error
                  : (parsed.error?.message || JSON.stringify(parsed.error));
                req.reject(new Error(`ACP JSON-RPC error: ${errMsg}`));
              } else if (parsed.result !== undefined) {
                req.resolve(parsed.result);
              } else {
                req.reject(new Error('Malformed JSON-RPC 2.0 response: must contain either result or error'));
              }
            }

            // Dispatch to generic message listeners
            for (const listener of messageListeners) {
              try { listener(parsed); } catch {}
            }
          }
        }
      }
    });

    const initPayload = JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: ACP_PROTOCOL_VERSION,
        clientInfo: { name: 'agy-security-audit', version: '1.0.0' },
        capabilities: {}
      }
    }) + '\n';

    try {
      child.stdin.write(initPayload);
    } catch (err) {
      failHandshake(`Failed to write initialize payload: ${err.message}`);
    }
  });
}
