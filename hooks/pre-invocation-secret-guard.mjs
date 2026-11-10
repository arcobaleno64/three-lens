#!/usr/bin/env node
/**
 * pre-invocation-secret-guard.mjs
 * PreInvocation Lifecycle Hook for Antigravity (AGY).
 *
 * Intercepts incoming user prompts BEFORE model dispatch.
 * Scans for high-entropy secrets, private keys, and cloud credentials.
 * Enforces Fail-Closed terminationBehavior: "terminate" to prevent token leakage.
 *
 * Subprocess Calling Contract Compliance:
 * 1. Non-blocking stdin read with unref'd timer (fails closed on empty pipe / timeout).
 * 2. Explicit LF-only JSON output (no CRLF).
 * 3. Strict schema adherence (injectSteps, terminationBehavior).
 *
 * Governance Invariant (M54-P1-F01):
 * - Does not claim absolute zero-leak coverage; protects against specified credential patterns.
 * - Fails safe (closed) on parsing exceptions or execution timeouts.
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Emits result with strict LF line ending, avoiding CRLF conversion issues on Windows
function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// Credential detection patterns
export const SECRET_PATTERNS = [
  {
    name: 'PRIVATE_KEY',
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/
  },
  {
    name: 'AWS_ACCESS_KEY',
    regex: /\bAKIA[0-9A-Z]{16}\b/
  },
  {
    name: 'GITHUB_TOKEN',
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}\b/
  },
  {
    name: 'SLACK_TOKEN',
    regex: /\bxox[baprs]-[0-9A-Za-z]{10,48}\b/
  },
  {
    name: 'GOOGLE_API_KEY',
    regex: /\bAIza[0-9A-Za-z\-_]{35}\b/
  },
  {
    name: 'BEARER_TOKEN',
    regex: /\bBearer\s+(?:eyJ[A-Za-z0-9_\-\.=:_\+\/]{16,}|[A-Za-z0-9_\-\.=:_\+\/]{24,})\b/i
  },
  {
    name: 'GENERIC_HIGH_ENTROPY_TOKEN',
    regex: /(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{24,}['"]/i
  }
];

/**
 * Scans a string for prohibited secret patterns.
 * Returns the first matched pattern name, or null if clean.
 */
export function scanForSecrets(text) {
  if (typeof text !== 'string' || !text.trim()) return null;
  for (const { name, regex } of SECRET_PATTERNS) {
    if (regex.test(text)) {
      return name;
    }
  }
  return null;
}

/**
 * Reads stdin with timeout, failing closed on unexpected hang.
 */
function readStdinWithTimeout(timeoutMs = 1500) {
  return new Promise((resolve, reject) => {
    let data = '';
    const timer = setTimeout(() => {
      reject(new Error(`[FAIL_CLOSED] Stdin read timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

export async function main() {
  let rawInput = '';
  try {
    rawInput = await readStdinWithTimeout(1500);
  } catch (err) {
    // Fail-Closed: If stdin hangs or fails, terminate to avoid uninspected pass-through
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: `[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Stdin ingestion error (${err.message}). Turn halted.`
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  if (!rawInput || !rawInput.trim()) {
    // Fail-Closed: Empty input cannot be verified, terminate to prevent uninspected turn dispatch
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: '[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Empty or whitespace stdin received. Invocation terminated.'
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  let payload = null;
  try {
    payload = JSON.parse(rawInput);
  } catch (err) {
    // Fail-Closed on invalid JSON payload
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: `[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Invalid hook JSON payload (${err.message}). Turn halted.`
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: '[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Hook payload must be a non-null JSON object. Turn halted.'
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  // Extract all text candidates from user prompt and common fields
  const candidatesToScan = [];

  if (typeof payload?.lastUserInput === 'string') {
    candidatesToScan.push(payload.lastUserInput);
  }
  if (typeof payload?.prompt === 'string') {
    candidatesToScan.push(payload.prompt);
  }
  if (Array.isArray(payload?.messages)) {
    for (const msg of payload.messages) {
      if (typeof msg?.content === 'string') {
        candidatesToScan.push(msg.content);
      }
    }
  }

  // Ingest pending subagent messages from .system_generated/messages/ if available
  if (typeof payload?.transcriptPath === 'string' && payload.transcriptPath.trim()) {
    try {
      const logsDir = path.dirname(payload.transcriptPath);
      const systemGenDir = path.dirname(logsDir);
      const messagesDir = path.join(systemGenDir, 'messages');
      if (fs.existsSync(messagesDir)) {
        const messageFiles = fs.readdirSync(messagesDir);
        for (const file of messageFiles) {
          if (file.endsWith('.json') && file !== 'read.json') {
            const msgPath = path.join(messagesDir, file);
            const rawMsg = fs.readFileSync(msgPath, 'utf8');
            const msgObj = JSON.parse(rawMsg);
            if (typeof msgObj?.content === 'string') {
              candidatesToScan.push(msgObj.content);
            }
          }
        }
      }
    } catch {
      // Ingestion of message queue is best-effort fallback for subagent environments
    }
  }

  // Check whether this invocation is an autonomous continuation turn
  // (e.g. tool execution continuation, multi-turn tool loops, or existing transcript)
  const isContinuation =
    (typeof payload?.invocationNum === 'number' && payload.invocationNum > 1) ||
    (typeof payload?.initialNumSteps === 'number' && payload.initialNumSteps > 0);

  // If this is a continuation turn with no new user input candidates, allow normal turn dispatch
  if (isContinuation && !candidatesToScan.some(text => text.trim().length > 0)) {
    return emit({});
  }

  // Fail-Closed: Missing verifiable prompt or message payload fields
  if (candidatesToScan.length === 0) {
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: '[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Missing required verifiable prompt or message payload fields. Invocation terminated.'
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  // Fail-Closed (Gate 0 / M54-P1-F01): Empty or whitespace-only candidates cannot be verified
  const hasNonEmptyCandidate = candidatesToScan.some(text => text.trim().length > 0);
  if (!hasNonEmptyCandidate) {
    return emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: '[PRE_INVOCATION_SECRET_GUARD] Fail-Closed: Empty or whitespace-only prompt payload received. Invocation terminated.'
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  }

  // Check each text candidate
  for (const text of candidatesToScan) {
    const matchedSecret = scanForSecrets(text);
    if (matchedSecret) {
      // Deterministic block: emit errorMessage and terminationBehavior: "terminate"
      return emit({
        injectSteps: [
          {
            errorMessage: {
              userMessage: `[PRE_INVOCATION_SECRET_GUARD] Blocked: Credential pattern '${matchedSecret}' detected in user input. Model turn dispatch suppressed under Fail-Closed policy.`
            }
          }
        ],
        terminationBehavior: 'terminate'
      });
    }
  }

  // Clean prompt: proceed normally
  return emit({});
}

// Direct execution guard (handles file paths with spaces and special characters via fileURLToPath).
// Node resolves the main module's import.meta.url to its realpath while process.argv[1] keeps the path
// as invoked, so a lexical compare silently skips main() when the hook is reached through a symlink
// (for example macOS /var -> /private/var). Compare realpaths; if either cannot be resolved, fall back
// to the lexical compare so behavior never gets looser than before.
function isDirectRun() {
  if (!process.argv[1]) return false;
  const invoked = path.resolve(process.argv[1]);
  const self = path.resolve(fileURLToPath(import.meta.url));
  if (invoked === self) return true;
  try {
    return fs.realpathSync(invoked) === fs.realpathSync(self);
  } catch {
    return false;
  }
}

if (isDirectRun()) {
  main().catch((err) => {
    emit({
      injectSteps: [
        {
          errorMessage: {
            userMessage: `[PRE_INVOCATION_SECRET_GUARD] Fatal exception: ${err.message}. Turn halted.`
          }
        }
      ],
      terminationBehavior: 'terminate'
    });
  });
}
