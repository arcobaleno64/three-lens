#!/usr/bin/env node
/**
 * test-pre-invocation-secret-guard.mjs
 * Verification suite for PreInvocation secret guard hook (M54-P1-F01).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { scanForSecrets } from '../hooks/pre-invocation-secret-guard.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const HOOK_SCRIPT = path.resolve(__dirname, '../hooks/pre-invocation-secret-guard.mjs');

function runHook(payloadString) {
  const result = spawnSync(process.execPath, [HOOK_SCRIPT], {
    input: payloadString,
    encoding: 'utf8',
    timeout: 3000
  });

  assert.equal(result.status, 0, `Hook process exited with code ${result.status}, stderr: ${result.stderr}`);
  assert.ok(!result.stdout.includes('\r\n'), 'CRLF violation: hook output must be strictly LF-only');

  const parsed = JSON.parse(result.stdout.trim());
  return parsed;
}

test('PreInvocation Secret Guard - scanForSecrets unit checks', () => {
  assert.equal(scanForSecrets('audit src/controllers/user.js'), null);
  assert.equal(scanForSecrets('here is a key: AKIAIOSFODNN7EXAMPLE for AWS'), 'AWS_ACCESS_KEY');
  const dummyGh = ['ghp', '_', 'abcdefghijklmnopqrstuvwxyz0123456789'].join('');
  assert.equal(scanForSecrets(`token: ${dummyGh}`), 'GITHUB_TOKEN');
  assert.equal(scanForSecrets('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...'), 'PRIVATE_KEY');
  const dummySlack = ['xoxb', '-1234567890-1234567890123-abcdefghijklmnopqrstuvwx'].join('');
  assert.equal(scanForSecrets(dummySlack), 'SLACK_TOKEN');
  assert.equal(scanForSecrets('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.signature'), 'BEARER_TOKEN');
});

test('PreInvocation Secret Guard - Clean Prompt (Allow Turn)', () => {
  const payload = {
    conversationId: 'test-clean',
    lastUserInput: 'Please review evals/semantic-benchmark/safe/01-authz-bypass.js for CWE-862'
  };
  const response = runHook(JSON.stringify(payload));
  assert.deepEqual(response, {}, 'Clean input must emit empty object (proceed normally)');
});

test('PreInvocation Secret Guard - Private Key Detection (Fail-Closed Terminate)', () => {
  const payload = {
    conversationId: 'test-private-key',
    lastUserInput: 'Check this configuration: -----BEGIN OPENSSH PRIVATE KEY----- b3BlbnNza...'
  };
  const response = runHook(JSON.stringify(payload));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(Array.isArray(response.injectSteps));
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('PRIVATE_KEY'));
  assert.ok(!response.injectSteps[0].errorMessage.userMessage.includes('0 token leak'), 'Must not claim absolute 0 token leak');
});

test('PreInvocation Secret Guard - AWS Key Detection in Messages Array', () => {
  const payload = {
    conversationId: 'test-aws-key',
    messages: [
      { role: 'user', content: 'Deploy with AWS_ACCESS_KEY_ID=AKIA1234567890ABCDEF now' }
    ]
  };
  const response = runHook(JSON.stringify(payload));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('AWS_ACCESS_KEY'));
});

test('PreInvocation Secret Guard - Bearer Token Detection (Fail-Closed Terminate)', () => {
  const payload = {
    conversationId: 'test-bearer',
    prompt: 'Use header Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.secret'
  };
  const response = runHook(JSON.stringify(payload));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('BEARER_TOKEN'));
});

test('PreInvocation Secret Guard - Malformed JSON Payload (Fail-Closed Invariant)', () => {
  const response = runHook('MALFORMED_NON_JSON_CONTENT');
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Fail-Closed'));
});

test('PreInvocation Secret Guard - Empty Stdin (Fail-Closed Invariant)', () => {
  const response = runHook('');
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Empty or whitespace'));
});

test('PreInvocation Secret Guard - Whitespace Stdin (Fail-Closed Invariant)', () => {
  const response = runHook('   \n  \t ');
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Empty or whitespace'));
});

test('PreInvocation Secret Guard - Missing Verifiable Content Fields (Fail-Closed Invariant)', () => {
  const response = runHook(JSON.stringify({ conversationId: 'no-content' }));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Missing required verifiable prompt or message payload fields'));
});

test('PreInvocation Secret Guard - Empty String Field Counterexample F01 (Fail-Closed Invariant)', () => {
  // Counterexample identified by ChatGPT R3: {"lastUserInput": ""} must NOT bypass missing field check
  const response = runHook(JSON.stringify({ lastUserInput: '' }));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Empty or whitespace-only prompt payload'));
});

test('PreInvocation Secret Guard - Whitespace-only Field (Fail-Closed Invariant)', () => {
  const response = runHook(JSON.stringify({ lastUserInput: '   \t  \n ' }));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Empty or whitespace-only prompt payload'));
});

test('PreInvocation Secret Guard - Empty Prompt and Whitespace Messages (Fail-Closed Invariant)', () => {
  const response = runHook(JSON.stringify({
    prompt: '',
    messages: [
      { role: 'user', content: '' },
      { role: 'user', content: '   ' }
    ]
  }));
  assert.equal(response.terminationBehavior, 'terminate');
  assert.ok(response.injectSteps[0].errorMessage.userMessage.includes('Empty or whitespace-only prompt payload'));
});

test('PreInvocation Secret Guard - Non-Object JSON Payload (Fail-Closed Invariant)', () => {
  const responseArray = runHook(JSON.stringify(['arbitrary', 'array']));
  assert.equal(responseArray.terminationBehavior, 'terminate');
  assert.ok(responseArray.injectSteps[0].errorMessage.userMessage.includes('must be a non-null JSON object'));

  const responseNull = runHook(JSON.stringify(null));
  assert.equal(responseNull.terminationBehavior, 'terminate');
  assert.ok(responseNull.injectSteps[0].errorMessage.userMessage.includes('must be a non-null JSON object'));
});

test('PreInvocation Secret Guard - Installation path with spaces executes directly (R21-F01-01)', async () => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  const tempSpaceDir = path.join(os.tmpdir(), `secret guard test ${Date.now()}`);
  fs.mkdirSync(tempSpaceDir, { recursive: true });
  const copiedHook = path.join(tempSpaceDir, 'pre-invocation-secret-guard.mjs');
  fs.copyFileSync(HOOK_SCRIPT, copiedHook);

  try {
    const payload = JSON.stringify({
      prompt: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...'
    });
    const result = spawnSync(process.execPath, [copiedHook], {
      input: payload,
      encoding: 'utf8',
      timeout: 3000
    });

    assert.equal(result.status, 0, `Process exited with code ${result.status}, stderr: ${result.stderr}`);
    const parsed = JSON.parse(result.stdout.trim());
    assert.equal(parsed.terminationBehavior, 'terminate');
    assert.ok(parsed.injectSteps[0].errorMessage.userMessage.includes('PRIVATE_KEY'));
  } finally {
    fs.rmSync(tempSpaceDir, { recursive: true, force: true });
  }
});

test('PreInvocation Secret Guard - Executes and blocks when the hook is reached through a symlinked directory', async (t) => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  // Canonicalize the temp root so the "real" side is genuinely different from the symlinked side.
  const root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'secret-guard-link-'));
  try {
    const realDir = path.join(root, 'real');
    const linkDir = path.join(root, 'link');
    fs.mkdirSync(realDir);
    fs.copyFileSync(HOOK_SCRIPT, path.join(realDir, 'pre-invocation-secret-guard.mjs'));
    try {
      try {
        fs.symlinkSync(realDir, linkDir, 'dir');
      } catch {
        fs.symlinkSync(realDir, linkDir, 'junction');
      }
    } catch (err) {
      t.skip(`cannot create a directory symlink on this runner: ${err.code || err.message}`);
      return;
    }

    const payload = JSON.stringify({ prompt: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...' });
    const run = (dir) => spawnSync(process.execPath, [path.join(dir, 'pre-invocation-secret-guard.mjs')], {
      input: payload,
      encoding: 'utf8',
      timeout: 3000
    });

    // Control: via the real path the hook blocks.
    const viaReal = run(realDir);
    assert.equal(JSON.parse(viaReal.stdout.trim()).terminationBehavior, 'terminate');

    // Regression: via the symlinked path it must block too, not exit 0 with empty output.
    const viaLink = run(linkDir);
    assert.equal(viaLink.status, 0, `exit ${viaLink.status}, stderr: ${viaLink.stderr}`);
    assert.notEqual(viaLink.stdout.trim(), '', 'hook produced no output when invoked through a symlinked directory');
    const parsed = JSON.parse(viaLink.stdout.trim());
    assert.equal(parsed.terminationBehavior, 'terminate');
    assert.ok(parsed.injectSteps[0].errorMessage.userMessage.includes('PRIVATE_KEY'));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('PreInvocation Secret Guard - Tool Continuation Turn (invocationNum > 1 with empty input)', () => {
  const payload = {
    conversationId: 'test-continuation',
    invocationNum: 2,
    lastUserInput: ''
  };
  const response = runHook(JSON.stringify(payload));
  assert.deepEqual(response, {}, 'Continuation turn with empty lastUserInput must be allowed');
});

test('PreInvocation Secret Guard - Tool Continuation Turn (initialNumSteps > 0 with empty input)', () => {
  const payload = {
    conversationId: 'test-continuation-steps',
    initialNumSteps: 5,
    lastUserInput: '   '
  };
  const response = runHook(JSON.stringify(payload));
  assert.deepEqual(response, {}, 'Continuation turn with initialNumSteps > 0 must be allowed');
});

test('PreInvocation Secret Guard - Subagent Message Ingestion from .system_generated/messages/', async () => {
  const os = await import('node:os');
  const fs = await import('node:fs');
  const tempBase = path.join(os.tmpdir(), `subagent-guard-test-${Date.now()}`);
  const logsDir = path.join(tempBase, '.system_generated', 'logs');
  const messagesDir = path.join(tempBase, '.system_generated', 'messages');
  fs.mkdirSync(logsDir, { recursive: true });
  fs.mkdirSync(messagesDir, { recursive: true });

  const transcriptPath = path.join(logsDir, 'transcript.jsonl');
  fs.writeFileSync(transcriptPath, '');

  try {
    // 1. Clean subagent message: should allow turn
    const cleanMsg = {
      id: 'clean-msg-1',
      recipient: 'subagent-1',
      sender: 'parent-agent',
      content: 'You are the REACHABILITY Lens verifier operating under 3lens.'
    };
    fs.writeFileSync(path.join(messagesDir, 'clean-msg-1.json'), JSON.stringify(cleanMsg));

    const cleanPayload = {
      conversationId: 'subagent-1',
      transcriptPath,
      lastUserInput: ''
    };
    const cleanResponse = runHook(JSON.stringify(cleanPayload));
    assert.deepEqual(cleanResponse, {}, 'Clean subagent message must be allowed');

    // 2. Secret-bearing subagent message: should detect secret and terminate
    const secretMsg = {
      id: 'secret-msg-2',
      recipient: 'subagent-1',
      sender: 'parent-agent',
      content: 'Here is the credential for AWS: AKIAIOSFODNN7EXAMPLE'
    };
    fs.writeFileSync(path.join(messagesDir, 'secret-msg-2.json'), JSON.stringify(secretMsg));

    const secretPayload = {
      conversationId: 'subagent-1',
      transcriptPath,
      lastUserInput: ''
    };
    const secretResponse = runHook(JSON.stringify(secretPayload));
    assert.equal(secretResponse.terminationBehavior, 'terminate');
    assert.ok(secretResponse.injectSteps[0].errorMessage.userMessage.includes('AWS_ACCESS_KEY'));
  } finally {
    fs.rmSync(tempBase, { recursive: true, force: true });
  }
});

test('Issue #56 Regression: Unified SECRET_PATTERNS covers all 15 credential shapes in both context tokenizer and prompt guard', async () => {
  const { tokenizeSecretsForContext, redactSecrets, SECRET_PATTERNS: FINALIZER_PATTERNS } = await import('../skills/3lens/scripts/finalize-scan.mjs');
  const { SECRET_PATTERNS: GUARD_PATTERNS } = await import('../hooks/pre-invocation-secret-guard.mjs');

  assert.strictEqual(GUARD_PATTERNS, FINALIZER_PATTERNS, 'Prompt guard and context tokenizer must share the exact same SECRET_PATTERNS reference');

  const A36 = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const samples = {
    'AWS access key':             'const k = "AKIAIOSFODNN7EXAMPLE";',
    'GitHub ghp_ token':          `const t = "ghp_${A36}";`,
    'JWT':                        'const j = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl";',
    'PEM RSA private key block':  '-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----',
    'password: 16+ plain chars':  'password: abcdefghijklmnop1234',
    'Slack bot token':            'const s = "xoxb-123456789012-abcdefghijkl";',
    'Google API key':             'const g = "AIzaSyA1234567890abcdefghijklmnopqrstuv";',
    'password with symbols':      'password = "P@ssw0rd!2024#xyzABCD"',
    'password shorter than 16':   'password = "hunter2"',
    'DB URL with inline password':'DATABASE_URL=postgres://admin:SuperSecret123456@db.example.com/app',
    'client_secret':              'client_secret = "abcdefghijklmnop1234567890"',
    'bare "token" key':           '"token": "abcdef0123456789abcdef0123"',
    'Azure AccountKey':           'AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF==;',
    'PEM ENCRYPTED PRIVATE KEY':  '-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIfake\n-----END ENCRYPTED PRIVATE KEY-----',
    'PGP private key block':      '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQfake\n-----END PGP PRIVATE KEY BLOCK-----',
  };

  for (const [label, text] of Object.entries(samples)) {
    const tok = tokenizeSecretsForContext(text);
    assert.ok(tok.secretCount > 0, `Context tokenizer missed sample '${label}': ${text}`);
    const red = redactSecrets(text);
    assert.ok(red.includes('[REDACTED_'), `redactSecrets missed sample '${label}': ${text}`);
    const guardMatch = scanForSecrets(text);
    assert.ok(guardMatch !== null, `Prompt guard scanForSecrets missed sample '${label}': ${text}`);
  }
});
