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
