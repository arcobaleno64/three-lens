#!/usr/bin/env node
/**
 * test-containment-gaps.mjs
 * Regression tests for Layer 3 (shadow-context-guard symlink containment) and
 * Layer 4 (safeReadFileContained descriptor-to-realpath identity binding).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { safeReadFileContained } from '../skills/3lens/scripts/path-containment.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');
const HOOK_PATH = path.join(REPO_ROOT, 'hooks', 'shadow-context-guard.mjs');

function createDirLink(target, linkPath) {
  try {
    fs.symlinkSync(target, linkPath, 'dir');
  } catch {
    fs.symlinkSync(target, linkPath, 'junction');
  }
}

function invokeHook(toolName, args, workspaceRoot, envOverrides = {}, extraPayload = {}) {
  const res = spawnSync(process.execPath, [HOOK_PATH], {
    input: JSON.stringify({
      toolCall: { name: toolName, args },
      workspacePaths: [workspaceRoot],
      conversationId: 'test-containment-gap1',
      ...extraPayload
    }),
    env: { ...process.env, ...envOverrides },
    encoding: 'utf8',
    timeout: 15000
  });
  assert.equal(res.status, 0, `Hook exited with code ${res.status}: ${res.stderr}`);
  assert.ok(!res.stdout.includes('\r'), 'Hook output must be strictly LF-only');
  const lastLine = (res.stdout || '').trim().split('\n').filter(Boolean).pop() || '{}';
  return JSON.parse(lastLine);
}

test('Gap 1 (Layer 3): shadow-context-guard denies symlink escapes inside scratch/ and scratch/context/ while allowing valid non-existent write targets and symlinked os.tmpdir()', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'test-gap1-layer3-'));
  try {
    const realTmp = path.join(base, 'real-tmp');
    const symlinkedTmp = path.join(base, 'symlink-tmp');
    const repo = path.join(base, 'repo');
    const ctx = path.join(repo, 'scratch', 'context');
    const outside = path.join(base, 'outside');

    for (const d of [realTmp, ctx, outside]) {
      fs.mkdirSync(d, { recursive: true });
    }
    createDirLink(realTmp, symlinkedTmp);

    fs.writeFileSync(path.join(outside, 'secret.txt'), 'OUTSIDE-SECRET', 'utf8');
    fs.writeFileSync(path.join(ctx, 'benign.txt'), 'SHADOW-BENIGN', 'utf8');
    fs.writeFileSync(
      path.join(ctx, 'context-manifest.json'),
      JSON.stringify({ contextRoot: ctx, repoRoot: repo, manifestDigest: 'gap1-test' }),
      'utf8'
    );

    createDirLink(outside, path.join(repo, 'scratch', 'link-out'));
    createDirLink(outside, path.join(ctx, 'link-out'));

    const tmpEnv = { TEMP: symlinkedTmp, TMP: symlinkedTmp, TMPDIR: symlinkedTmp };

    // W1: write through symlink inside scratch/ pointing outside repo -> must deny
    const w1 = invokeHook(
      'write_to_file',
      { TargetFile: path.join(repo, 'scratch', 'link-out', 'pwned.txt') },
      repo,
      tmpEnv
    );
    assert.equal(w1.decision, 'deny', 'W1: write via scratch/link-out -> outside must be denied');

    // R1: read through symlink inside scratch/context/ pointing outside repo -> must deny
    const r1 = invokeHook(
      'view_file',
      { AbsolutePath: path.join(ctx, 'link-out', 'secret.txt') },
      repo,
      tmpEnv
    );
    assert.equal(r1.decision, 'deny', 'R1: read via scratch/context/link-out -> outside must be denied');

    // Positive controls:
    // 1. Not-yet-existing nested file inside scratch/ -> must allow
    const wNewScratch = invokeHook(
      'write_to_file',
      { TargetFile: path.join(repo, 'scratch', 'new-subdir', 'nested', 'draft.patch') },
      repo,
      tmpEnv
    );
    assert.equal(wNewScratch.decision, 'allow', 'Write to not-yet-existing target inside scratch/ must be allowed');

    // 2. Not-yet-existing file under symlinked os.tmpdir() -> must allow
    const wNewTmp = invokeHook(
      'write_to_file',
      { TargetFile: path.join(symlinkedTmp, 'subdir', 'note.txt') },
      repo,
      tmpEnv
    );
    assert.equal(wNewTmp.decision, 'allow', 'Write to not-yet-existing target inside symlinked os.tmpdir() must be allowed');

    // 3. Symlink inside os.tmpdir() pointing outside os.tmpdir() -> must deny
    createDirLink(outside, path.join(realTmp, 'escape-link'));
    const wTmpEscape = invokeHook(
      'write_to_file',
      { TargetFile: path.join(symlinkedTmp, 'escape-link', 'escaped.txt') },
      repo,
      tmpEnv
    );
    assert.equal(wTmpEscape.decision, 'deny', 'Write via symlink inside os.tmpdir() escaping outside must be denied');

    // 4. Legitimate read inside scratch/context/ -> must allow
    const rBenign = invokeHook(
      'view_file',
      { AbsolutePath: path.join(ctx, 'benign.txt') },
      repo,
      tmpEnv
    );
    assert.equal(rBenign.decision, 'allow', 'Legitimate read inside contextRoot must be allowed');
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test('Gap 2 (Layer 4): safeReadFileContained rejects fd-to-realpath identity mismatch on double path swap (A1)', () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), 'test-gap2-layer4-'));
  const origLstat = fs.lstatSync;
  const origFstat = fs.fstatSync;

  try {
    const root = path.join(base, 'root');
    const outside = path.join(base, 'outside');
    fs.mkdirSync(root, { recursive: true });
    fs.mkdirSync(outside, { recursive: true });

    const SECRET = 'OUTSIDE-SECRET';
    const INSIDE = 'inside-benign';
    const secretFile = path.join(outside, 'secret.txt');
    fs.writeFileSync(secretFile, SECRET, 'utf8');
    const targetFile = path.join(root, 'file.txt');

    const putRegular = () => {
      try { fs.unlinkSync(targetFile); } catch {}
      fs.writeFileSync(targetFile, INSIDE, 'utf8');
    };
    const putLink = () => {
      try { fs.unlinkSync(targetFile); } catch {}
      fs.symlinkSync(secretFile, targetFile, 'file');
    };

    let afterLstat = null;
    let afterFstat = null;

    fs.lstatSync = function (p, ...args) {
      const r = origLstat.call(this, p, ...args);
      if (path.resolve(String(p)) === path.resolve(targetFile) && afterLstat) {
        const fn = afterLstat;
        afterLstat = null;
        fn();
      }
      return r;
    };

    fs.fstatSync = function (fd, ...args) {
      const r = origFstat.call(this, fd, ...args);
      if (afterFstat) {
        const fn = afterFstat;
        afterFstat = null;
        fn();
      }
      return r;
    };

    // Control 1: regular in-root file succeeds
    putRegular();
    const c1 = safeReadFileContained(root, targetFile);
    assert.equal(c1.ok, true, 'Control C1: regular in-root file must succeed');
    assert.equal(c1.content, INSIDE);

    // Control 2: static symlink -> outside rejected
    putLink();
    const c2 = safeReadFileContained(root, targetFile);
    assert.equal(c2.ok, false, 'Control C2: static symlink must be rejected');

    // Control 3: single swap after lstat rejected
    putRegular();
    afterLstat = putLink;
    const c3 = safeReadFileContained(root, targetFile);
    assert.equal(c3.ok, false, 'Control C3: single swap after lstat must be rejected');
    assert.notEqual(c3.content, SECRET);

    // Attack A1: swap -> link after lstat, swap -> regular after fstat
    putRegular();
    afterLstat = putLink;
    afterFstat = putRegular;
    const a1 = safeReadFileContained(root, targetFile);
    assert.equal(a1.ok, false, 'Attack A1: double swap must fail closed on descriptor-to-realpath identity mismatch');
    assert.notEqual(a1.content, SECRET, 'Attack A1 must never return outside secret content');
  } finally {
    fs.lstatSync = origLstat;
    fs.fstatSync = origFstat;
    fs.rmSync(base, { recursive: true, force: true });
  }
});
