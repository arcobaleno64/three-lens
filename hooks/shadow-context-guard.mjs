#!/usr/bin/env node
/**
 * shadow-context-guard.mjs
 * PreToolUse Lifecycle Hook for Antigravity (AGY).
 *
 * Enforces runtime containment and Fail-Closed Default-Deny on repository reads,
 * directing agents to sanitized shadow context under scratch/context/.
 *
 * Subprocess Calling Contract Compliance:
 * 1. Non-blocking stdin read with unref'd timer (fails safe on empty pipe).
 * 2. Explicit LF-only JSON output (no CRLF).
 * 3. Strict schema adherence (only decision, reason, permissionOverrides).
 *
 * Supported Tools:
 * - view_file (AbsolutePath)
 * - grep_search (SearchPath)
 * - list_dir (DirectoryPath)
 * - find_by_name (SearchDirectory)
 *
 * Zero external npm dependencies.
 */

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { isRealPathContained, isPathContained } from '../skills/3lens/scripts/path-containment.mjs';

export const READ_TOOLS = new Set(['view_file', 'grep_search', 'list_dir', 'find_by_name']);
export const NETWORK_TOOLS = new Set(['search_web', 'read_url_content', 'read_browser_page', 'call_mcp_tool']);
export const WRITE_TOOLS = new Set(['write_to_file', 'replace_file_content']);
export const SUBAGENT_TOOLS = new Set(['invoke_subagent']);
export const COMMAND_TOOLS = new Set(['run_command']);

export const SUPPORTED_TOOLS = new Set([
  ...READ_TOOLS,
  ...NETWORK_TOOLS,
  ...WRITE_TOOLS,
  ...SUBAGENT_TOOLS,
  ...COMMAND_TOOLS
]);

// Emits result with strict LF line ending, avoiding CRLF conversion issues on Windows
function emit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
}

// Extracts target path parameter based on tool definition
export function extractTargetParam(toolName, args) {
  if (!args || typeof args !== 'object') return null;
  switch (toolName) {
    case 'view_file':
      return typeof args.AbsolutePath === 'string' ? args.AbsolutePath : null;
    case 'grep_search':
      return typeof args.SearchPath === 'string' ? args.SearchPath : null;
    case 'list_dir':
      return typeof args.DirectoryPath === 'string' ? args.DirectoryPath : null;
    case 'find_by_name':
      return typeof args.SearchDirectory === 'string' ? args.SearchDirectory : null;
    case 'write_to_file':
    case 'replace_file_content':
      return typeof args.TargetFile === 'string' ? args.TargetFile : (typeof args.targetFile === 'string' ? args.targetFile : null);
    default:
      return null;
  }
}

// Reads stdin with timeout to guard against open-but-empty pipes (Contract Rule 1)
function readStdinWithTimeout(timeoutMs = 1500) {
  return new Promise((resolve) => {
    let data = '';
    const timer = setTimeout(() => {
      resolve(data);
    }, timeoutMs);
    if (timer.unref) timer.unref();

    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      data += chunk;
    });
    process.stdin.on('end', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.on('error', () => {
      clearTimeout(timer);
      resolve(data);
    });
    process.stdin.resume();
  });
}

// Discovers active scratch/context/context-manifest.json
function findContextManifest(workspacePaths, targetFilePath) {
  const candidates = [];
  if (Array.isArray(workspacePaths)) {
    for (const ws of workspacePaths) {
      if (typeof ws === 'string' && ws.trim()) {
        candidates.push(path.resolve(ws, 'scratch/context/context-manifest.json'));
      }
    }
  }

  if (targetFilePath && typeof targetFilePath === 'string') {
    let currentDir = path.dirname(path.resolve(targetFilePath));
    while (true) {
      candidates.push(path.resolve(currentDir, 'scratch/context/context-manifest.json'));
      const parent = path.dirname(currentDir);
      if (parent === currentDir) break;
      currentDir = parent;
    }
  }

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate)) {
        const raw = fs.readFileSync(candidate, 'utf8');
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === 'object') {
          return {
            manifest: parsed,
            manifestPath: candidate,
            contextRoot: path.resolve(parsed.contextRoot || path.dirname(candidate)),
            repoRoot: path.resolve(parsed.repoRoot || path.resolve(path.dirname(candidate), '../..'))
          };
        }
      }
    } catch {}
  }

  return null;
}

// Records structured audit telemetry to trusted location and contextRoot mirror
function recordTelemetry(contextInfo, payload, toolName, targetPath, decision, action, reason) {
  try {
    const event = {
      timestamp: new Date().toISOString(),
      conversationId: payload?.conversationId || 'UNKNOWN',
      stepIdx: typeof payload?.stepIdx === 'number' ? payload.stepIdx : null,
      modelName: payload?.modelName || 'UNKNOWN',
      manifestDigest: contextInfo?.manifest?.manifestDigest || null,
      tool: toolName,
      targetPath: (targetPath || '').replace(/\\/g, '/'),
      decision,
      action,
      reason
    };
    const eventLine = JSON.stringify(event) + '\n';

    // Trusted execution-side location (artifactDirectoryPath)
    if (payload?.artifactDirectoryPath && typeof payload.artifactDirectoryPath === 'string') {
      try {
        if (fs.existsSync(payload.artifactDirectoryPath)) {
          const trustedPath = path.join(payload.artifactDirectoryPath, 'shadow-guard-telemetry.jsonl');
          fs.appendFileSync(trustedPath, eventLine, 'utf8');
        }
      } catch {}
    }

    // Target contextRoot mirror (backward compatibility)
    if (contextInfo?.contextRoot) {
      try {
        if (fs.existsSync(contextInfo.contextRoot)) {
          const eventsFile = path.resolve(contextInfo.contextRoot, 'guard-events.jsonl');
          fs.appendFileSync(eventsFile, eventLine, 'utf8');
        }
      } catch {}
    }
  } catch {}
}

// Resolves realpath of an existing target or its deepest existing ancestor (for not-yet-existing write targets),
// failing closed if a symlink or junction along the path escapes rootDir.
function isWriteTargetRealPathContained(rootDir, targetPath) {
  if (!rootDir || !targetPath || typeof rootDir !== 'string' || typeof targetPath !== 'string') {
    return false;
  }
  if (
    targetPath.includes('..\\') ||
    targetPath.includes('../') ||
    targetPath === '..' ||
    targetPath.endsWith('/..') ||
    targetPath.endsWith('\\..')
  ) {
    return false;
  }
  const resolvedRoot = path.resolve(rootDir);
  const resolvedTarget = path.resolve(targetPath);

  let rootReal;
  try {
    rootReal = fs.realpathSync(resolvedRoot);
  } catch {
    // Root directory may not exist yet (e.g. artifactDirectoryPath before first write);
    // walk up to the deepest existing ancestor of rootDir to canonicalize symlinked prefixes (like os.tmpdir()).
    let curRoot = resolvedRoot;
    const rootTail = [];
    while (true) {
      try {
        const ancestorReal = fs.realpathSync(curRoot);
        rootReal = path.resolve(ancestorReal, ...rootTail);
        break;
      } catch {
        const parent = path.dirname(curRoot);
        if (parent === curRoot) return false;
        rootTail.unshift(path.basename(curRoot));
        curRoot = parent;
      }
    }
  }

  let current = resolvedTarget;
  const tailSegments = [];
  while (true) {
    let lstat = null;
    try {
      lstat = fs.lstatSync(current);
    } catch {
      lstat = null;
    }

    if (lstat !== null) {
      try {
        const currentReal = fs.realpathSync(current);
        const projectedReal = path.resolve(currentReal, ...tailSegments);
        const rel = path.relative(rootReal, projectedReal);
        return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
      } catch {
        // Dangling symlink or unresolvable existing node fails closed
        return false;
      }
    }

    const parent = path.dirname(current);
    if (parent === current) {
      return false;
    }
    tailSegments.unshift(path.basename(current));
    current = parent;
  }
}

async function main() {
  let rawInput = '';
  try {
    rawInput = await readStdinWithTimeout(1500);
  } catch {
    return emit({ decision: 'allow' });
  }

  if (!rawInput || !rawInput.trim()) {
    return emit({ decision: 'allow' });
  }

  let payload = null;
  try {
    payload = JSON.parse(rawInput);
  } catch {
    return emit({ decision: 'allow' });
  }

  const toolName = payload?.toolCall?.name;
  if (!toolName || !SUPPORTED_TOOLS.has(toolName)) {
    return emit({ decision: 'allow' });
  }

  const targetPathArg = extractTargetParam(toolName, payload?.toolCall?.args);
  const candidateResolved = targetPathArg && typeof targetPathArg === 'string' ? path.resolve(targetPathArg) : null;
  const contextInfo = findContextManifest(payload?.workspacePaths, candidateResolved);

  // If no shadow context is active for this workspace, allow direct access
  if (!contextInfo) {
    return emit({ decision: 'allow' });
  }

  const { contextRoot, repoRoot } = contextInfo;

  // ---------------------------------------------------------------------------
  // Control 3: DENY_NETWORK_EXFILTRATION (Network Tools & Shell Egress)
  // ---------------------------------------------------------------------------
  if (NETWORK_TOOLS.has(toolName)) {
    recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_NETWORK_TOOL', `Outbound network tool '${toolName}' is blocked during headless security audit (G6 DENY_NETWORK_EXFILTRATION).`);
    return emit({
      decision: 'deny',
      reason: `[NETWORK_CONFINEMENT_ENFORCEMENT] Outbound network tool '${toolName}' is blocked during headless security audit (G6 DENY_NETWORK_EXFILTRATION).`
    });
  }

  if (COMMAND_TOOLS.has(toolName)) {
    const cmdLine = payload?.toolCall?.args?.CommandLine || '';
    const NETWORK_EGRESS_REGEX = /\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod|iwr|irm|nc|ncat|netcat|telnet|ssh|scp|ftp|sftp)\b/i;
    if (NETWORK_EGRESS_REGEX.test(cmdLine)) {
      const match = cmdLine.match(NETWORK_EGRESS_REGEX);
      const matchedBinary = match ? match[1] : 'network_egress';
      recordTelemetry(contextInfo, payload, toolName, cmdLine, 'deny', 'DENIED_NETWORK_CMD', `Shell command blocked: prohibited outbound network egress via '${matchedBinary}' (G6 DENY_NETWORK_EXFILTRATION).`);
      return emit({
        decision: 'deny',
        reason: `[NETWORK_CONFINEMENT_ENFORCEMENT] Shell command blocked: prohibited outbound network egress via '${matchedBinary}' (G6 DENY_NETWORK_EXFILTRATION).`
      });
    }
    return emit({ decision: 'allow' });
  }

  // ---------------------------------------------------------------------------
  // Control 5: DENY_SUBAGENT_RECURSION (Subagent Spawning & Depth Limits)
  // ---------------------------------------------------------------------------
  if (SUBAGENT_TOOLS.has(toolName)) {
    const subagentDepth = typeof payload?.subagentDepth === 'number'
      ? payload.subagentDepth
      : (payload?.isSubagent || (payload?.agentRole && payload?.agentRole !== 'coordinator') ? 1 : 0);

    if (subagentDepth >= 1) {
      recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_RECURSION', `Recursive subagent invocation blocked: depth ${subagentDepth} exceeds allowable quorum depth (G6 DENY_SUBAGENT_RECURSION).`);
      return emit({
        decision: 'deny',
        reason: `[SUBAGENT_CONFINEMENT_ENFORCEMENT] Subagent recursion rejected: subagents cannot recursively spawn further subagents (quorum depth limit: 1).`
      });
    }

    const subagentsList = payload?.toolCall?.args?.Subagents || [];
    if (Array.isArray(subagentsList) && subagentsList.length > 5) {
      recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_RECURSION', `Subagent invocation blocked: batch size ${subagentsList.length} exceeds maximum concurrent quorum quota (5).`);
      return emit({
        decision: 'deny',
        reason: `[SUBAGENT_CONFINEMENT_ENFORCEMENT] Subagent invocation blocked: batch size ${subagentsList.length} exceeds maximum concurrent quorum quota (5).`
      });
    }

    recordTelemetry(contextInfo, payload, toolName, '', 'allow', 'ALLOWED_COORDINATOR_SPAWN', 'Coordinator subagent invocation permitted within quorum quota.');
    return emit({ decision: 'allow' });
  }

  // ---------------------------------------------------------------------------
  // Control 4: DENY_ARBITRARY_FS_WRITE (Filesystem Mutation Sandbox Boundary)
  // ---------------------------------------------------------------------------
  if (WRITE_TOOLS.has(toolName)) {
    if (!targetPathArg || typeof targetPathArg !== 'string' || !targetPathArg.trim()) {
      recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_MALFORMED', `Write tool '${toolName}' rejected: missing TargetFile argument.`);
      return emit({
        decision: 'deny',
        reason: `[FILESYSTEM_CONFINEMENT_ENFORCEMENT] Write tool '${toolName}' rejected: missing TargetFile argument.`
      });
    }

    const resolvedTarget = path.resolve(targetPathArg);
    const scratchDir = path.resolve(repoRoot, 'scratch');
    const artifactDir = payload?.artifactDirectoryPath ? path.resolve(payload.artifactDirectoryPath) : null;
    const tmpDir = os.tmpdir() ? path.resolve(os.tmpdir()) : null;

    const isInsideScratch = isPathContained(scratchDir, resolvedTarget) && isWriteTargetRealPathContained(scratchDir, resolvedTarget);
    const isInsideArtifact = Boolean(
      artifactDir &&
      isPathContained(artifactDir, resolvedTarget) &&
      isWriteTargetRealPathContained(artifactDir, resolvedTarget)
    );
    const isInsideRepo = isPathContained(repoRoot, resolvedTarget) || isWriteTargetRealPathContained(repoRoot, resolvedTarget);
    const isInsideTmp = Boolean(
      !isInsideRepo &&
      tmpDir &&
      isWriteTargetRealPathContained(tmpDir, resolvedTarget)
    );

    if (isInsideScratch || isInsideArtifact || isInsideTmp) {
      recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'allow', 'ALLOWED_SANDBOX_WRITE', 'Filesystem write within authorized sandbox boundary permitted.');
      return emit({ decision: 'allow' });
    }

    const rel = path.relative(repoRoot, resolvedTarget).replace(/\\/g, '/');
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_FS_WRITE', `Filesystem write to '${rel}' blocked: mutations outside authorized sandbox boundary are prohibited (G6 DENY_ARBITRARY_FS_WRITE).`);
    return emit({
      decision: 'deny',
      reason: `[FILESYSTEM_CONFINEMENT_ENFORCEMENT] Filesystem write to '${rel}' is blocked. Mutations outside authorized sandbox boundary ('scratch/') are prohibited during security audit.`
    });
  }

  // ---------------------------------------------------------------------------
  // Control 1 & 2: ALLOW_SHADOW_READ & DENY_RAW_REPO_READ (Filesystem Reads)
  // ---------------------------------------------------------------------------
  // Active shadow context is present! Strict Fail-Closed enforcement applies.
  if (!targetPathArg || typeof targetPathArg !== 'string' || !targetPathArg.trim()) {
    recordTelemetry(contextInfo, payload, toolName, '', 'deny', 'DENIED_MALFORMED', 'Tool call rejected: missing required path argument.');
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Tool call '${toolName}' rejected: missing required path argument.`
    });
  }

  const resolvedTarget = path.resolve(targetPathArg);

  // 1. If path is already inside contextRoot, allow sanitized inspection (both lexical and realpath containment must hold)
  if (isPathContained(contextRoot, resolvedTarget) && isRealPathContained(contextRoot, resolvedTarget)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'allow', 'ALLOWED_SHADOW', 'Access to sanitized shadow context permitted.');
    return emit({ decision: 'allow' });
  }

  // 2. If path escapes repoRoot (traversal or symlink escape), strictly deny
  if (!isRealPathContained(repoRoot, resolvedTarget) || !isPathContained(repoRoot, resolvedTarget)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_ESCAPE', 'Path containment violation: path escapes repository boundary.');
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Path containment violation: '${targetPathArg}' escapes repository boundary (CWE-59 defense).`
    });
  }

  // 3. Path is within repoRoot (raw repository path).
  // Check if sanitized shadow counterpart exists.
  const relPath = path.relative(repoRoot, resolvedTarget);
  const shadowEquivalent = path.resolve(contextRoot, relPath);
  const shadowRel = path.relative(repoRoot, shadowEquivalent).replace(/\\/g, '/');
  const rawRel = relPath.replace(/\\/g, '/');

  if (fs.existsSync(shadowEquivalent)) {
    recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_RAW', `Direct access to raw repository path blocked; sanitized shadow copy exists at '${shadowRel}'.`);
    return emit({
      decision: 'deny',
      reason: `[SHADOW_CONTEXT_ENFORCEMENT] Direct access to raw repository path '${rawRel}' is blocked. You MUST inspect the sanitized shadow copy at '${shadowRel}'.`
    });
  }

  // 4. Path is unshadowed within repoRoot: strictly deny under Default-Deny (Fail-Closed)
  recordTelemetry(contextInfo, payload, toolName, resolvedTarget, 'deny', 'DENIED_UNSHADOWED', `Direct access to raw repository path blocked; path '${rawRel}' is absent from sanitized shadow context.`);
  return emit({
    decision: 'deny',
    reason: `[SHADOW_CONTEXT_ENFORCEMENT] Direct access to raw repository path '${rawRel}' is blocked. This path is not present in the sanitized shadow context.`
  });
}

main().catch(() => {
  emit({ decision: 'allow' });
});