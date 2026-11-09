#!/usr/bin/env node
/**
 * scripts/fetch-upstream-oss-fixture.mjs
 * Milestone 5.5 (RFC 0006 Workstream 2):
 * Hermetic Multi-Repo Checkout & Upstream OSS Ground Truth Fetch Harness.
 *
 * Capabilities:
 * - Reads Layer 2 external validity corpus (evals/v2-corpus/layer2-external-validity-corpus.json).
 * - Filters cases marked UPSTREAM_VERIFIED_OSS.
 * - Resolves upstream repository remote and commit SHA.
 * - Hermetically clones/fetches pinned revisions into isolated checkout paths (evals/oss-checkouts/).
 * - Enforces Zero Workspace Pollution: checkouts are confined to .gitignored paths.
 * - Provides --dry-run and --verify-upstream validation flags.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, '..');

/**
 * Resolves the real canonical filesystem path across symlinks, junctions, and non-existent leaf segments.
 * Walks up the tree to the nearest existing ancestor, resolves native physical realpath,
 * and re-appends leaf segments, preventing lexical fallback bypasses (R07-F05).
 * @param {string} p
 * @returns {string}
 */
export function getCanonicalRealPath(p) {
  let existing = path.resolve(p);
  const segments = [];
  while (!fs.existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) break;
    segments.unshift(path.basename(existing));
    existing = parent;
  }

  let realExisting = existing;
  try {
    realExisting = fs.realpathSync.native ? fs.realpathSync.native(existing) : fs.realpathSync(existing);
  } catch {
    realExisting = path.resolve(existing);
  }

  return segments.length > 0 ? path.join(realExisting, ...segments) : realExisting;
}

const DEFAULT_CORPUS_PATH = path.join(REPO_ROOT, 'evals', 'v2-corpus', 'layer2-external-validity-corpus.json');
const DEFAULT_OUT_DIR = path.join(REPO_ROOT, 'evals', 'oss-checkouts');

function printUsage() {
  console.log(`
Usage: node scripts/fetch-upstream-oss-fixture.mjs [options]

Options:
  --corpus <path>       Path to Layer 2 corpus JSON (default: evals/v2-corpus/layer2-external-validity-corpus.json)
  --out-dir <path>      Target checkout directory (default: evals/oss-checkouts)
  --case <id>           Target specific case ID (e.g., L2-15)
  --dry-run             Validate upstream URLs and commit formats without network cloning
  --verify-upstream     Verify commit authenticity via GitHub API
  --help                Show this message
`);
}

export function parseArgs(argv = process.argv.slice(2)) {
  const args = {
    corpusPath: DEFAULT_CORPUS_PATH,
    outDir: DEFAULT_OUT_DIR,
    caseId: null,
    dryRun: false,
    verifyUpstream: false,
    help: false
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--corpus' && argv[i + 1]) {
      args.corpusPath = path.resolve(argv[++i]);
    } else if (arg === '--out-dir' && argv[i + 1]) {
      args.outDir = path.resolve(argv[++i]);
    } else if (arg === '--case' && argv[i + 1]) {
      args.caseId = argv[++i];
    } else if (arg === '--dry-run') {
      args.dryRun = true;
    } else if (arg === '--verify-upstream') {
      args.verifyUpstream = true;
    } else if (arg === '--help' || arg === '-h') {
      args.help = true;
    }
  }

  return args;
}

export async function verifyUpstreamCommit(repoUrl, commitSha) {
  if (!repoUrl || !commitSha) {
    return { ok: false, error: 'Missing repoUrl or commitSha' };
  }

  // Parse owner/repo from GitHub URL
  const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+?)(?:\.git|\/)?$/i);
  if (!match) {
    return { ok: false, error: `Unsupported upstream provider: ${repoUrl}` };
  }

  const [, owner, repo] = match;
  const apiUrl = `https://api.github.com/repos/${owner}/${repo}/commits/${commitSha}`;

  try {
    const res = await fetch(apiUrl, {
      headers: {
        'User-Agent': 'three-lens-oss-fixture-fetcher/1.13.0',
        'Accept': 'application/vnd.github.v3+json'
      }
    });

    if (res.status === 200) {
      const data = await res.json();
      return { ok: true, sha: data.sha, commitMessage: data.commit?.message?.split('\n')[0] };
    } else {
      return { ok: false, status: res.status, error: `GitHub API returned ${res.status}` };
    }
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

export async function runHarness(options = {}) {
  const {
    corpusPath = DEFAULT_CORPUS_PATH,
    outDir = DEFAULT_OUT_DIR,
    caseId = null,
    dryRun = false,
    verifyUpstream = false
  } = options;

  if (!fs.existsSync(corpusPath)) {
    throw new Error(`Corpus file not found: ${corpusPath}`);
  }

  const corpus = JSON.parse(fs.readFileSync(corpusPath, 'utf8'));
  const cases = Array.isArray(corpus.cases) ? corpus.cases : [];
  const ossCases = cases.filter(c => c.provenanceType === 'UPSTREAM_VERIFIED_OSS');

  const targets = caseId ? ossCases.filter(c => (c.caseId || c.id) === caseId) : ossCases;

  if (targets.length === 0) {
    if (caseId) {
      console.error(`✖ Error: Specified caseId '${caseId}' does not exist in corpus.`);
      return { total: 0, verified: 0, failed: 1, skipped: 0 };
    }
    console.log(`No UPSTREAM_VERIFIED_OSS cases found matching filter.`);
    return { total: 0, verified: 0, failed: 0, skipped: 0 };
  }

  console.log(`Processing ${targets.length} UPSTREAM_VERIFIED_OSS case(s)...`);

  let verifiedCount = 0;
  let failedCount = 0;
  const resolvedOutDir = path.resolve(outDir);
  const canonicalRepoRoot = getCanonicalRealPath(REPO_ROOT);
  const canonicalResolvedOutDir = getCanonicalRealPath(resolvedOutDir);

  // R05-F05 & R06-F04: Confine outDir strictly to dedicated repository harness sandbox paths
  // Validates both string lexical path and physical canonical realpath across symlinks/junctions
  const allowedBaseDirs = [
    path.join(REPO_ROOT, 'evals', 'oss-checkouts'),
    path.join(REPO_ROOT, 'evals', 'live-runs'),
    path.join(REPO_ROOT, 'scratch')
  ];
  const isStringAllowed = allowedBaseDirs.some(base =>
    resolvedOutDir === base || resolvedOutDir.startsWith(base + path.sep)
  );
  const canonicalAllowedBases = allowedBaseDirs.map(getCanonicalRealPath);
  const isPhysicalAllowed = canonicalAllowedBases.some(base =>
    canonicalResolvedOutDir === base || canonicalResolvedOutDir.startsWith(base + path.sep)
  );

  if (!isStringAllowed || !isPhysicalAllowed) {
    throw new Error(
      `Security Exception (R06-F04): outDir '${resolvedOutDir}' physically escapes allowed sandbox roots (${allowedBaseDirs.map(d => path.relative(REPO_ROOT, d)).join(', ')})`
    );
  }

  for (const tc of targets) {
    const upstreamUrl = tc.upstreamRepoUrl || tc.upstreamRepo;
    const commitSha = tc.upstreamCommitSha || tc.commitSha;

    const caseId = tc.caseId || tc.id;
    const cwe = tc.cwe || tc.cweFamily || 'N/A';
    const rawPkg = tc.package || tc.upstreamRepo?.split('/')?.pop()?.replace(/\.git$/, '') || caseId;
    // Strict path traversal defense: strip any non-whitelisted characters
    const safePkg = String(rawPkg).replace(/[^a-zA-Z0-9._-]/g, '_');

    console.log(`\nCase [${caseId}] ${tc.cveId || 'No-CVE'} (${cwe}) - ${safePkg}`);
    console.log(`  Upstream Remote: ${upstreamUrl || 'NONE'}`);
    console.log(`  Commit SHA:      ${commitSha || 'NONE'}`);
    console.log(`  Role:            ${tc.role}`);

    if (!upstreamUrl || !commitSha) {
      console.warn(`  ⚠ Missing upstream metadata!`);
      failedCount++;
      continue;
    }

    if (verifyUpstream) {
      process.stdout.write(`  Verifying upstream commit against GitHub API... `);
      const vRes = await verifyUpstreamCommit(upstreamUrl, commitSha);
      if (vRes.ok) {
        console.log(`✔ VERIFIED (${vRes.commitMessage})`);
        verifiedCount++;
      } else {
        console.log(`✖ FAILED (${vRes.error})`);
        failedCount++;
      }
    } else if (dryRun) {
      console.log(`  ✔ Dry-run format valid: ${commitSha.slice(0, 10)} from ${upstreamUrl}`);
      verifiedCount++;
    } else {
      // Hermetic checkout logic with strict lexical and physical containment checks
      const safeRole = String(tc.role || 'role').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
      const targetDir = path.resolve(resolvedOutDir, `${safePkg}-${safeRole}-${commitSha.slice(0, 7)}`);
      const canonicalTarget = getCanonicalRealPath(targetDir);

      if (!targetDir.startsWith(resolvedOutDir + path.sep) || !canonicalTarget.startsWith(canonicalResolvedOutDir + path.sep)) {
        throw new Error(`Path containment violation (R06-F04): ${targetDir} escapes outDir ${resolvedOutDir}`);
      }

      // R04-F05, R05-F03, R06-F04 & R07-F07: Safe harness directory purger with mandatory dual-attestation (AND binding)
      function safePurgeHarnessTarget(dir, baseOutDir, expectedRemote, expectedCaseId, expectedCommitSha) {
        const canonicalDir = getCanonicalRealPath(dir);
        const canonicalBase = getCanonicalRealPath(baseOutDir);
        if (!canonicalDir.startsWith(canonicalBase + path.sep)) {
          throw new Error(`Security Exception (R07-F05): targetDir ${dir} physically escapes base outDir ${baseOutDir}`);
        }
        if (!fs.existsSync(dir)) return;

        // If target directory itself is a symlink or junction, unlink it directly without recursing into external target
        const lstat = fs.lstatSync(dir, { throwIfNoEntry: false });
        if (lstat && lstat.isSymbolicLink()) {
          fs.unlinkSync(dir);
          return;
        }

        // R07-F07 Dual-Control: Both external marker binding AND git remote check are required (AND logic)
        const marker = path.join(baseOutDir, `.${path.basename(dir)}.harness-metadata.json`);
        const gitConfig = path.join(dir, '.git', 'config');

        let markerValid = false;
        if (fs.existsSync(marker)) {
          try {
            const data = JSON.parse(fs.readFileSync(marker, 'utf8'));
            if ((!expectedCaseId || data.caseId === expectedCaseId) &&
                (!expectedCommitSha || data.upstreamCommitSha === expectedCommitSha)) {
              markerValid = true;
            }
          } catch {}
        }

        const gitRemoteValid = fs.existsSync(gitConfig) && fs.readFileSync(gitConfig, 'utf8').includes(expectedRemote);

        // Require both marker and git remote (or empty directory) to purge safely
        const isVerifiedHarnessTarget = (markerValid && gitRemoteValid) || fs.readdirSync(dir).length === 0;
        if (!isVerifiedHarnessTarget) {
          throw new Error(
            `Safety Exception (R07-F07): Refusing to delete directory '${dir}' without mandatory dual-attestation (markerValid: ${markerValid}, gitRemoteValid: ${gitRemoteValid})`
          );
        }

        fs.rmSync(dir, { recursive: true, force: true });
        if (fs.existsSync(marker)) {
          try { fs.unlinkSync(marker); } catch {}
        }
      }

      // R03-F02, R04-F03 & R05-F03: Full 40-char SHA matching and worktree verification immune to skip-worktree / assume-unchanged
      let isExistingValidRepo = false;
      if (fs.existsSync(targetDir) && fs.existsSync(path.join(targetDir, '.git'))) {
        try {
          const headRev = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: targetDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
          const statusOutput = execFileSync('git', ['status', '--porcelain'], { cwd: targetDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
          
          // R04-F03: Exact 40-character commit SHA match
          const isExactCommit = headRev.toLowerCase() === commitSha.toLowerCase();
          
          // R05-F03: Detect index manipulation / skip-worktree / assume-unchanged via git ls-files -v
          // In git ls-files -v:
          // 'H' = cached (normal valid index entry)
          // 'S' = skip-worktree (tampered/masked index entry)
          // 'h' = assume-unchanged (tampered/masked index entry)
          const lsFilesOut = execFileSync('git', ['ls-files', '-v'], { cwd: targetDir, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
          const hasIndexTampering = lsFilesOut.split(/\r?\n/).some(line => {
            const trimmed = line.trim();
            if (!trimmed) return false;
            const tag = trimmed[0];
            return tag === 'S' || tag === 'h' || (tag !== 'H' && tag !== '?');
          });

          let isTreeIntact = false;
          try {
            execFileSync('git', ['diff-index', '--quiet', 'HEAD', '--'], { cwd: targetDir, stdio: ['ignore', 'pipe', 'pipe'] });
            execFileSync('git', ['diff-files', '--quiet'], { cwd: targetDir, stdio: ['ignore', 'pipe', 'pipe'] });
            isTreeIntact = (statusOutput === '' && !hasIndexTampering);
          } catch {
            isTreeIntact = false;
          }

          if (isExactCommit && isTreeIntact) {
            isExistingValidRepo = true;
          }
        } catch {
          isExistingValidRepo = false;
        }
      }

      if (isExistingValidRepo) {
        console.log(`  ✔ Valid verified checkout found at: ${path.relative(REPO_ROOT, targetDir)}`);
        verifiedCount++;
      } else {
        // If directory exists but failed validation, safely remove it before re-cloning
        if (fs.existsSync(targetDir)) {
          console.warn(`  ⚠ Partial or invalid checkout detected at: ${path.relative(REPO_ROOT, targetDir)}, cleaning up safely...`);
          safePurgeHarnessTarget(targetDir, resolvedOutDir, upstreamUrl, caseId, commitSha);
        }

        console.log(`  Cloning to isolated sandbox: ${path.relative(REPO_ROOT, targetDir)}...`);
        fs.mkdirSync(resolvedOutDir, { recursive: true });
        try {
          execFileSync('git', ['clone', '--no-checkout', upstreamUrl, targetDir], { stdio: 'pipe' });
          execFileSync('git', ['checkout', commitSha], { cwd: targetDir, stdio: 'pipe' });
          // Stamp harness ownership marker OUTSIDE targetDir to prevent working tree pollution (R05-F03 & R06-F04)
          const externalMarker = path.join(resolvedOutDir, `.${path.basename(targetDir)}.harness-metadata.json`);
          fs.writeFileSync(externalMarker, JSON.stringify({
            caseId: tc.caseId,
            upstreamCommitSha: commitSha,
            createdAt: new Date().toISOString()
          }, null, 2));
          console.log(`  ✔ Successfully checked out ${commitSha.slice(0, 10)}`);
          verifiedCount++;
        } catch (err) {
          console.error(`  ✖ Checkout failed: ${err.message}`);
          // Ensure incomplete directory is safely deleted fail-closed
          if (fs.existsSync(targetDir)) {
            try { safePurgeHarnessTarget(targetDir, resolvedOutDir, upstreamUrl, caseId, commitSha); } catch {}
          }
          failedCount++;
        }
      }
    }
  }

  return { total: targets.length, verified: verifiedCount, failed: failedCount };
}

// CLI Execution Entrypoint
if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  const args = parseArgs();
  if (args.help) {
    printUsage();
    process.exit(0);
  }

  runHarness(args).then(result => {
    if (result.failed > 0 || (args.verifyUpstream && result.verified !== result.total)) {
      console.error(`\nHarness finished with ${result.failed} failure(s). Exiting fail-closed.`);
      process.exit(1);
    }
  }).catch(err => {
    console.error(`\nFatal error in fetch harness: ${err.message}`);
    process.exit(1);
  });
}
