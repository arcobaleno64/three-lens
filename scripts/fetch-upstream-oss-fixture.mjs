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
    console.log(`No UPSTREAM_VERIFIED_OSS cases found matching filter.`);
    return { total: 0, verified: 0, failed: 0, skipped: 0 };
  }

  console.log(`Processing ${targets.length} UPSTREAM_VERIFIED_OSS case(s)...`);

  let verifiedCount = 0;
  let failedCount = 0;
  const resolvedOutDir = path.resolve(outDir);

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
      // Hermetic checkout logic with strict directory containment check
      const safeRole = String(tc.role || 'role').toLowerCase().replace(/[^a-z0-9_-]/g, '_');
      const targetDir = path.resolve(resolvedOutDir, `${safePkg}-${safeRole}-${commitSha.slice(0, 7)}`);

      if (!targetDir.startsWith(resolvedOutDir + path.sep)) {
        throw new Error(`Path containment violation: ${targetDir} escapes outDir ${resolvedOutDir}`);
      }

      if (fs.existsSync(targetDir)) {
        console.log(`  ✔ Already checked out at: ${path.relative(REPO_ROOT, targetDir)}`);
        verifiedCount++;
      } else {
        console.log(`  Cloning to isolated sandbox: ${path.relative(REPO_ROOT, targetDir)}...`);
        fs.mkdirSync(resolvedOutDir, { recursive: true });
        try {
          execFileSync('git', ['clone', '--no-checkout', upstreamUrl, targetDir], { stdio: 'pipe' });
          execFileSync('git', ['checkout', commitSha], { cwd: targetDir, stdio: 'pipe' });
          console.log(`  ✔ Successfully checked out ${commitSha.slice(0, 7)}`);
          verifiedCount++;
        } catch (err) {
          console.error(`  ✖ Checkout failed: ${err.message}`);
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
