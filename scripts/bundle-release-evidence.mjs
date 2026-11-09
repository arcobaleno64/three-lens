#!/usr/bin/env node
/**
 * bundle-release-evidence.mjs
 * Zero-dependency Node.js release evidence bundler for @arcobaleno64/agy-security-audit.
 *
 * Staging and validation script for empirical benchmark deliverables:
 * 1. reports/empirical-baseline-n5-report-2026-09-13.md
 * 2. reports/empirical-benchmark-20-paired-report-2026-09-13.md
 * 3. evals/semantic-benchmark/ground-truth.json
 * 4. skills/3lens/tool-integrity-manifest.json
 * 5. evals/live-runs/ and evals/recorded-runs/ -> empirical-benchmark-envelopes.tar.gz
 * 6. Deterministic cryptographic checksums -> SHA256SUMS.txt
 *
 * Supported CLI flags:
 *   --out-dir <dir>    Destination staging directory (default: 'release-evidence')
 *   --repo-root <dir>  Repository root directory (default: parent of scripts/)
 *   --check            Validates mandatory evidence files exist and are non-empty without writing
 *   --help, -h         Display usage instructions
 *
 * Zero external dependencies. Enforces strict LF line endings.
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = path.resolve(path.dirname(__filename), '..');

export const MANDATORY_INDIVIDUAL_FILES = [
  {
    repoPath: 'reports/empirical-baseline-n5-report-2026-09-13.md',
    stagedName: 'empirical-baseline-n5-report-2026-09-13.md',
    description: 'Authentic N=5 Model Discovery Baseline Report'
  },
  {
    repoPath: 'reports/empirical-benchmark-20-paired-report-2026-09-13.md',
    stagedName: 'empirical-benchmark-20-paired-report-2026-09-13.md',
    description: '20-Fixture Paired Disposition Benchmark Report'
  },
  {
    repoPath: 'reports/safe-control-baseline-report-2026-09-17.md',
    stagedName: 'safe-control-baseline-report-2026-09-17.md',
    description: 'Authentic Label-Blind Safe-Control Baseline Report'
  },
  {
    repoPath: 'evals/semantic-benchmark/ground-truth.json',
    stagedName: 'ground-truth.json',
    description: 'Authoritative 20-Fixture Paired Dataset'
  },
  {
    repoPath: 'evals/holdout-benchmark/ground-truth.json',
    stagedName: 'holdout-ground-truth.json',
    description: 'Authoritative 20-Fixture Paired Holdout Generalization Dataset'
  },
  {
    repoPath: 'skills/3lens/tool-integrity-manifest.json',
    stagedName: 'tool-integrity-manifest.json',
    description: 'SHA-256 Cryptographic TCB Integrity Manifest'
  },
  {
    repoPath: 'reports/reasoning-ablation-report-2026-09-17-corrected.md',
    stagedName: 'reasoning-ablation-report-2026-09-17-corrected.md',
    description: 'Corrected Reasoning Profile Ablation Report (Milestone G5)'
  },
  {
    repoPath: 'reports/runtime-confinement-report-2026-09-22.md',
    stagedName: 'runtime-confinement-report-2026-09-22.md',
    description: 'Dual-Control Runtime Confinement Matrix Report (Milestone G6)'
  },
  {
    repoPath: 'reports/runtime-canary-report-2026-09-22.md',
    stagedName: 'runtime-canary-report-2026-09-22.md',
    description: 'Live Runtime Confinement Canary Report (Milestone G6-L2)'
  },
  {
    repoPath: 'reports/oss-transfer-benchmark-report-2026-09-22.md',
    stagedName: 'oss-transfer-benchmark-report-2026-09-22.md',
    description: 'External OSS Transfer Benchmark Report (Milestone G7)'
  },
  {
    repoPath: 'reports/cross-provider-replication-report-2026-09-22.md',
    stagedName: 'cross-provider-replication-report-2026-09-22.md',
    description: 'Cross-Provider Model Replication Report (Milestone G8 Superseded)'
  },
  {
    repoPath: 'reports/cross-provider-replication-report-2026-09-23.md',
    stagedName: 'cross-provider-replication-report-2026-09-23.md',
    description: 'Live Cross-Provider Model Replication Report (Milestone G8-R)'
  },
  {
    repoPath: 'reports/oss-transfer-live-report-2026-09-23.md',
    stagedName: 'oss-transfer-live-report-2026-09-23.md',
    description: 'Live Full Upstream Repository Transfer Evaluation Report (Milestone G7-R)'
  },
  {
    repoPath: 'schemas/evidence-matrix.schema.json',
    stagedName: 'evidence-matrix.schema.json',
    description: 'Draft-07 JSON Schema for Evidence Matrix Artifact'
  },
  {
    repoPath: 'evals/evidence-matrix.json',
    stagedName: 'evidence-matrix.json',
    description: 'Authoritative 5-Dimension Evidence Matrix Artifact'
  }
];

export const MANDATORY_ENVELOPE_DIRS = [
  {
    repoDir: 'evals/live-runs',
    archivePrefix: 'evals/live-runs',
    description: 'Machine-readable MODEL_OBSERVED run envelopes'
  },
  {
    repoDir: 'evals/live-runs/oss-transfer',
    archivePrefix: 'evals/live-runs/oss-transfer',
    description: 'Machine-readable MODEL_OBSERVED OSS transfer run envelopes'
  },
  {
    repoDir: 'evals/recorded-runs',
    archivePrefix: 'evals/recorded-runs',
    description: 'Machine-readable SYNTHETIC run envelopes'
  }
];

/**
 * Creates a standard POSIX UStar 512-byte tar header.
 */
function createTarHeader(name, size, mode = 0o644, mtime = 0) {
  const buf = Buffer.alloc(512, 0);

  // 0..99: File name
  const nameBytes = Buffer.from(name, 'utf8');
  if (nameBytes.length > 100) {
    throw new Error(`Tar entry name exceeds 100 bytes limit: ${name}`);
  }
  nameBytes.copy(buf, 0);

  // 100..107: File mode (octal, 8 bytes, null-padded)
  const modeStr = (mode & 0o7777).toString(8).padStart(7, '0');
  buf.write(modeStr + '\0', 100, 8, 'ascii');

  // 108..115: Owner UID (octal, 8 bytes, null-padded)
  buf.write('0000000\0', 108, 8, 'ascii');

  // 116..123: Owner GID (octal, 8 bytes, null-padded)
  buf.write('0000000\0', 116, 8, 'ascii');

  // 124..135: File size (octal, 12 bytes, null-padded)
  const sizeStr = size.toString(8).padStart(11, '0');
  buf.write(sizeStr + '\0', 124, 12, 'ascii');

  // 136..147: Modification time (octal, 12 bytes, null-padded, fixed at 0 for determinism)
  const mtimeStr = mtime.toString(8).padStart(11, '0');
  buf.write(mtimeStr + '\0', 136, 12, 'ascii');

  // 148..155: Checksum field initially 8 spaces (0x20)
  buf.fill(0x20, 148, 156);

  // 156: Type flag ('0' for regular file)
  buf[156] = 0x30; // '0'

  // 157..256: Link name (unused, zeroes)

  // 257..262: Magic indicator 'ustar\0'
  buf.write('ustar\0', 257, 6, 'ascii');

  // 263..264: Version '00'
  buf.write('00', 263, 2, 'ascii');

  // Compute checksum (sum of all 512 bytes where checksum field is spaces)
  let sum = 0;
  for (let i = 0; i < 512; i++) {
    sum += buf[i];
  }
  const sumStr = sum.toString(8).padStart(6, '0') + '\0 ';
  buf.write(sumStr, 148, 8, 'ascii');

  return buf;
}

/**
 * Packs files into a deterministic, zero-dependency .tar.gz archive.
 * @param {Array<{ archivePath: string, content: Buffer|string }>} entries
 * @returns {Buffer}
 */
export function createDeterministicTarGz(entries) {
  // Sort entries alphabetically by archivePath for strict determinism
  const sorted = [...entries].sort((a, b) => a.archivePath.localeCompare(b.archivePath));

  const chunks = [];
  for (const entry of sorted) {
    const content = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    const header = createTarHeader(entry.archivePath, content.length, 0o644, 0);
    chunks.push(header);
    chunks.push(content);

    // Pad content to 512-byte boundary
    const padSize = (512 - (content.length % 512)) % 512;
    if (padSize > 0) {
      chunks.push(Buffer.alloc(padSize, 0));
    }
  }

  // End of archive marker: two 512-byte zero blocks
  chunks.push(Buffer.alloc(1024, 0));

  const tarBuffer = Buffer.concat(chunks);

  // Compress with max compression level
  const gzBuffer = zlib.gzipSync(tarBuffer, { level: 9 });

  // Normalize gzip header for deterministic cross-platform byte output:
  // Bytes 4..7: MTIME (little-endian 32-bit timestamp) -> set to 0
  // Byte 9: OS flag -> set to 0xff (unknown)
  if (gzBuffer.length >= 10) {
    gzBuffer[4] = 0;
    gzBuffer[5] = 0;
    gzBuffer[6] = 0;
    gzBuffer[7] = 0;
    gzBuffer[9] = 0xff;
  }

  return gzBuffer;
}

/**
 * Creates a deterministic, zero-dependency .zip archive buffer.
 * @param {Array<{ archivePath: string, content: Buffer|string }>} entries
 * @returns {Buffer}
 */
export function createDeterministicZip(entries) {
  // Sort entries alphabetically by archivePath for strict determinism
  const sorted = [...entries].sort((a, b) => a.archivePath.localeCompare(b.archivePath));

  const localChunks = [];
  const cdChunks = [];
  let offset = 0;

  for (const entry of sorted) {
    if (!entry.archivePath || typeof entry.archivePath !== 'string') {
      throw new Error('ZIP entry missing valid archivePath');
    }
    if (entry.archivePath.startsWith('agy-plugin-cc') || entry.archivePath.includes('agy-plugin-cc/')) {
      throw new Error(`Forbidden legacy directory in release archive: ${entry.archivePath}`);
    }
    if (!entry.archivePath.startsWith('agy-security-audit/')) {
      throw new Error(`Release archive entry must be under root directory 'agy-security-audit/': ${entry.archivePath}`);
    }
    const rawContent = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content, 'utf8');
    const isDeflated = rawContent.length > 0;
    const compressed = isDeflated ? zlib.deflateRawSync(rawContent, { level: 9 }) : Buffer.alloc(0);
    const method = isDeflated ? 8 : 0;
    const crc = zlib.crc32(rawContent);
    const nameBuf = Buffer.from(entry.archivePath, 'utf8');

    // Local file header (30 bytes + name length)
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); // Local header signature
    lh.writeUInt16LE(20, 4);          // Version needed: 2.0
    lh.writeUInt16LE(0x0800, 6);       // Flags: bit 11 = UTF-8 filename
    lh.writeUInt16LE(method, 8);       // Compression method
    lh.writeUInt16LE(0, 10);          // Last mod time: 00:00:00
    lh.writeUInt16LE(0x0021, 12);      // Last mod date: 1980-01-01
    lh.writeUInt32LE(crc, 14);         // CRC-32
    lh.writeUInt32LE(compressed.length, 18); // Compressed size
    lh.writeUInt32LE(rawContent.length, 22);  // Uncompressed size
    lh.writeUInt16LE(nameBuf.length, 26);     // File name length
    lh.writeUInt16LE(0, 28);                  // Extra field length

    const localOffset = offset;
    localChunks.push(lh, nameBuf, compressed);
    offset += lh.length + nameBuf.length + compressed.length;

    // Central directory header (46 bytes + name length)
    const cdh = Buffer.alloc(46);
    cdh.writeUInt32LE(0x02014b50, 0); // Central directory signature
    cdh.writeUInt16LE(0x0314, 4);      // Version made by: UNIX v2.0
    cdh.writeUInt16LE(20, 6);          // Version needed: 2.0
    cdh.writeUInt16LE(0x0800, 8);      // Flags: UTF-8
    cdh.writeUInt16LE(method, 10);     // Compression method
    cdh.writeUInt16LE(0, 12);         // Last mod time
    cdh.writeUInt16LE(0x0021, 14);     // Last mod date
    cdh.writeUInt32LE(crc, 16);        // CRC-32
    cdh.writeUInt32LE(compressed.length, 20); // Compressed size
    cdh.writeUInt32LE(rawContent.length, 24); // Uncompressed size
    cdh.writeUInt16LE(nameBuf.length, 28);    // File name length
    cdh.writeUInt16LE(0, 30);                 // Extra field length
    cdh.writeUInt16LE(0, 32);                 // Comment length
    cdh.writeUInt16LE(0, 34);                 // Disk number start
    cdh.writeUInt16LE(0, 36);                 // Internal file attributes
    cdh.writeUInt32LE((0o100644 << 16) >>> 0, 38); // External attributes (regular file 0644)
    cdh.writeUInt32LE(localOffset, 42);       // Relative offset of local header

    cdChunks.push(cdh, nameBuf);
  }

  const cdBuffer = Buffer.concat(cdChunks);
  const cdOffset = offset;
  const cdSize = cdBuffer.length;

  // End of central directory record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // EOCD signature
  eocd.writeUInt16LE(0, 4);          // Disk number
  eocd.writeUInt16LE(0, 6);          // Disk with start of CD
  eocd.writeUInt16LE(entries.length, 8);  // Entries on this disk
  eocd.writeUInt16LE(entries.length, 10); // Total entries
  eocd.writeUInt32LE(cdSize, 12);         // CD size
  eocd.writeUInt32LE(cdOffset, 16);       // CD offset
  eocd.writeUInt16LE(0, 20);              // Comment length

  return Buffer.concat([...localChunks, cdBuffer, eocd]);
}

/**
 * Discovers repository files to include in release archive.
 * Returns relative POSIX paths sorted alphabetically.
 */
export function getReleaseArchiveFiles(repoRoot = REPO_ROOT) {
  let files = [];
  try {
    const res = spawnSync('git', ['ls-files'], {
      cwd: repoRoot,
      encoding: 'utf8',
      shell: false,
      stdio: ['ignore', 'pipe', 'ignore']
    });
    if (res.status === 0 && res.stdout) {
      files = res.stdout.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
    }
  } catch {}

  if (files.length === 0) {
    const EXCLUDED_DIRS = new Set(['.git', 'node_modules', 'scratch', 'release-evidence']);
    function walk(dir, relPrefix = '') {
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      for (const ent of entries) {
        if (ent.isDirectory()) {
          if (!EXCLUDED_DIRS.has(ent.name)) {
            walk(path.join(dir, ent.name), path.join(relPrefix, ent.name));
          }
        } else if (ent.isFile()) {
          files.push(path.join(relPrefix, ent.name).replace(/\\/g, '/'));
        }
      }
    }
    walk(repoRoot);
  }

  // If package.json defines files allowlist, restrict release archive entries to declared plugin files
  try {
    const pkgPath = path.resolve(repoRoot, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (Array.isArray(pkg.files) && pkg.files.length > 0) {
        const allowed = new Set(pkg.files.map(p => p.replace(/\\/g, '/').replace(/\/$/, '')));
        allowed.add('package.json');
        files = files.filter(f => {
          const normalized = f.replace(/\\/g, '/');
          const top = normalized.split('/')[0];
          return allowed.has(top) || allowed.has(normalized);
        });
      }
    }
  } catch {}

  return files
    .filter(f => !f.startsWith('scratch/') && !f.startsWith('release-evidence/') && !f.startsWith('.git/'))
    .sort();
}

/**
 * Validates that all required evidence files exist and are non-empty.
 * @param {string} repoRoot
 * @returns {{ valid: boolean, errors: string[], checkedFiles: string[] }}
 */

/**
 * Zero-dependency JSON Schema validator supporting Draft-07 subsets required
 * by evidence-matrix.schema.json ($ref, definitions, type, required, properties,
 * items, enum, pattern).
 *
 * @param {any} data
 * @param {object} schema
 * @param {object} rootSchema
 * @param {string} currentPath
 * @returns {string[]} List of validation error strings
 */
export function validateAgainstSchema(data, schema, rootSchema = schema, currentPath = '') {
  const errors = [];
  if (!schema || typeof schema !== 'object') return errors;

  if (schema['$ref']) {
    const ref = schema['$ref'];
    if (typeof ref === 'string' && ref.startsWith('#/')) {
      const parts = ref.slice(2).split('/');
      let resolved = rootSchema;
      for (const part of parts) {
        if (resolved && typeof resolved === 'object' && part in resolved) {
          resolved = resolved[part];
        } else {
          resolved = null;
          break;
        }
      }
      if (!resolved) {
        errors.push(`Unresolvable schema reference '${ref}' at ${currentPath || 'root'}`);
        return errors;
      }
      return validateAgainstSchema(data, resolved, rootSchema, currentPath);
    }
  }

  if (schema.type) {
    const p = currentPath || 'root';
    switch (schema.type) {
      case 'object':
        if (typeof data !== 'object' || data === null || Array.isArray(data)) {
          errors.push(`Expected object at ${p}, found ${data === null ? 'null' : Array.isArray(data) ? 'array' : typeof data}`);
          return errors;
        }
        break;
      case 'array':
        if (!Array.isArray(data)) {
          errors.push(`Expected array at ${p}, found ${typeof data}`);
          return errors;
        }
        break;
      case 'string':
        if (typeof data !== 'string') {
          errors.push(`Expected string at ${p}, found ${typeof data}`);
          return errors;
        }
        break;
      case 'integer':
        if (typeof data !== 'number' || !Number.isInteger(data)) {
          errors.push(`Expected integer at ${p}, found ${typeof data}`);
          return errors;
        }
        break;
      case 'number':
        if (typeof data !== 'number' || Number.isNaN(data)) {
          errors.push(`Expected number at ${p}, found ${typeof data}`);
          return errors;
        }
        break;
      case 'boolean':
        if (typeof data !== 'boolean') {
          errors.push(`Expected boolean at ${p}, found ${typeof data}`);
          return errors;
        }
        break;
    }
  }

  if (Array.isArray(schema.enum)) {
    if (!schema.enum.includes(data)) {
      const p = currentPath || 'root';
      errors.push(`Value '${data}' at ${p} is not one of enum [${schema.enum.map(v => JSON.stringify(v)).join(', ')}]`);
    }
  }

  if (typeof schema.pattern === 'string' && typeof data === 'string') {
    const regex = new RegExp(schema.pattern);
    if (!regex.test(data)) {
      const p = currentPath || 'root';
      errors.push(`String '${data}' at ${p} does not match pattern '${schema.pattern}'`);
    }
  }

  if (Array.isArray(schema.required) && typeof data === 'object' && data !== null && !Array.isArray(data)) {
    for (const reqProp of schema.required) {
      if (data[reqProp] === undefined || data[reqProp] === null) {
        const p = currentPath ? `${currentPath}.${reqProp}` : reqProp;
        errors.push(`Missing required property: ${p}`);
      }
    }
  }

  if (schema.properties && typeof schema.properties === 'object' && typeof data === 'object' && data !== null && !Array.isArray(data)) {
    for (const [propName, propSchema] of Object.entries(schema.properties)) {
      if (data[propName] !== undefined) {
        const subPath = currentPath ? `${currentPath}.${propName}` : propName;
        const subErrors = validateAgainstSchema(data[propName], propSchema, rootSchema, subPath);
        errors.push(...subErrors);
      }
    }
  }

  if (schema.items && Array.isArray(data)) {
    data.forEach((item, index) => {
      const subPath = `${currentPath || 'root'}[${index}]`;
      const itemErrors = validateAgainstSchema(item, schema.items, rootSchema, subPath);
      errors.push(...itemErrors);
    });
  }

  return errors;
}

/**
 * Validates the evidence matrix artifact against schemas/evidence-matrix.schema.json.
 * @param {object} matrix
 * @param {string} repoRoot
 * @returns {{ valid: boolean, errors: string[] }}
 */
export function validateEvidenceMatrixSchema(matrix, repoRoot = REPO_ROOT) {
  const schemaPath = path.resolve(repoRoot, 'schemas/evidence-matrix.schema.json');
  if (!fs.existsSync(schemaPath)) {
    return {
      valid: false,
      errors: [`Evidence matrix schema file missing at ${schemaPath}`]
    };
  }

  let schema;
  try {
    schema = JSON.parse(fs.readFileSync(schemaPath, 'utf8'));
  } catch (err) {
    return {
      valid: false,
      errors: [`Failed to parse evidence matrix schema: ${err.message}`]
    };
  }

  const errors = validateAgainstSchema(matrix, schema, schema);
  return {
    valid: errors.length === 0,
    errors
  };
}

export function checkEvidenceCompleteness(repoRoot = REPO_ROOT) {
  const errors = [];
  const checkedFiles = [];

  // Check individual mandatory files
  for (const item of MANDATORY_INDIVIDUAL_FILES) {
    const fullPath = path.resolve(repoRoot, item.repoPath);
    if (!fs.existsSync(fullPath)) {
      errors.push(`Missing mandatory evidence file: ${item.repoPath} (${item.description})`);
    } else {
      const stats = fs.statSync(fullPath);
      if (!stats.isFile()) {
        errors.push(`Mandatory evidence path is not a regular file: ${item.repoPath}`);
      } else if (stats.size === 0) {
        errors.push(`Mandatory evidence file is empty: ${item.repoPath}`);
      } else {
        if (item.repoPath.endsWith('.json')) {
          try {
            JSON.parse(fs.readFileSync(fullPath, 'utf8'));
          } catch (err) {
            errors.push(`Mandatory evidence file is not valid JSON: ${item.repoPath} (${err.message})`);
          }
        }
        checkedFiles.push(item.repoPath);
      }
    }
  }

  // Check envelope directories
  for (const item of MANDATORY_ENVELOPE_DIRS) {
    const fullDir = path.resolve(repoRoot, item.repoDir);
    if (!fs.existsSync(fullDir) || !fs.statSync(fullDir).isDirectory()) {
      errors.push(`Missing mandatory envelope directory: ${item.repoDir} (${item.description})`);
      continue;
    }

    const files = fs.readdirSync(fullDir)
      .filter(f => f.endsWith('.json'))
      .sort();

    if (files.length === 0) {
      errors.push(`Envelope directory contains no JSON files: ${item.repoDir}`);
      continue;
    }

    for (const f of files) {
      const filePath = path.join(fullDir, f);
      const relPath = path.join(item.repoDir, f).replace(/\\/g, '/');
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) {
        continue;
      }
      if (stats.size === 0) {
        errors.push(`Envelope file is empty: ${relPath}`);
      } else {
        try {
          JSON.parse(fs.readFileSync(filePath, 'utf8'));
          checkedFiles.push(relPath);
        } catch (err) {
          errors.push(`Envelope file is not valid JSON: ${relPath} (${err.message})`);
        }
      }
    }
  }

  // 2.5 Verify authoritative evidence matrix artifact integrity, Draft-07 schema compliance, and dimension hashes
  const matrixRelPath = 'evals/evidence-matrix.json';
  const matrixFullPath = path.resolve(repoRoot, matrixRelPath);
  if (!fs.existsSync(matrixFullPath)) {
    errors.push(`Missing mandatory evidence matrix: ${matrixRelPath}`);
  } else {
    try {
      const matrix = JSON.parse(fs.readFileSync(matrixFullPath, 'utf8'));
      const schemaValidation = validateEvidenceMatrixSchema(matrix, repoRoot);
      if (!schemaValidation.valid) {
        for (const err of schemaValidation.errors) {
          errors.push(`Evidence matrix schema violation: ${err}`);
        }
      }

      // Physical artifact existence & hash verification under Fail-Closed Default-Deny
      if (matrix.dimensions && typeof matrix.dimensions === 'object') {
        for (const [dim, dimData] of Object.entries(matrix.dimensions)) {
          if (dimData && Array.isArray(dimData.artifacts)) {
            for (const art of dimData.artifacts) {
              if (art && typeof art.path === 'string') {
                const artFullPath = path.resolve(repoRoot, art.path);
                if (!fs.existsSync(artFullPath)) {
                  errors.push(`Evidence matrix artifact missing on disk: ${art.path} in dimension ${dim}`);
                } else {
                  const actualHash = crypto.createHash('sha256').update(fs.readFileSync(artFullPath)).digest('hex');
                  if (actualHash !== art.sha256) {
                    errors.push(`Evidence matrix artifact SHA-256 mismatch for ${art.path}: expected ${art.sha256}, actual ${actualHash}`);
                  }
                }
              }
            }
          }
        }
      }
    } catch (err) {
      errors.push(`Failed to parse evidence matrix (${matrixRelPath}): ${err.message}`);
    }
  }

  // 3. Check release archive completeness
  let releaseArchive = null;
  const pkgPath = path.resolve(repoRoot, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    errors.push('Missing package.json for release archive packaging');
  } else {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      if (pkg.name !== '@arcobaleno64/three-lens') {
        errors.push(`package.json name must be '@arcobaleno64/three-lens', found '${pkg.name}'`);
      }
      if (!pkg.version || typeof pkg.version !== 'string') {
        errors.push('package.json missing version for release archive packaging');
      } else {
        const archiveFiles = getReleaseArchiveFiles(repoRoot);
        if (archiveFiles.length === 0) {
          errors.push('Release archive contains 0 files to package');
        } else {
          for (const f of archiveFiles) {
            const filePath = path.resolve(repoRoot, f);
            if (!fs.existsSync(filePath)) {
              errors.push(`Release archive file missing on disk: ${f}`);
            }
            if (f.startsWith('agy-plugin-cc/') || f.includes('agy-plugin-cc')) {
              errors.push(`Release archive contains forbidden legacy path: ${f}`);
            }
          }
          const releaseZipName = `agy-security-audit-v${pkg.version}.zip`;
          releaseArchive = {
            name: releaseZipName,
            rootDir: 'agy-security-audit/',
            filesCount: archiveFiles.length
          };
        }
      }
    } catch (err) {
      errors.push(`package.json is not valid JSON: ${err.message}`);
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    checkedFiles,
    releaseArchive
  };
}

/**
 * Bundles and stages all release evidence into target directory.
 * @param {string} outDir
 * @param {string} repoRoot
 * @returns {{ targetDir: string, stagedAssets: Array<{ name: string, sizeBytes: number, sha256: string }>, shaSumsContent: string }}
 */
export function bundleReleaseEvidence(outDir, repoRoot = REPO_ROOT) {
  const check = checkEvidenceCompleteness(repoRoot);
  if (!check.valid) {
    throw new Error(`Evidence check failed before bundling:\n${check.errors.join('\n')}`);
  }

  const targetDir = path.resolve(repoRoot, outDir);
  if (targetDir === path.resolve(repoRoot)) {
    throw new Error(`Target outDir cannot be identical to repository root: ${outDir}`);
  }
  fs.mkdirSync(targetDir, { recursive: true });

  const stagedAssets = [];

  // 1. Stage mandatory individual files
  for (const item of MANDATORY_INDIVIDUAL_FILES) {
    const src = path.resolve(repoRoot, item.repoPath);
    const content = fs.readFileSync(src);
    const dest = path.join(targetDir, item.stagedName);
    fs.writeFileSync(dest, content);

    const hash = crypto.createHash('sha256').update(content).digest('hex');
    stagedAssets.push({
      name: item.stagedName,
      sizeBytes: content.length,
      sha256: hash
    });
  }

  // 2. Bundle envelope directories into empirical-benchmark-envelopes.tar.gz
  const archiveEntries = [];
  for (const item of MANDATORY_ENVELOPE_DIRS) {
    const fullDir = path.resolve(repoRoot, item.repoDir);
    const files = fs.readdirSync(fullDir)
      .filter(f => f.endsWith('.json'))
      .sort();

    for (const f of files) {
      const filePath = path.join(fullDir, f);
      const stats = fs.statSync(filePath);
      if (!stats.isFile()) continue;
      const content = fs.readFileSync(filePath);
      const archivePath = `${item.archivePrefix}/${f}`.replace(/\\/g, '/');
      archiveEntries.push({ archivePath, content });
    }
  }

  const tarGzBuffer = createDeterministicTarGz(archiveEntries);
  const tarGzName = 'empirical-benchmark-envelopes.tar.gz';
  const tarGzDest = path.join(targetDir, tarGzName);
  fs.writeFileSync(tarGzDest, tarGzBuffer);

  const tarGzHash = crypto.createHash('sha256').update(tarGzBuffer).digest('hex');
  stagedAssets.push({
    name: tarGzName,
    sizeBytes: tarGzBuffer.length,
    sha256: tarGzHash
  });

  // 3. Package clean release archive agy-security-audit-v${version}.zip
  const pkgPath = path.resolve(repoRoot, 'package.json');
  const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
  const version = pkg.version;
  const releaseZipName = `agy-security-audit-v${version}.zip`;

  const archiveFiles = getReleaseArchiveFiles(repoRoot);
  const zipEntries = [];
  for (const f of archiveFiles) {
    const filePath = path.resolve(repoRoot, f);
    if (!fs.existsSync(filePath)) continue;
    const stats = fs.statSync(filePath);
    if (!stats.isFile()) continue;
    const content = fs.readFileSync(filePath);
    const archivePath = `agy-security-audit/${f}`.replace(/\\/g, '/');
    zipEntries.push({ archivePath, content });
  }

  const releaseZipBuffer = createDeterministicZip(zipEntries);
  const releaseZipDest = path.join(targetDir, releaseZipName);
  fs.writeFileSync(releaseZipDest, releaseZipBuffer);

  const releaseZipHash = crypto.createHash('sha256').update(releaseZipBuffer).digest('hex');
  stagedAssets.push({
    name: releaseZipName,
    sizeBytes: releaseZipBuffer.length,
    sha256: releaseZipHash
  });

  // Sort staged assets alphabetically for deterministic SHA256SUMS.txt
  stagedAssets.sort((a, b) => a.name.localeCompare(b.name));

  // 4. Write SHA256SUMS.txt (POSIX LF, standard 2-space separator)
  const shaSumsLines = stagedAssets.map(asset => `${asset.sha256}  ${asset.name}`);
  const shaSumsContent = shaSumsLines.join('\n') + '\n';
  const shaSumsPath = path.join(targetDir, 'SHA256SUMS.txt');
  fs.writeFileSync(shaSumsPath, shaSumsContent, 'utf8');

  return {
    targetDir,
    stagedAssets,
    shaSumsContent
  };
}

// CLI Execution Entrypoint
export function runCli(args = process.argv.slice(2)) {
  let outDir = 'release-evidence';
  let checkOnly = false;
  let repoRoot = REPO_ROOT;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--check') {
      checkOnly = true;
    } else if (arg === '--out-dir') {
      if (i + 1 >= args.length || args[i + 1].startsWith('-')) {
        console.error('Error: --out-dir requires a directory path argument.');
        process.exit(1);
      }
      outDir = args[++i];
    } else if (arg.startsWith('--out-dir=')) {
      outDir = arg.slice('--out-dir='.length);
      if (!outDir) {
        console.error('Error: --out-dir requires a directory path argument.');
        process.exit(1);
      }
    } else if (arg === '--repo-root') {
      if (i + 1 >= args.length || args[i + 1].startsWith('-')) {
        console.error('Error: --repo-root requires a directory path argument.');
        process.exit(1);
      }
      repoRoot = path.resolve(args[++i]);
    } else if (arg.startsWith('--repo-root=')) {
      repoRoot = path.resolve(arg.slice('--repo-root='.length));
    } else if (arg === '-h' || arg === '--help') {
      console.log('Usage: node scripts/bundle-release-evidence.mjs [options]');
      console.log('');
      console.log('Options:');
      console.log('  --out-dir <dir>    Staging directory (default: release-evidence)');
      console.log('  --repo-root <dir>  Repository root directory (default: auto-detected)');
      console.log('  --check            Validate mandatory evidence completeness without staging');
      console.log('  -h, --help         Show this help message');
      process.exit(0);
    } else {
      console.error(`Error: Unrecognized option '${arg}'. Run with --help for usage.`);
      process.exit(1);
    }
  }

  if (checkOnly) {
    console.log('Checking mandatory release evidence completeness...');
    const result = checkEvidenceCompleteness(repoRoot);
    if (!result.valid) {
      console.error('Release evidence check FAILED:');
      for (const err of result.errors) {
        console.error(`  ✖ ${err}`);
      }
      process.exit(1);
    }
    console.log(`Release evidence check PASSED (${result.checkedFiles.length} files verified):`);
    for (const f of result.checkedFiles) {
      console.log(`  ✔ ${f}`);
    }
    if (result.releaseArchive) {
      console.log(`  ✔ Release archive packaging verified: ${result.releaseArchive.name} (${result.releaseArchive.filesCount} files under '${result.releaseArchive.rootDir}')`);
    }
    process.exit(0);
  }

  console.log(`Bundling release evidence into '${outDir}'...`);
  try {
    const result = bundleReleaseEvidence(outDir, repoRoot);
    console.log(`Successfully staged ${result.stagedAssets.length} release assets to ${result.targetDir}:`);
    for (const asset of result.stagedAssets) {
      console.log(`  ✔ ${asset.name} (${asset.sizeBytes} bytes) - sha256: ${asset.sha256}`);
    }
    console.log('  ✔ SHA256SUMS.txt generated.');
  } catch (err) {
    console.error(`Failed to bundle release evidence: ${err.message}`);
    process.exit(1);
  }
}

// Auto-run when invoked directly as CLI
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(__filename)) {
  runCli();
}
