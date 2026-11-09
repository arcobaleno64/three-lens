# Milestone 5.4 Phase 2 Round 06 Independent Review Report

- **Date**: 2026-11-07
- **Target Pull Request**: [#52 (arcobaleno64/three-lens)](https://github.com/arcobaleno64/three-lens/pull/52)
- **Branch**: `feat/m54-phase-2-governance`
- **Reviewed Head Commit**: `ca002080f5c4ee47011b63601ba588abbf88ca3b`
- **Auditor Persona**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (Cold-Start Default-Deny via ChatGPT Pro with High Reasoning Effort)
- **Auditor Initial Verdict**: `REJECTED` (Pending remediation of combination attacks and authorization boundaries)
- **CI Status**: PASS across all runners (Ubuntu, macOS, Windows) on Run `42377398122`.

---

## 1. Auditor Findings & Scope Summary

The independent auditor performed a cold-start review of commit `ca002080f5c4ee47011b63601ba588abbf88ca3b` on PR #52.
While verifying that all GitHub Actions CI workflows passed and shallow clone issues were resolved (R05-B06 APPROVED), the auditor identified 5 critical architectural findings and combination attack vectors requiring deterministic remediation:

### 1.1 R06 Genesis Replay Combination Attack (P1 - Blocker)
- **Finding**: In `loadTrustRegistry()`, rollback detection compared `maxHistVersion > parsed.registryVersion`. When an established installation was on version 1 (`history/trust-registry.v1.json` with HWM), an attacker who replaced `supervisor-trust-registry.json` with bare Genesis v1 and simultaneously deleted `.irv-revocation-journal.jsonl` and `supervisor-revocation-checkpoint.json` could bypass rollback checks because `maxHistVersion = 1` and `parsed.registryVersion = 1`, causing `isRevoked()` to falsely accept revoked nonces.
- **Remediation**:
  1. `loadTrustRegistry()` now inspects all history files in `history/`:
     - Compares same-version historical entries: if `sameVersionHistRegistry` had a high-water mark and `parsed` lacks it, or if `parsed` has a lower high-water mark, it fails closed with `[REGISTRY_ROLLBACK_DETECTED]`.
     - Compares highest historical HWM index across any version: if `highestHistHwmIndex >= 0` and `parsed` lacks HWM or is behind, it fails closed.
     - Detects journal/checkpoint deletion: if `highestHistHwmIndex >= 0` and either `.irv-revocation-journal.jsonl` or `supervisor-revocation-checkpoint.json` is missing on disk, it fails closed with `[JOURNAL_ROLLBACK_DETECTED]`.

### 1.2 R05-B01: Revocation High-Water Mark Signature Binding & Decoupling (P1 - Blocker)
- **Finding**:
  1. HWM validation in `validateTrustRegistry()` only verified signatures if `hwm.signature || hwm.authorizedBy` was truthy; stripping both fields completely bypassed verification.
  2. Root's `authorizationProof` and HWM's sub-signature were entangled: `validateTrustRegistry()` attempted a fallback verification path that stripped HWM if root authorization failed.
- **Remediation**:
  1. When `registry.revocationHighWaterMark` is present, `authorizedBy` and `signature` are **strictly mandatory** (`[HIGH_WATER_MARK_SIGNATURE_MISSING]`).
  2. The fallback verification path that retried authorization without HWM was completely deleted.
  3. Registry structure authorization (`regObj.authorizationProof`) and HWM sub-signatures (`regObj.revocationHighWaterMark.signature`) are cleanly decoupled: Root signs the registry structure and key membership; authorized active operators sign the revocation HWM; `validateTrustRegistry()` verifies both under Default-Deny.

### 1.3 R05-B03: Complete Multi-File Transactional Rollback (P2 - Blocker)
- **Finding**: In `appendRevocationEntry()`, failure during registry update only truncated the journal, leaving checkpoint pointing to the new entry and causing subsequent reads to fail with `JOURNAL_TRUNCATION_DETECTED`.
- **Remediation**:
  1. Full pre-transaction snapshot: records initial state of journal (`initialJournalSize`), checkpoint (`initialCheckpointRaw`), registry (`initialRegistryRaw`), and history file (`initialHistRaw`).
  2. On any transaction failure in the `catch` block, all files are atomically restored to their exact pre-transaction bytes (or unlinked if they did not exist initially).
  3. Added unit test verifying that subsequent journal load passes with exact initial count and no truncation errors.

### 1.4 Signer Authority & Historical Key Lifecycle (P2)
- **Finding**:
  1. `appendRevocationEntry()` did not verify that `signerKeyId` had `ACTIVE` status or that `signerPrivateKey` matched the public key registered in the trust registry.
  2. `doLoadRevocationJournal()` stripped revoked keys from historical verification, preventing historical entries signed prior to key revocation from being verified.
- **Remediation**:
  1. `appendRevocationEntry()` enforces that new write signers must be in `registry.keys` with status `ACTIVE` or `ACTIVE_PINNED_ROOT`, not in `revokedKeyIds`, and tests cryptographic key matching before touching disk.
  2. `doLoadRevocationJournal()` resolves historical public keys from `history/trust-registry.v*.json`, ensuring complete historical verification across key rotation and lifecycle changes.

### 1.5 R05-B05: CASE Pre-Compaction State Authentication & finalizeScan Key Propagation (P1 - Blocker)
- **Finding**:
  1. In `finalizeScan.mjs`, `extractCompactedAuditHeader` was called without `compactOptions?.verifierPublicKey`.
  2. Unauthenticated `preCompactionState` could override `effectiveToolProvenance`.
  3. `canonicalJsonStringify` in `compact-guard.mjs` did not normalize `undefined`, `Date`, and array nulls.
- **Remediation**:
  1. `extractCompactedAuditHeader` now receives `verifierPublicKey` and `requireSignature`.
  2. `toolManifestDigest` strictly anchors to `effectiveToolProvenance?.toolIntegrityDigest`.
  3. `repoRootFingerprint` is derived directly from `repoRoot`.
  4. `canonicalJsonStringify` updated to filter `undefined` properties, serialize `Date` as ISO strings, and map array `undefined` to `null`.

### 1.6 Layer 2 Corpus Prototype Pollution & Concurrency Oracle Alignments (P2)
- **Finding**: `L2-08-FIX-PROTOTYPEPOLLUTION` fixed counterpart was bypassed by `constructor.prototype` in minimist 1.2.2; `L2-09-VULN-CONCURRENCY` described voucher redemption with CWE-362 while fixture was wallet withdrawal with CWE-367.
- **Remediation**:
  1. `evals/oss-corpus/post-fix/01-minimist-prototype-pollution.js` remediated to filter `constructor` and `prototype` alongside `__proto__`.
  2. `evals/v2-corpus/layer2-external-validity-corpus.json` updated with accurate CWE-367 mapping and withdrawal race condition description.

---

## 2. Verification Matrix
- `npm test`: 121/121 render-sarif and finalize-scan tests PASS.
- `npm run test:plugin-data`: 34/34 tests PASS (including combination attack, HWM stripping, signer validation, and complete rollback).
- `npm run test:compact`: 19/19 tests PASS.
- `npm run validate:v2-corpus`: 14/14 cases PASS (100% verified on disk).
- `npm run check:release`: 62 specifications, 40 security invariants PASS.
- `npm run check:docs`: PASSED.
- `bundle-release-evidence.mjs --check`: PASSED.
