# Changelog

All notable changes to `@arcobaleno64/agy-security-audit` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.13.0] - 2026-11-10

### Milestone 5.5: Multi-Tier Empirical Calibration, Upstream Verified OSS Ground Truth & ACP Inline Streaming Diagnostics
This release delivers Milestone 5.5 workstreams 2-4 (upstream verified OSS corpus, ACP inline diagnostics, specification alignment) and only a single-fixture pilot of workstream 1. It went through 12 rounds of independent review; a 13th round on `301b672` returned NOT APPROVED, its findings were fixed afterwards (see Security and Fixed) and have not been re-reviewed.

### Added
- **Layer 2 Upstream Verified OSS Ground-Truth Corpus**:
  - Expanded external validity corpus to 26 cases (13 Vulnerable, 10 Fixed Counterparts, 3 Clean Controls) spanning 7 distinct CWE families.
  - Curated 12 real-world upstream open-source CVE pairs with 100% physical file integrity and immutable git blob SHA-256 anchoring.
- **Agent Client Protocol (ACP) Inline Streaming Diagnostics Adapter**:
  - Implemented bidirectional JSON-RPC 2.0 streaming adapter (`scripts/adapters/acp-adapter.mjs`) for real-time IDE diagnostics and ballot notifications.
  - Strict Default-Deny Authority Invariant: Unverified candidates are strictly clamped to `severity: HINT (4)` with `[UNVERIFIED CANDIDATE]` prefix; only findings cryptographically attested by the supervisor root key can escalate to `ERROR` or `WARNING`.
  - Session/turn scoped cancellation tracking, monotonic turn handles, and race-free diagnostic emission.
- **Cryptographic Authority Root Hardening & In-Memory Test Isolation**:
  - Official ACP authority gate immutably bound to sovereign supervisor root (`DEFAULT_SUPERVISOR_PUBLIC_PEM`).
  - SPKI DER SHA-256 fingerprint comparison (`computePublicKeyFingerprint`) ensuring robust, format-independent identification of revoked keys.
  - Zero caller override parameters in formal public verification APIs.
  - In-memory dynamic ephemeral keypairs for cryptographic testing with zero unrevoked static test keys; historical leaked test keys strictly confined to negative regression tests verifying fail-closed fingerprint revocation.

### Security
- **Layer 3 hook symlink bypass (present in v1.12.0; earlier versions not checked)**: paths under `scratch/` were allowed when the lexical check passed even if the real path left the repository, so a symlink planted there let reads and writes escape. Both checks must now pass. (#53)
- **Layer 4 file-descriptor binding**: `safeReadFileContained` binds the opened descriptor to the checked path (dev/ino) and uses `O_NOFOLLOW` where available. (#53)
- **ACP document binding**: a diagnostic is bound to exactly the document it is published to; suffix matching and the loss of the `file:` authority are gone, and `data.documentBound` is exposed. (#67, #69)

### Changed
- Findings signed with a repo-relative `location.uri` that are published to an absolute `file:///` URI are now downgraded to `HINT` until a trusted workspace root is supplied. (#69)

### Fixed
- The pre-invocation secret guard did not run when reached through a symlinked path. (#63)
- The `SKILL.md` header version is now checked by `check-version`. (#57, #64, #66)
- Docs said claims default to `UNVERIFIED`; the default disposition is `DEFERRED`. (#55, #65)
- CI: Windows glob expansion and a macOS temp-directory test. (#58, #59, #61, #62)

### Known limitations
- Workstream 1 (multi-tier effort calibration) is a pilot: one fixture (`SEM-03`), `low` vs `medium`, one pass. The RFC 0006 target (multi-pass runs on the Layer 2 corpus across `low`, `medium`, `high`, `argon` with D1, D2, D4 metrics) was not met; the report is labelled a smoke check.

---

## [1.12.0] - 2026-11-09

### Milestone 5.4 Phase 2: Multi-Tier Reasoning, Dual-Anchor Governance & Context Compression Contracts
This release concludes Milestone 5.4 Phase 2 across 37 rounds of independent cryptographic and AppSec review. It introduces persistent cross-session trust governance with zero-workspace pollution via `PLUGIN_DATA`, fail-closed `/compact` state preservation contracts, high-performance package slimming (-85% unpacked footprint), and modularization of the 121-rule SARIF invariant test suite.

### Added
- **Dual-Anchor `PLUGIN_DATA` Persistence & Governance**:
  - Isolated global trust registry and append-only cryptographic revocation journal (`journal.jsonl`).
  - Strict sovereign root anchoring, monotonic sequence numbers, and fail-closed transaction recovery across clean process restarts.
- **Fail-Closed `/compact` Context Contract**:
  - Nonce-anchored cryptographic state preservation across Antigravity CLI context compression boundaries.
  - Zero workspace pollution: all governance state safely confined outside the target repository.
- **Modularized Test Suite & Package Slimming**:
  - Extracted 121 invariant verification tests from `render-sarif.mjs` into `tests/test-render-sarif.mjs`, reducing scanner script footprint to 319 lines.
  - Enforced `package.json` files whitelist, reducing unpacked npm archive from 7.9 MB (398 files) to 1.2 MB (74 files, -85% reduction).

### Changed
- **Marketplace & Platform Alignment**:
  - Aligned agent skill bindings (`skills: [3lens]`) with Antigravity canonical registration.
  - Transparent fail-open boundary documentation for PreInvocation / PreToolUse hooks with defense-in-depth relying on Layer 1 sandbox.

---

## [1.11.0] - 2026-11-07

### Three-Lens Identity Realignment & Ecosystem Hardening
This release finalizes the transition to **Three-Lens (3lens)** as the canonical project and plugin identity, aligns Node.js platform compatibility requirements, adds CLI `--effort` control, introduces the authoritative FAQ and boundary definitions, and formalizes documentation and release gates.

### Added
- **Canonical Three-Lens (3lens) Plugin Identity**:
  - Rebranded plugin identity to `three-lens` with backwards compatibility across documentation, manifests, and CLI integrations.
  - Added comprehensive `docs/FAQ.md` addressing source code privacy, data handling boundaries, model independence, and zero external npm dependencies.
- **CLI Effort Level Control**:
  - Added `--effort <low|medium|high>` argument support to `skills/3lens/SKILL.md` under Dimension 0.5.
- **Node.js Environment Compatibility Baseline**:
  - Synchronized and verified minimum Node.js runtime requirement to `>= 20.0.0` across `README.md`, `README.zh-TW.md`, `package.json`, and `docs/reproduction/platform-compatibility.md`.

### Changed
- **TCB Cryptographic Manifest Pinned**:
  - Re-computed and verified SHA-256 integrity hashes for all critical trusted computing base scripts in `skills/3lens/tool-integrity-manifest.json` and `evals/evidence-matrix.json`.
- **Documentation Drift Invariant Enforcement**:
  - Synchronized `SECURITY.md` supported versions table for active support of the `1.11.x` minor line.

---

## [1.10.0] - 2026-11-05

### Landmark Milestone 5.3 & Phase B-5 Baseline Freeze Release
This milestone release culminates the 112-round Milestone 5.3 Phase B-5 independent security assurance review under Default-Deny, introducing OS-isolated replica containers, double-blind 3-lens consensus, cryptographic anti-rollback journals, and a hardened shadow execution context.

### Added
- **Stage 5: Isolated Replica View (IRV) & Preflight Replay Verification**:
  - Linux Bubblewrap (`bwrap`) container isolation running under unprivileged UID 1000 with unshared User, Mount, and Network namespaces.
  - Disposable tmpfs projections (`/tmp/irv-...`) with synthetic outbound canary socket blocks and verified zero host filesystem mutation.
  - Three-Phase Automated Preflight Verifier (`verify-third-party-preflight.mjs`) for baseline hash auditing, Ed25519 anti-rollback journal verification, and post-cleanup mount leak audits.
- **Fixed 3-Lens Double-Blind Consensus Verification**:
  - Independent verification panel comprising `REACHABILITY`, `DEFENSES`, and `IMPACT` lenses.
  - Symmetrical conjunction voting rule: Decisive refutations (e.g. proof of sanitization or unreachable sink) suppress candidates under Default-Deny; defenses cannot be outvoted 2-to-1.
- **Dual-Key Cryptographic Anti-Rollback Journal & Checkpoint Engine**:
  - Dual Ed25519 signature chain: Genesis Line 1 signed by Supervisor v1, Sequence 2 Recovery signed by Supervisor v2 (`bfa8a29c...`).
  - Strict SHA-256 hash chaining linking Genesis raw bytes to Sequence 2 `prevRecordDigest`.
  - Checkpoint state anchor binding `checkpointSequenceFloor = 2` and persistent watermark monotonic recovery state machines.
- **Hardened Shadow Context PreToolUse Guard & Subprocess Contract**:
  - Subprocess Calling Contract enforcement: Non-blocking stdin, CRLF sanitization, and protocol payload validation.
  - TOCTOU-resistant atomic file reads, path traversal containment barriers, and symlink boundary enforcement.
- **121 Automated Security Invariants**:
  - 100% pass rate (121/121) across render-sarif, CVSS v4.0 scoring, Directory Accounting reconciliation, real agent discovery evaluation, and L1.5 ground-truth disposition benchmarks.
- **Antigravity CLI Plugin Specification Conformance**:
  - Updated `plugin.json` with display metadata, logo, and proactive prompt workflows.

### Changed
- **Architectural Shift from Dynamic Reflection to Static Schema Validation**:
  - Abolished runtime dynamic prototype inspection (`walkOptionsDeep`) in favor of immutable frozen prototype baselines and strict JSON Schema Draft-07 validation.
- **Delivery Packaging Discipline (`CORE_REPACKAGING_CESSATION`)**:
  - Mandated core package freezing to prevent binary hash drift during documentation and errata corrections.
- **Updated Evaluation Corpus**:
  - Augmented `evals/external-validity-corpus.json` with real-world CVE reproductions for path traversal, prototype pollution, and command injection.

### Security
- **Root Trust Anchor Rotation & Key Custody Policy**:
  - Remediated root key exposure (`B5-R43-F01`), rotated trust anchor to v2 key (`COLLECTOR-KEY-2026-V1`), and codified 4 non-negotiable governance invariants (0 ACL mutations, 0 private key access, 0 unmanaged test re-runs, Phase B-6 unauthorized).
- **Default-Deny Authority Claims**:
  - All candidate findings, remediation patches, and test coverage claims are treated as unverified by default until confirmed by affirmative multi-lens evidence.

---

## [1.9.2] - 2026-10-18
- Addressed external validity evaluation protocols and RFC 0003 empirical validation harness.

## [1.9.1] - 2026-10-17
- Added runtime confinement benchmark matrices and verified Bubblewrap isolation contracts.

## [1.9.0] - 2026-10-15
- Implemented Isolated Replica View (IRV) prototype and supervisor key custody policies.

## [1.8.1] - 2026-09-24
- Added consumer provenance verification guide and SLSA Build Level 2 transparency logs.
