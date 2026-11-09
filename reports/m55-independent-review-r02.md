# Milestone 5.5 Independent Architecture & AppSec Review R02

**Date**: `2026-11-10T00:21:49Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Commit**: `aeb5b6a4caa300acefc68a90d18d7b18496b2d23` (HEAD of `feat/v1.13.0-dev`)  
**Parent Commit**: `8972ef70147aebca95d020ec3ee49c61c707898e`  
**Verdict**: **NOT APPROVED FOR MILESTONE ACCEPTANCE (MILESTONE ACCEPTANCE REJECTED)**  
**Determination Status**:
- **R01-F01**: CLOSED (Constrained to upstream commit SHA identity verification)
- **R01-F02**: OPEN (CWE diversity deficit remains in Layer 2; fetch harness flaws)
- **R01-F03**: OPEN (ACP initialization payload mismatch with `validateAcpHandshake()`)
- **R01-F04**: OPEN (Authority Gate default disposition flaw: defaults to `REPORTABLE` on missing disposition)
- **R01-F05**: PARTIALLY FIXED (Range clamping improved; backpressure/cancellation open)
- **R01-F06**: PARTIALLY FIXED (Data verified with pilot envelopes; environmental differences noted)
- **R01-F07**: OPEN (Timestamp synchronized, but case ID mismatch between report and corpus)
- **R01-F08**: FIXED_PENDING_VERIFY (Context limited path patched; test assertion needed for canDeclareClean===false)
- **New Finding R02-01**: Upstream Ground Truth semantic divergence in `json-pointer` fixture
- **New Finding R02-02**: ACP initialization protocol discrepancy with `scripts/adapters/acp-transport-adapter.mjs`
- **New Finding R02-03**: `formatAcpDiagnostic` Authority Gate severity & display dissonance
- **New Finding R02-04**: OSS Fetch Harness fail-closed, case selection, and path containment gaps

---

## Findings & Actionable Remediations

### 1. R02-03 / R01-F04 (Critical Authority Gate Flaw in acp-adapter.mjs)
- **Defect**: In `formatAcpDiagnostic()`:
  ```javascript
  const disposition = String(finding.disposition || 'REPORTABLE').toUpperCase().trim();
  ```
  Missing `disposition` defaulted to `'REPORTABLE'`, converting unevidenced raw candidates into IDE Errors!
- **Fix**: Under Default-Deny, missing disposition MUST default to `'UNVERIFIED'`.
  ```javascript
  const disposition = finding.disposition ? String(finding.disposition).toUpperCase().trim() : 'UNVERIFIED';
  ```
  Add strict negative unit test: Critical finding without disposition MUST map to `HINT` with `authorityConfirmed: false`.

### 2. R02-02 / R01-F03 (ACP Initialization Alignment with acp-transport-adapter.mjs)
- **Defect**: `handleInitialize()` in `acp-adapter.mjs` returned custom schema:
  `{ capabilities: { diagnosticProvider: true } }`
  which does not align with the existing `validateAcpHandshake()` in `scripts/adapters/acp-transport-adapter.mjs`!
  In `acp-transport-adapter.mjs`, the handshake expects:
  `protocolVersion: 1`, `agentCapabilities`, `agentInfo: { name, version }`.
- **Fix**: Align `handleInitialize()` with `validateAcpHandshake()`:
  ```javascript
  {
    protocolVersion: 1,
    agentCapabilities: {
      loadContext: true,
      streamingDiagnostics: true
    },
    agentInfo: {
      name: "three-lens",
      version: "1.13.0"
    }
  }
  ```

### 3. R02-04 / R01-F02 (OSS Fetch Harness Fail-Closed Hardening)
- **Defect**:
  - Used `c.id === caseId` instead of `(c.caseId || c.id) === caseId`.
  - In `verifyUpstreamCommit()`: when API returns non-200, return non-zero exit code.
  - Path containment: ensure target directory cannot escape `--out-dir` via directory traversal in package names.
  - Increment `verifiedCount` ONLY upon successful clone/checkout.

### 4. R02-01 / R01-F02 (Layer 2 Corpus CWE Diversity & Semantic Ground Truth)
- Expand upstream corpus to cover 4 distinct CWE families:
  - `CWE-1321` (Prototype Pollution: `minimist` CVE-2020-7598)
  - `CWE-022` (Path Traversal: `node-tar` CVE-2021-32803)
  - `CWE-078` (Command Injection: `node-growl` CVE-2017-16042)
  - `CWE-1333` (ReDoS: `marked` CVE-2022-21680)

### 5. R01-F07 (Report Case ID Alignment)
- Harmonize `evals/v2-corpus/layer2-external-validity-corpus.json` and `reports/multi-tier-effort-empirical-benchmark-2026-11.md` case IDs so they match 100% character-for-character.
- Align `Generated` timestamp in UTC.

### 6. R01-F08 (Test Assertion for canDeclareClean === false under CONTEXT_LIMITED)
- Add explicit assertion in `tests/test-render-sarif.mjs` under test 90 (R9-T10):
  `assert.equal(finalized90.summary.canDeclareClean, false)`!
