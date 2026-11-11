# External Reproduction Kit (Track D Skeleton)

> **Governing Specification**: [RFC 0002: Track D - External Reproducibility, Real-World Transfer & Adoption Readiness](../rfcs/0002-external-reproducibility-and-adoption-readiness.md)  
> **Status**: REPRODUCIBILITY_READY / D-AC-10 OPEN  
> **Frozen Baseline**: `agy-security-audit v1.14.0`

---

## 1. Overview

This directory provides the authoritative, self-contained kit for unfamiliar operators to independently install, inspect, execute, and verify `agy-security-audit` claims without maintainer intervention.

Under Track D's **Multi-Axis Independence Model**, an external reproduction must be:
- **Clean-room**: Executed in a disposable or clean environment without unpublished author artifacts.
- **Autonomous**: Executed with zero maintainer assistance (any assistance is recorded and downgrades evidence to usability feedback).
- **Verifiable**: Emits a cryptographic reproduction record matching `schemas/reproduction-record.schema.json`.

---

## 2. Phase D1 Environment Doctor

The deterministic Doctor is the first preflight for Track D and performs **no network I/O**:

```bash
# Human-readable diagnostics
npm run doctor

# Machine-readable report
npm run doctor -- --json

# Deterministic policy/regression suite
npm run test:doctor
```

The JSON report conforms to `schemas/doctor-report.schema.json` and distinguishes four evidence states:

- `READY`: the checked prerequisite is affirmatively satisfied.
- `DEGRADED`: an optional capability is missing or below the recommended threshold, such as `gh` for strict provenance verification.
- `UNSUPPORTED`: a critical prerequisite is absent or incompatible.
- `UNVERIFIABLE`: static configuration exists but live enforcement has not been observed.

The Doctor deliberately keeps **Tier 2 sandbox enforcement `UNVERIFIABLE`** when only configuration files are present. A live AGY canary is required before runtime enforcement may be claimed as observed.

The machine-readable report includes local executable and plugin paths because RFC 0002 requires explicit environment provenance. Review those fields before publishing a reproduction bundle if local path disclosure is undesirable.

---

## 3. Reproduction Tiers (Roadmap)

### Tier 1: Deterministic Reproduction (Offline & Fast)
- **Prerequisites**: Node.js `>= 20.0.0`, Git `>= 2.30.0`.
- **Zero Dependencies**: Requires no `npm install` and zero external npm packages.
- **Commands**:
  ```bash
  # Execute all 7 deterministic Tier 1 verification gates and emit summary
  npm run check:reproducibility

  # Output machine-readable reproduction record JSON to stdout
  npm run check:reproducibility -- --json

  # Write reproduction record JSON to target path
  npm run check:reproducibility -- --out reproduction-record.json

  # Run the deterministic reproduction policy & regression suite
  npm run test:reproducibility
  ```
- **Automated Verification Gates**:
  1. `doctor-preflight`: Deterministic Environment Doctor Preflight (`scripts/doctor.mjs`)
  2. `evidence-bundle-completeness`: Release evidence and archive packaging (`scripts/bundle-release-evidence.mjs --check`)
  3. `docs-integrity-gate`: Documentation in lockstep with invariants (`scripts/check-docs-integrity.mjs`)
  4. `provenance-policy-tests`: SLSA provenance & attestation policy suite (`scripts/test-release-provenance.mjs` - 19/19 PASS)
  5. `doctor-policy-tests`: Doctor preflight & schema policy suite (`scripts/test-doctor.mjs` - 13/13 PASS)
  6. `section-24-release-gate`: Section 24 release-invariant gate (62 specifications, 40 invariants, 0 dependencies)
  7. `section-24-invariant-suite`: Section 24 global security invariant suite (`render-sarif.mjs` - 121/121 PASS)

### Maintainer Intervention Degradation Rule
Under RFC 0002 §6.3 and §8:
- If a reproduction run involves any out-of-band maintainer assistance, coaching, or privileged debugging, the operator must execute with `--assisted`:
  ```bash
  npm run check:reproducibility -- --assisted
  ```
- The harness sets `maintainerAssistance: true` and strictly degrades `reproductionClassification` from `INDEPENDENT_OPERATOR_REPRODUCTION` to `INDEPENDENT_ENVIRONMENT_REPLAY`.
- Any reproduction record asserting `maintainerAssistance: true` while simultaneously claiming `INDEPENDENT_OPERATOR_REPRODUCTION` or `EXTERNAL_SYSTEM_REPLICATION` is rejected as an invalid capability overclaim.

### Tier 2: Live Assurance Reproduction (Authentic LLM Execution)
- **Prerequisites**: Antigravity CLI (`agy`) `>= 1.2.0`, supported LLM credentials.
- **Commands**:
  ```bash
  # Execute Tier 2 live micro-corpus evaluation via AGY
  npm run check:micro-corpus

  # Execute Tier 2 in deterministic synthetic/mock mode (for offline / CI environments)
  npm run check:micro-corpus -- --mock

  # Run the micro-corpus policy & regression test suite (10 tests)
  npm run test:micro-corpus

  # Run unified Tier 1 + Tier 2 reproduction check
  npm run check:reproducibility -- --tier2
  npm run check:reproducibility -- --tier2 --mock
  ```
- **Frozen Micro-Corpus (`evals/micro-corpus/`)**:
  1. `quickstart-vulnerable`: Known true-positive flaw (CWE-22 path traversal direct concatenation sink).
  2. `quickstart-safe`: Known false-positive defense control (path enclosure boundary verification).
  3. `quickstart-disputed`: Architectural tradeoff / boundary condition (intentional local loopback sidecar proxy / CWE-918).
- **Verification Protocol**:
  1. Execute controlled discovery scan under Default-Deny.
  2. Retain raw stream NDJSON trace and cryptographic SHA-256 digest (`streamDigest`).
  3. Emit structured `tier2Results` block in `reproduction-record.json`.

---

## 4. Phase D3: Operator Readiness & Friction Observability

Conforming to [RFC 0002 §7](../rfcs/0002-external-reproducibility-and-adoption-readiness.md), Track D rejects subjective surveys in favor of quantitative operational friction measurements.

```bash
# Output a blank operator metrics template JSON
node scripts/operator-metrics.mjs --template

# Validate an operator metrics JSON file against schema and evaluate interface recommendations
node scripts/operator-metrics.mjs metrics.json
node scripts/operator-metrics.mjs --check metrics.json

# Run operator metrics test suite (13/13 PASS)
npm run test:operator-metrics

# Attach operator metrics to a reproduction check envelope
npm run check:reproducibility -- --metrics metrics.json --json
```

The metrics conform to `schemas/operator-metrics.schema.json`. Under RFC 0002 §7.2 (**Interface Decision Gate**), metrics empirically dictate the necessity of CLI, TUI, or GUI investments based on navigation and invocation friction thresholds:
- High raw SARIF/JSON navigation friction (`manualFilesOpenedCount > 5` or `findingAdjudicationSeconds > 300`) triggers `TUI_RECOMMENDED`.
- High invocation friction (`rerunsRequiredCount > 1` or `commandsRetriedCount > 2`) triggers `CLI_WORKFLOW_IMPROVEMENT_RECOMMENDED`.
- Ambiguity in evidence vocabulary (`misinterpretedStatusesCount > 0`) triggers `STATUS_VOCABULARY_CLARIFICATION_RECOMMENDED`.
- Occam's razor strictly prohibits building a GUI until CLI and TUI optimizations are empirically proven insufficient.

---

## 5. Provenance & Platform Compatibility References

- **Consumer Provenance Verification Path (D-AC-06)**: Complete instructions for verifying published releases via Sigstore/Rekor/gh are provided in [`docs/verify-release.md`](../verify-release.md).
- **Platform Compatibility Matrix (D-AC-07)**: Detailed transparency matrix categorizing platforms into five evidence grades (`LIVE_RUNTIME_VALIDATED`, `CI_TESTED`, `DECLARED`, `UNKNOWN`, `UNSUPPORTED`) is provided in [`platform-compatibility.md`](./platform-compatibility.md).

---

## 6. Submitting an Independent Reproduction

Once Track D implementation is complete:
1. Execute the reproduction protocol autonomously (`npm run check:reproducibility -- --tier2 --out reproduction-record.json`).
2. Optionally record and attach operator friction metrics (`--metrics <path>`).
3. Record execution environment, commands, and resulting artifact hashes.
4. Submit the resulting `reproduction-record.json` via a GitHub issue or discussion for maintainer adjudication.

---

## 7. Authority-Side Revalidation Protocol (D-AC-10 Adjudication)

Under RFC 0002 §10 and §11, incoming external reproduction submissions must undergo strict authority-side revalidation rather than blind acceptance:

```text
external reproduction-record.json
        ↓
1. Schema & Semantic Validation (`validateReproductionRecordShape`)
        ↓
2. Independent GitHub Release Asset Re-resolution (`gh release view <tag> --json assets`)
        ↓
3. Cross-Field Cryptographic Comparison:
     - releaseTag matches immutable target release
     - releaseAssetName matches canonical package archive
     - releaseAssetDigest matches canonical immutable digest recorded by GitHub Release API
     - sourceCommit matches immutable release commit
        ↓
4. Attestation & Provenance Verification (`gh attestation verify <archive> --deny-self-hosted-runners`)
        ↓
5. Independence Confirmation: `maintainerAssistance === false`
        ↓
Accept as D-AC-10 Evidence (Transitions Track D to COMPLETE / VERIFIED)
```


