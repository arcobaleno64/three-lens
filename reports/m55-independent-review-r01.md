# Milestone 5.5 Independent Architecture & AppSec Review R01

**Date**: `2026-11-09T15:49:17Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Commit**: `8972ef70147aebca95d020ec3ee49c61c707898e` (HEAD of `feat/v1.13.0-dev`)  
**Verdict**: **NOT APPROVED FOR MILESTONE ACCEPTANCE**  
**Findings Summary**: 8 Findings (4 High, 4 Medium, 0 Low)  

---

## Executive Summary & Overall Verdict

Preliminary code inspection shows that the architectural direction of the four workstreams in RFC 0006 is sound, but significant boundary issues and evidence gaps prevent milestone certification:

1. **Layer 2**: Existing validator checks disk and git object SHA-256 consistency within `three-lens`, but declared `upstreamCommitSha` values cannot be resolved in upstream open-source GitHub repositories.
2. **ACP**: JSON-RPC serialization and diagnostic mapping exist, but end-to-end ACP stream isolation, lifecycle management, and finalizer gate enforcement are incomplete.
3. **Reasoning Calibration**: Single-case `low` vs `medium` comparison supports preliminary efficiency observations, but cannot be extrapolated as generalized recall parity across security audits.
4. **Governance**: Tripartite separation is explicitly defined, but requires fail-closed enforcement across all output channels (ACP, SARIF, and CLI).

---

## Detailed Findings Table

| Finding ID | Severity | Status | Workstream | Summary |
| :--- | :--- | :--- | :--- | :--- |
| **R01-F01** | **High** | **OPEN (BLOCKING)** | WS 2 (Layer 2) | **Upstream Commit Authentication Failure**: Six `UPSTREAM_VERIFIED_OSS` cases declare `upstreamCommitSha` pointing to `three-lens` internal git history rather than resolving in upstream repos (`minimistjs/minimist`, `manuelstofer/json-pointer`, `npm/ini`). GitHub API returned `422 No commit found for SHA`. |
| **R01-F02** | **High** | **OPEN** | WS 2 (Layer 2) | **CWE Family Diversity Deficit**: Added cases only cover a single CWE (`CWE-1321` Prototype Pollution), failing RFC 0006 requirement of $\ge 4$ CWE families. Upstream fetch harness (`scripts/fetch-upstream-oss-fixture.mjs`) is missing from the tree. |
| **R01-F03** | **High** | **OPEN** | WS 3 (ACP) | **ACP Protocol Gap**: Adapter lacks initialization handshake (`initialize`/`initialized`), ballot notifications, and finalizer integration; relies on plain LSP notifications without validated ACP streaming harness. |
| **R01-F04** | **High** | **OPEN** | WS 3 (ACP) | **Bypassed Finalizer Gate in Diagnostics**: `emitDiagnostic()` allows unverified `HIGH`/`CRITICAL` candidates to be emitted as IDE Errors without requiring 3-lens consensus disposition (`CONFIRMED`/`REPORTABLE`). |
| **R01-F05** | **Medium** | **OPEN** | WS 3 (ACP) | **Input Validation & Backpressure**: Diagnostic positions lack strict integer/range validation; input size, backpressure, cancellation, and stream error handling are insufficient. |
| **R01-F06** | **Medium** | **OPEN** | WS 1 (Calibration) | **Missing Grounded Benchmark Run Envelopes**: `--effort` forwarding is functional, but claims of multi-tier empirical efficiency lack frozen, standalone raw run envelopes in `evals/live-runs/`. |
| **R01-F07** | **Medium** | **OPEN** | WS 4 (Governance) | **Outdated Frozen Timestamp**: Acceptance criteria updated upper bounds but retained stale `frozenBeforeRunTimestamp`. Empirical report had case naming discrepancies with corpus. |
| **R01-F08** | **Medium** | **OPEN** | WS 4 (Governance) | **`CONTEXT_LIMITED` Clean Risk**: Finalizer in `CONTEXT_LIMITED` state could still theoretically evaluate `canDeclareClean=true`, creating downstream misinterpretation risk. |

---

## Workstream Determinations

| Workstream | Determination | Rationale |
| :--- | :--- | :--- |
| **WS 2: Layer 2 OSS** | **BLOCKED** | Upstream provenance integrity failed physical verification against upstream remotes. |
| **WS 3: ACP Streaming** | **BLOCKED** | Missing finalizer gate enforcement and full ACP lifecycle. |
| **WS 1: Reasoning Calibration** | **PARTIALLY HOLDS** | Parameter forwarding verified; empirical data valid for exploratory pilot, but insufficient for general parity claim. |
| **WS 4: Governance** | **PARTIALLY HOLDS** | Invariants sound; requires tightening `CONTEXT_LIMITED` fail-closed clean declaration. |
