# Elastic Subagent Swarm & Consensus Voting Protocol

## 1. Presumption of Non-Pass (Default-Deny Engine)

The consensus engine operates strictly under the **Default-Deny** axiom:
- **Null Hypothesis**: Authority claims (candidate findings, patches, and coverage claims) are unverified by default (a candidate's default disposition is `DEFERRED`; `UNVERIFIED` is a status or display label, not a disposition) until conclusive affirmative proof is established. An audited component is not presumed vulnerable; a completed review may legitimately produce zero candidates.
- **Burden of Proof**: The burden of proof rests entirely on the party asserting an authority transition. A candidate cannot transition to `REPORTABLE` without independent 3-lens quorum and verified evidence, and cannot be dismissed as `SUPPRESSED / FALSE_POSITIVE` without an affirmative, reproducible proof of mitigation (exact in-repo file path and line number).
- **Fallback on Deadlock**: If consensus cannot be achieved, or if verifier subagents time out, fail to produce ballots, or exhibit proof gaps, the candidate automatically falls back to `DEFERRED / NEEDS_MANUAL_REVIEW`.

---

## 2. Elastic Discovery Concurrency Window (`--concurrency`)

To enable scalable codebase exploration without causing local OS thread exhaustion or API 429 rate limit cascades, candidate discovery across the **Component × Family Matrix** is abstracted into a **Sliding Concurrency Window**:

```
[Component × Vulnerability Family Matrix]
                    │
                    ▼ (Concurrency Window: C = 2..8 workers)
[Discovery Worker 1] [Discovery Worker 2] ... [Discovery Worker N]
                    │
                    ▼
[Candidate Findings Store: scratch/candidate-findings.json]
                    │
                    ▼
[Fixed 3-Lens Panel: REACHABILITY, DEFENSES, IMPACT]
                    │
                    ▼ (Coordinator validates identity, lens, and nonce, then persists)
[Private Ballot Store: scratch/votes/{finding_id}/ballot_{uuid}.json]
```

### Concurrency Characteristics
- **Concurrency Range**: $C_{\text{active}} \in [2, 8]$.
- **Scope**: Concurrency controls discovery speed, token consumption, and parallelism; it does **NOT** alter verification assurance or thresholds.
- **Token Budget Guardrail**: Maximum 300k tokens per single finding verification pass.

---

## 3. Double-Blind Private Ballot Protocol

To eliminate Cascading Hallucinations and Conformity Bias, verifiers must never see each other's reasoning or scores.

### Private Ballot Channels
1. The coordinator dispatches independent verification tasks via `invoke_subagent` with a generated task-correlation nonce (`X-NONCE-{token}`).
2. Verifier subagents operate strictly in least-privilege read-only mode (`commandExecutionPolicy: off`, no filesystem write tools) and return structured verdicts enclosing the nonce directly to the coordinator.
3. The coordinator enforces `expected_nonce === returned_nonce`, finding identity, and evidence format, then persists verified ballots to:
   `scratch/votes/{finding_id}/ballot_{uuid}.json`
4. Verifiers are strictly isolated: they cannot view other verifiers' ballots or communication channels.

---

## 4. Cognitive Diversity Discovery Personas (Stage 2)

During Stage 2 Discovery, subagents explore the Component $\times$ Family matrix using distinct, orthogonal personas to uncover diverse vulnerability archetypes:

### Persona 1: The Dataflow Risk Analyst
- **Focus**: Traces source-to-sink dataflows and identifies missing input neutralization.

### Persona 2: The Boundary Robustness Reviewer
- **Focus**: Checks whether validation controls remain effective under edge cases (e.g. ReDoS, Unicode normalization collisions, null-byte truncations, encoding discrepancies).

### Persona 3: The Logic & State Auditor (State Machine / Business Logic)
- **Focus**: Audits timing, authorization state machines, IDOR, race conditions (TOCTOU), and missing access controls.

### Persona 4: The Language Specification Formalist (Semantics & Spec)
- **Focus**: Probes language-level quirks: prototype pollution, variable scope leakage, implicit type conversions, and compiler/runtime edge cases.

---

## 5. Fixed 3-Lens Verification Panel (Stage 3)

In Stage 3, candidate findings are evaluated strictly by the **Fixed 3-Lens Verifier Panel**:
- `REACHABILITY Lens` (`agents/verifier-reachability.md`): Confirms untrusted source entry and unbroken flow to sink.
- `DEFENSES Lens` (`agents/verifier-defenses.md`): Confirms absence, flaws, or residual gaps in sanitizers/validators.
- `IMPACT Lens` (`agents/verifier-impact.md`): Calibrates authentic blast radius, privilege boundary transgression, and CVSS v4 vector.

### 3-Lens Ballot Schema
```json
{
  "findingId": "SEC-001",
  "lens": "REACHABILITY | DEFENSES | IMPACT",
  "decision": "SUPPORTS | REFUTES",
  "reason": "Detailed technical rationale",
  "evidence": [
    {
      "path": "src/api/routes.ts",
      "line": 42,
      "role": "entrypoint | guard | sink | impact-boundary"
    }
  ],
  "nonce": "X-NONCE-38f9b2"
}
```

### Table of Verdict Rules (3-Lens Conjunctive Verification)
1. **`CONFIRMED` (`REPORTABLE`)**:
   - Requires unanimous 3-Lens support (`supports === 3`) under Default-Deny.
   - Must include a concrete, verified taint flow pathway.
2. **`FALSE_POSITIVE` (`SUPPRESSED`)**:
   - Decisive refutation by any lens backed by verified in-repo evidence (`path` + positive line number):
     - `REACHABILITY`: Proves entrypoint is uncalled, dead code, or internal test mock.
     - `DEFENSES`: Proves affirmative defense barrier or input validation invariant.
     - `IMPACT`: Proves zero demonstrable security harm or strict containment.
   - Any refutation lacking verified evidence strictly defaults to `DEFERRED` (silence/unsupported claims are not approval).
3. **`NEEDS_MANUAL_REVIEW` (`DEFERRED`)**:
   - Default for all split decisions, lack of quorum, missing ballots, unverified refutations, or unclosed proof gaps.

---

## 6. Deadman Watchdog & Default-Deny Completion

1. **Watchdog Timer**:
   - Coordinator sets a watchdog timer via `schedule(DurationSeconds=180, Prompt="Watchdog: Subagent batch timeout")`.
   - On completion, the timer task is cancelled immediately.
2. **Quorum & Missing Ballots**:
   - In 3-Lens verification, all 3 lenses (`REACHABILITY`, `DEFENSES`, `IMPACT`) are strictly required.
   - Silence is not approval: if any lens times out or fails to return a ballot, the candidate cannot be confirmed or suppressed; it is sealed as `DEFERRED / NEEDS_MANUAL_REVIEW` under Default-Deny.

