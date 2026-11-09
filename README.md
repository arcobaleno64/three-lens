# Three-Lens (3lens) v1.11.0

three-lens is an evidence-backed, multi-stage security assurance and vulnerability verification plugin for Antigravity CLI (agy).

Its defensive architecture aligns with **NIST SSDF (SP 800-218)**, **OWASP ASVS 5.0.0**, **OWASP SAMM**, **CWE Taxonomy**, **CVSS v4.0**, and **SARIF 2.1.0**, and incorporates defensive concepts from Anthropic's Claude Security and OpenAI's Codex Security research.

[繁體中文說明 →](README.zh-TW.md)

## Related project

[`agy-plugin-cc`](https://github.com/arcobaleno64/agy-plugin-cc) is a separate Claude Code companion for running Gemini CLI or Antigravity CLI (`agy`) as a cross-model task delegate and code reviewer. It delegates work from Claude Code; `three-lens` runs natively inside Antigravity CLI. Neither project is bundled with or required by the other.

> **Independent project.** `three-lens` is community-maintained and is **not affiliated with, endorsed by, or sponsored by Google LLC, Anthropic, or OpenAI**. Third-party names identify tools, standards, or research this project interoperates with or discusses; their respective terms govern those systems.

## Getting Started

### Prerequisites & Support Matrix
- **Node.js**: `>= 20.0.0` (pure Node.js built-ins; 0 external npm dependencies).
- **Antigravity CLI (`agy`)**: `>= 1.2.0`.
- **Operating Systems**: Windows (PowerShell), Linux (Bash), macOS (Zsh/Bash).
- **Git**: `>= 2.30.0` (required for diff reviews and safe repository isolation).
- **GitHub CLI (`gh`)**: `>= 2.50.0` (optional; required only for strict SLSA provenance and release attestation verification).

### Installation
Clone or install the plugin into your Antigravity plugin directory:
```bash
git clone https://github.com/arcobaleno64/three-lens.git ~/.gemini/config/plugins/three-lens
```

### Running Your First Security Audit
Navigate to any target repository you have permission to review:
```bash
cd /path/to/target-repo
agy
```
In the Antigravity prompt, invoke the skill:
```text
/three-lens:3lens
```
Or use the short skill alias:
```text
/3lens
```
Or run with non-interactive scope flags:
- **Full repository scan**: `/three-lens:3lens --scope codebase` (or `/3lens --scope codebase`)
- **Scoped path review**: `/three-lens:3lens --scope path --path src/` (or `/3lens --scope path --path src/`)
- **Git diff review**: `/three-lens:3lens --scope changes` (or `/3lens --scope changes`)

### Expected Outputs
Upon completion of the 5-stage orchestration pipeline (Stages 1–4, with Stage 5 IRV replay), findings and evidence are generated under:
- `reports/scan.md` (or `reports/review.md`): Structured, evidence-bound executive Markdown report.
- `reports/scan.sarif`: OASIS SARIF 2.1.0 standard log for IDE, GitHub Advanced Security, or CI ingestion.
- `scratch/context/`: Sanitized, secret-redacted shadow inspection artifacts.

---

## Foundational Axiom: Presumption of Non-Pass (Default-Deny on Authority Claims)

All authority claims (candidate findings, patch remediations, and coverage completeness) default to **`UNVERIFIED`**. An audited codebase is not presumed vulnerable; a review may legitimately produce zero candidates (zero findings, no quota pressure). A candidate cannot self-declare `CONFIRMED` or `REPORTABLE`; without verifier consensus, below quorum (< 2 votes), or with zero votes, it is strictly classified `DEFERRED` (`NEEDS_MANUAL_REVIEW`). When directory-accounting coverage is incomplete, the system strictly forbids declaring the codebase clean (Clean Claim Fail-Closed). A "Clean" declaration means no validated, unremediated substantive findings and no evidence gaps remain within declared scope — a bounded assurance, not an absolute, universal certification.

---

## Audit Intents & Convergence Semantics

1. **`DISCOVERY`**: Open-ended exploration across the component × vulnerability-family matrix, producing evidence-backed candidate hypotheses. No finding quota; zero findings is a legitimate, normal outcome.
2. **`VALIDATION`**: Independent 3-Lens panel review of specific candidates, deriving an authoritative disposition.
3. **`REGRESSION`**: Patch verification and coverage-convergence mode. Reruns re-examine only the attack surface affected by the change, preventing unbounded novelty hunting.

---

## Supported Job Contracts (Operational Job Modes)

1. **`scan`**: Full-codebase vulnerability scan under strict, deterministic Directory Accounting.
2. **`review`**: Incremental review of a git commit/PR diff, with 100% changed/deleted-file accounting and safe pre-image inspection of prior history.
3. **`validate`**: Independent verification of an existing finding report — checks a single candidate without a full repository rescan.
4. **`deep`**: Multi-Run Deep Scan — multiple randomized discovery passes deduplicated via a length-prefixed deterministic fingerprint, tracking `recurrenceCount`.
5. **`remediate`**: Generates a minimal, surgical patch inside an isolated `scratch/patches/` sandbox, protected by the Patch Jail perimeter.
6. **`verify-fix`**: Patch-verification contract combining the 3-Lens verifier panel (DEFENSES, REACHABILITY, IMPACT) with baseline-staleness detection (`detectStalePatch`), strictly guarding against regressions and backdoors.

---

## Conjunctive 3-Lens Verifier Panel

Uses conjunctive logic to prevent a 2-to-1 democratic vote from overriding a concrete technical fact:
- **Reachability Lens**: Verifies call-graph and taint-path reachability; a `REFUTES` verdict determines unreachability.
- **Defenses Lens**: Verifies sanitizers and security invariants; a refutation must cite a line number and evidence (`mitigationProofLine` + `mitigationReason`), blocking democratic override.
- **Impact Lens**: Verifies the CVSS v4 11-dimension vector and substantive harm; a refutation must prove no substantive harm.

---

## 4-Layer Defense-in-Depth Execution Model & Sandbox Policy

Auditing untrusted source code requires multi-layered defense to prevent prompt injection, path traversal, unauthorized tool invocation, and host compromise. The plugin enforces a cohesive four-layer defense model:

| Layer | Component | Boundary & Mechanism | Security Objective |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **Terminal Sandbox**<br>`agy --sandbox` | OS-level container / namespaces / seatbelt isolation | Blocks arbitrary shell command execution, malicious network egress, and persistent filesystem corruption from untrusted audited code. |
| **Layer 2** | **Permission Engine**<br>`recommended-security-audit-permissions.json` | AGY CLI runtime tool dispatch (`deny > ask > allow`) | Enforces role-based least privilege (`coordinator`, `discovery`, `verifiers`, `remediation`), preventing subagents from invoking unauthorized tools or exfiltrating data. |
| **Layer 3** | **Shadow Context Guard**<br>`hooks/shadow-context-guard.mjs` | PreToolUse lifecycle hook | Transparently redirects file reads to sanitized shadow copies under `scratch/context/`, blocking symlink traversal (CWE-59) escaping repository boundaries. |
| **Layer 4** | **Deterministic TCB**<br>`path-containment.mjs` | Atomic file descriptor verification (`fs.openSync` + `fs.fstatSync`) | Eliminates filesystem race conditions (TOCTOU) and sibling-prefix path collisions (e.g. `scratch/context-evil`). |

> [!NOTE]
> **Boundary & Failure Semantics**:
> - **Layer 3 Failure Semantics**: The PreToolUse hook activates only during an active security audit session (when `scratch/context/` is present). In the absence of an active audit context, or if the hook encounters an unexpected runtime error or timeout, it fails-open to prevent disrupting the user's unrelated, general `agy` developer workflows. Complete isolation, network blocking, and filesystem write protection fundamentally rely on **Layer 1 (`agy --sandbox`)**.
> - **Command Interception Scope**: The shell command matching regex in Layer 3 (`curl`, `wget`, etc.) is designed as a guardrail to **reduce accidental tool misuse**, rather than an ironclad OS-level network boundary. Complete outbound network isolation requires Layer 1 sandbox execution.

### Recommended Permission Profile Usage

To run security audits under production-grade least privilege, launch Antigravity with the terminal sandbox enabled:

```bash
# Execute security audit under OS sandbox and role-based permissions
agy --sandbox "audit this repository for security vulnerabilities"
```

The role permissions defined in `recommended-security-audit-permissions.json` provide a recommended configuration template for operators configuring Antigravity role-based permissions (`settings.json` / profile import). When configured, they establish:
- **`coordinator`**: Allowed orchestration tools (`invoke_subagent`, `send_message`, `run_command:node skills/3lens/scripts/*`); asked on `run_command:git *`; strictly denied network egress (`read_url_content`, `search_web`, `curl`, `wget`) and write operations.
- **`discovery`**: Read-only exploration (`view_file`, `list_dir`, `grep_search`, `find_by_name`); strictly denied all write tools, network tools, and command executions.
- **`verifiers`**: Read-only 3-Lens verification panel; strictly denied all write tools, command executions, and network access.
- **`remediation`**: Surgical patch generation in isolated scratch workspaces; asked on `write_to_file`; strictly denied CI/CD manifests (`.github/*`), git metadata (`.git/*`), remote pushing (`git push`), and network egress.

---

## Directory Structure

```text
three-lens/
├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (1.11.0)
├── plugin.json                           # Antigravity plugin manifest (with schema, no BOM)
├── hooks.json                            # Antigravity hook registration (PreInvocation, PreToolUse)
├── hooks/                                # Lifecycle hook implementations
│   ├── pre-invocation-secret-guard.mjs   # PreInvocation hook: scans prompts for secrets before model dispatch
│   └── shadow-context-guard.mjs          # PreToolUse fail-closed deny with redirection to scratch/context/
├── recommended-security-audit-permissions.json # Role-based permissions profile under AGY Default-Deny
├── SECURITY.md                           # Honest trust model and sandbox boundary disclosure
├── CHANGELOG.md                          # Release history
├── CONTRIBUTING.md                       # Contribution guide
├── LICENSE                               # MIT License
├── agents/                               # Dedicated subagent definitions (at plugin root)
│   ├── security-audit-coordinator.md     # Primary orchestrator agent (mainAgent)
│   ├── threat-modeler.md                 # Threat-modeling specialist
│   ├── discovery-agent.md                # 9x10 discovery matrix specialist
│   ├── verifier-reachability.md          # 3-Lens reachability verification specialist
│   ├── verifier-defenses.md              # 3-Lens defense-mechanism verification specialist
│   └── verifier-impact.md                # 3-Lens impact-calibration verification specialist
├── evals/                                # Test corpus and semantic benchmarks
│   ├── vulnerable/                       # 10 ground-truth vulnerabilities (True Positives)
│   ├── safe/                             # 10 patched-control defensive barriers (False Positive Guards)
│   ├── prompt-injection/                 # 5 prompt-injection penetration tests
│   ├── report-injection/                 # 5 report-poisoning and control-character tests
│   ├── secret-leak/                      # 5 credential-redaction tests
│   ├── coverage-gap/                     # 5 accounting-coverage boundary tests
│   ├── git-config/                       # 5 malicious git-config isolation tests
│   ├── patch-regression/                 # 5 malicious-patch and stale-baseline tests
│   ├── semantic-benchmark/               # L1.5 disposition ground-truth benchmark (20 paired cases: 10 vulnerable, 10 safe controls)
│   ├── holdout-benchmark/                # Holdout benchmark fixtures
│   ├── live-runs/                        # Recorded live benchmark runs
│   ├── micro-corpus/                     # Micro-corpus fixtures with ground-truth.json
│   ├── oss-corpus/                       # Open-source fix diffs
│   ├── protocols/                        # Evaluation protocol definitions
│   ├── recorded-runs/                    # Recorded multi-pass runs for the stability benchmark
│   ├── reproduction-records/             # Reproduction records
│   └── test-reports/                     # Captured test-run outputs
├── schemas/                              # R2-P1-08 versioned JSON Schemas (Draft-07)
│   ├── scan-manifest.schema.json         # Directory-accounting manifest schema
│   ├── threat-model.schema.json          # Threat-model schema
│   ├── candidate.schema.json             # Candidate-finding schema (Security Property & Lineage)
│   ├── verifier-ballot.schema.json       # Verifier-ballot schema (3-Lens evidence binding)
│   ├── canonical-finding.schema.json     # Canonical authoritative-finding schema (Taxonomy & Reason Code)
│   ├── execution-attestation.schema.json # Execution-attestation schema (stage-coverage completeness)
│   ├── audit-baseline.schema.json        # Audit-baseline schema (historical state baseline)
│   ├── empirical-benchmark-run.schema.json # Empirical benchmark run envelope schema
│   ├── permissions-profile.schema.json  # Role-based permissions profile schema
│   ├── candidate-set.schema.json        # Candidate-set schema
│   ├── cross-model-protocol.schema.json # Cross-model protocol schema
│   ├── doctor-report.schema.json        # Doctor-report schema
│   ├── eval-protocol.schema.json        # Evaluation protocol schema
│   ├── evidence-matrix.schema.json      # Evidence-matrix schema
│   ├── operator-metrics.schema.json     # Operator-metrics schema
│   ├── reproduction-record.schema.json  # Reproduction-record schema
│   ├── shadow-cohort-record.schema.json # Shadow-cohort record schema
│   └── verifier-ballot-set.schema.json  # Verifier-ballot-set schema
├── rules/
│   └── AGENTS.md                         # Global zero-trust and data-review boundary rules
├── .github/                              # CI workflows (pull-request CI, release, Semgrep)
├── .security-audit/                      # Project security context for this repository
├── docs/                                 # Guides, reproduction notes and RFCs
├── reports/                              # Dated benchmark and replication reports
├── scripts/                              # Repository tooling: doctor, release provenance, benchmarks, version bump
├── test/                                 # Test fixtures (e.g. Cloudflare adapter)
├── tests/                                # Governance and invariant test suites
└── skills/
    └── 3lens/
        ├── SKILL.md                      # Primary skill entrypoint and workflow orchestration
        ├── tool-integrity-manifest.json  # Integrity manifest of critical scripts
        ├── standards/                    # R2-P1-01 standards-mapping layer
        │   ├── standards-map.json        # CWE -> ASVS 5.0 / SSDF / OWASP mapping
        │   └── applicability-profiles.json # Project-type applicability profiles
        ├── jobs/                         # 6 standard job contract specifications
        │   ├── scan.md                   # Full-repository accounting review contract
        │   ├── review.md                 # Diff and pre-image review contract
        │   ├── validate.md               # Independent finding-verification contract
        │   ├── deep.md                   # Multi-run randomized discovery and union contract
        │   ├── remediate.md              # Minimal surgical-patch generation contract
        │   └── verify-fix.md             # Patch verification and defense-invariant confirmation contract
        ├── references/
        │   ├── discovery.md              # 9-component × 10-vulnerability-family matrix
        │   ├── patching-jail.md          # Patch Jail perimeter specification
        │   ├── swarm-consensus.md        # 3-Lens conjunctive-consensus specification
        │   ├── threat-modeling.md        # Threat-modeling and 11-dimension vector baseline
        │   ├── verifier-protocol.md      # Verification protocol and evidence-binding invariants
        │   ├── finding-lineage.md        # Finding lineage tracking and fingerprinting architecture
        │   ├── safe-proof-policy.md      # Safe defensive-proof policy and prohibited commands
        │   └── model-independence.md     # Model and provider independence specification
        └── scripts/
            ├── path-containment.mjs      # Authoritative TCB path containment & TOCTOU-resistant atomic file reading
            ├── safe-git.mjs              # Hardened, isolated git-execution wrapper
            ├── finalize-scan.mjs         # Authoritative deterministic finalizer and standards integration
            ├── standards-mapping.mjs     # Industry-standards mapping and dependency-boundary detector
            ├── render-sarif.mjs          # SARIF 2.1.0 / Markdown rendering plus 121 invariant tests
            ├── build-inventory.mjs       # Ground-truth directory-accounting manifest generator
            ├── build-threat-model.mjs    # Deterministic threat-model generator
            ├── validate-attack-path.mjs  # Attack-path Schema 2.0 validation and proof-gap detection
            ├── validate-patch.mjs        # Patch-syntax, Patch Jail, staleness detection, and remediation verification
            ├── run-evals.mjs             # 50-case deterministic security-invariant and adversarial-regression suite
            ├── run-semantic-eval.mjs     # L1.5 disposition ground-truth benchmark suite
            ├── run-discovery-eval.mjs    # Agent discovery-evaluation suite (Simulated CI / Recorded Agent Run)
            ├── run-stability-eval.mjs    # Discovery-stability and multi-pass empirical benchmark
            ├── record-benchmark-run.mjs  # Recorded empirical benchmark protocol envelope recorder
            ├── prepare-review-context.mjs   # Pre-context secret protection and review-context preparation
            ├── project-context.mjs          # Project security context loader, validator and drift detector
            ├── adapters/                    # Finding-producer adapters
            │   └── cloudflare-adapter.mjs   # Cloudflare security-audit-skill findings adapter
            └── check-release-invariants.mjs # Section 24 release-invariant gate (62 specifications, 40 invariants)
```

---

## Testing & Release Verification

Run inside the project directory:
```bash
# Run the automated global security-invariant test suite:
npm test

# Run the 50-case deterministic security-invariant and adversarial-regression suite:
npm run test:evals

# Run the L1.5 disposition ground-truth benchmark (20 paired cases):
npm run test:semantic

# Run the agent discovery-evaluation benchmark (Simulated CI):
npm run test:discovery

# Run the stability benchmark (Synthetic Harness):
npm run test:stability

# Run the recorded synthetic stability benchmark (recorded multi-pass mode):
npm run test:stability-recorded

# Run the Section 24 release gate (verifies required specs, security invariants, and zero external dependencies):
npm run check:release

# Verify documentation integrity and drift prevention:
npm run check:docs

# Verify release provenance and SLSA attestation policy:
npm run test:provenance
```

---

## Public Benchmark Claims Policy (R2-P2-02)

This tool strictly follows an honest-disclosure principle and makes no exaggerated or misleading claims:
- **No claim of "100% accuracy" or "provably free of vulnerabilities"**: a Clean review result means only that **defined coverage was completed within declared scope** and no reportable issue with verified evidence was found — not a universal security proof.
- **Test-corpus and benchmark-measurement transparency disclosure**:
  - **Deterministic security-invariant and adversarial-regression suite**: 50 cases (covering 8 boundary-threat classes), verifying deterministic rules and defensive boundaries (Invariant Rate: 100%).
  - **L1.5 disposition ground-truth benchmark**: 20 paired cases (10 vulnerable, 10 safe controls), evaluating the Finalizer's deterministic disposition logic (100% 20/20 PASS) — measures decision logic compliance, not LLM discovery rate.
  - **Recorded synthetic stability benchmark**: 10 unique lineages across 3 simulated runs in `evals/recorded-runs/`, evaluating multi-run deterministic stability and line-shift invariance (100% 10/10 lineages, Mean Jaccard 100.0%).
  - **Empirical model discovery benchmark**: authentic AGY live execution harness (`scripts/run-live-model-benchmark.mjs`) tracking development baseline (SEM-03 regression set) with holdout generalization fixtures under Default-Deny.

| Benchmark | Corpus | Measurement Type | Public Status |
| :--- | :--- | :--- | :--- |
| Deterministic Invariants | 50 cases (8 boundary-threat classes) | Deterministic rule measurement (MEASURED) | 100% PASS |
| Disposition Ground Truth | 20 paired cases (10 vulnerable / 10 safe) | Deterministic decision measurement (MEASURED) | 100% PASS (20/20) |
| Recorded Synthetic Stability | 10 unique lineages (3 simulated passes) | Synthetic stability self-test (RECORDED_SYNTHETIC) | 100% PASS (10/10 lineages) |
| Synthetic Stability Harness | 3-corpus simulated pass | Synthetic pipeline self-test (SYNTHETIC_HARNESS) | PASS |
| Empirical Model Discovery | 10 benchmark fixtures (SEM-03 dev baseline) | Authentic model observation (MODEL_OBSERVED) | BASELINE ESTABLISHED |

- **Model-agnostic architecture**: every agent contract is strictly specified via data schemas and JSON Schema; the orchestrator and adjudication core do not depend on any specific LLM's proprietary hidden behavior.

---

## Licensing & Governance (Defensive Use — R2-P2-07)

- This project is licensed under the **MIT License** (see [LICENSE](LICENSE)).
- **Project Scope & Defensive Use**: Intended and supported exclusively for authorized defensive security audits, vulnerability verification, and defensive R&D against codebases, local fixtures, or environments you are legitimately authorized to review. Not designed, intended, or supported for unauthorized penetration testing, exploitation, destructive actions, credential reuse, or non-consensual threat probing.
