# Security Policy & Trust Model

## 1. Supported Defensive Scopes & Trust Boundary

The `security-audit` plugin is strictly designed for defensive security assurance of software artifacts. It operates exclusively within authorized repository boundaries:

### 1.1 Supported Target Scopes
- `OWNED_REPOSITORY`: Repositories authored, owned, and maintained by the user or organization.
- `CONTROLLED_REPOSITORY`: Infrastructure, internal services, and pipelines under direct administrative control.
- `AUTHORIZED_INTERNAL_REPOSITORY`: Workspaces explicitly authorized for security review and assurance.
- `LOCAL_TEST_FIXTURE`: Benign unit tests, integration test suites, and controlled evaluation fixtures.
- `LOCAL_ADVERSARIAL_FIXTURE`: Hardened regression test cases (e.g. `evals/`) executed locally to verify scanner resilience against hostile inputs (e.g. malformed git configs, prompt injection, report breakouts).

### 1.2 Explicitly Unsupported & Prohibited Scopes
- **No Third-Party Probing**: Auditing third-party websites, external APIs, or unauthorized repositories is strictly prohibited.
- **No Bug-Bounty Targets**: The plugin is not designed or authorized for external bug-bounty target hunting or remote penetration testing.
- **No Harmful Exploitation**: Execution never attempts live exploitation, credential stuffing, denial-of-service, data exfiltration, or persistence.

### 1.3 Authorized Defensive Use Only & Safe Proof Policy
- **Authorized Scope**: `security-audit` is designed strictly for defensive security assurance of repositories owned, controlled, or explicitly authorized by the user or organization.
- **Non-Destructive Guarantee**: The plugin never conducts live remote penetration testing, third-party network egress probing, credential stuffing, data exfiltration, persistence, or destructive commands.
- **Safe Proof Standards**: Vulnerability verification prioritizes static taint traces, local unit-test fixtures, and benign proof-of-concept indicators. Live harmful exploitation is explicitly prohibited and never required to establish a reportable code vulnerability.

---

## 2. Hardening & Guardrails (v1.11.0 / Production)

### 2.1 Presumption of Non-Pass (Default-Deny on Authority Claims)
- Under Default-Deny, all authority claims (candidate findings, remediation patches, and coverage claims) begin in an unverified state.
- Audited components are not presumed vulnerable; a completed review may legitimately produce zero candidates.
- Candidates cannot self-assert `CONFIRMED` or `REPORTABLE` status.
- Zero votes, lack of verifier quorum (< 2 independent votes), or missing consensus automatically forces candidates into `DEFERRED` (NEEDS_MANUAL_REVIEW).
- If coverage is `PARTIAL` or `UNCHECKABLE`, the audit engine is mathematically barred from certifying the repository as clean ("no vulnerabilities found").
- A clean audit result represents bounded assurance that declared coverage was reconciled completely with zero reportable findings, not a universal certification of flawless code.

### 2.2 Git Provenance Hardening
- Target repository `.git/config` settings such as `diff.external`, `core.fsmonitor`, textconv, or hooks can execute arbitrary binaries.
- All Git operations are executed through `safe-git.mjs` with hardened environment variables (`GIT_CONFIG_GLOBAL=NUL`, `GIT_CONFIG_SYSTEM=NUL`, `PAGER=cat`, `GIT_TERMINAL_PROMPT=0`) and safe flags (`-c core.fsmonitor=false`, `--no-ext-diff`, `--no-textconv`).
- No shell string interpolation is permitted.

### 2.3 Pre-Context Secret Protection & Anti-Leakage
- **Mandated Shadow Context Pipeline**: Review contexts are prepared by `prepare-review-context.mjs` into a dedicated sanitized shadow directory (`scratch/context/`). All agent file inspections, sink searches, and code snippets are mandated by orchestrator protocol to read exclusively from this prepared context. When runtime filesystem sandboxing telemetry is available, context isolation is attested as `OBSERVED`, otherwise truthfully attested as `MANDATED`.
- **Pre-Context Tokenization**: Raw plaintext secrets (AWS access keys, GitHub tokens, Bearer tokens, private keys, passwords, JWTs) are detected and tokenized locally before source code text is supplied to LLM inspection contexts (`tokenizeSecretsForContext`).
- **Structure-Preserving Placeholders**: Secrets are replaced with structured identifiers (`<SECRET:class=...:hash=...>`) that preserve exact line numbers, line counts, and syntactic layout so dataflow continuity is maintained without exposing real secrets to model contexts.
- **No Secret Map Leakage**: The secret resolution map is held strictly in ephemeral memory and is never serialized into agent-accessible files or review context artifacts.
- **No Detokenization in Model/Report Path**: `detokenizeSecrets()` is strictly excluded from all model prompts, agent transcripts, SARIF outputs, and Markdown reports.
- **Deterministic Finalizer Masking**: Reports and SARIF files emitted by `finalize-scan.mjs` redact any residual or tokenized secrets, suppressing line snippets for credential leaks (`CWE-798`) and outputting only safe fingerprints and location metadata.

### 2.4 Markdown & Output Injection Defenses
- Untrusted repository text (file names, code comments, payload strings) can contain ANSI escape sequences, Bidi override Unicode characters, Markdown heading injections (`#`), or code fence breakouts (```` ``` ```).
- Reports are processed through dedicated context-aware encoders (`sanitizeInlineText`, `sanitizeTableCell`, `sanitizeBlockText`, `sanitizeCodeSnippet`) to eliminate presentation-layer breakouts.

### 2.5 Prompt Injection Boundaries
- Code inspected by LLM agents is enclosed in XML data delimiters (`<untrusted_code_data>`).
- While this mitigates simple instruction confusion, prompt boundaries are a policy guidance mechanism rather than a cryptographic guarantee. For hostile repositories, containerized sandboxing is essential.

### 2.6 Strict Path Containment & Sibling Prefix Enclosure (R7-P0-01, v1.1.0 P0/P1)
- All boundary enforcement logic is centralized in the authoritative TCB module [`skills/3lens/scripts/path-containment.mjs`](file:///skills/3lens/scripts/path-containment.mjs).
- Context preparation (`prepare-review-context.mjs`), evidence snapshotting (`finalize-scan.mjs`), PreToolUse interception (`hooks/shadow-context-guard.mjs`), and attack path verification (`validate-attack-path.mjs`) consume `isPathContained()` and `isRealPathContained()`.
- Containment relies on `path.relative()` containment algebra (`relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative))`) rather than string-prefix matching (`startsWith`), strictly preventing parent directory traversals (`../outside`) and sibling directory confusion (e.g. `scratch/context` vs `scratch/context-evil`).
- Canonical target validation asserts realpath containment via `fs.realpathSync()`, failing closed under Default-Deny on unresolvable or escaping symbolic links (CWE-59 defense).

### 2.7 Deterministic SAST Ingestion, Funnel Corroboration & Filesystem Race Defense (R7-P0-02, R7-P1-02, v1.1.0 P0/P1)
- **Multi-Tool Corroboration**: The plugin ingests external deterministic SAST reports (Gitleaks -> Semgrep CE -> CodeQL) via `ingestExternalEvidence()`, normalizing cross-platform URI representations (Windows `\`, POSIX `/`, percent-encoded segments, `file://` schemes).
- **Granular Evidence Binding**: External findings are classified into authoritative binding states: `BOUND` (source line and hash verified), `UNBOUND_PATH` (line beyond EOF or syntax issue), `UNBOUND_MISSING_FILE` (target file missing), `GENERATED_DUPLICATE` (findings from generated shadow contexts such as `scratch/context/`), and `OUTSIDE_SCOPE` (paths outside repository root).
- **Filesystem Race (TOCTOU) Defense**: Hardened via `safeReadFileContained()` in `path-containment.mjs`. Instead of sequential `fs.existsSync` -> `fs.readFileSync` windows (flagged by CodeQL `js/file-system-race`), the implementation opens a dedicated file descriptor (`fs.openSync`), inspects the handle directly (`fs.fstatSync`), asserts canonical realpath containment, reads content directly from the descriptor (`fs.readSync`), and guarantees descriptor closure via `finally`.

### 2.8 4-Layer Defense-in-Depth Execution Model (v1.3.0-dev / Production)
In security audit contexts, no single security perimeter can protect against all attack vectors (e.g. prompt injection in reviewed code, symlink path traversal, arbitrary shell execution, secret exfiltration). The plugin operates under a formal four-layer defense-in-depth model:

1. **Layer 1: Terminal Sandbox (`agy --sandbox`)**
   - **Boundary**: OS kernel containment (Container/Namespaces/Seatbelt/AppContainer).
   - **Objective**: Prevents untrusted target repository code from executing arbitrary system commands, corrupting files outside the sandbox, or establishing outbound network connections.
   - **Failure Modes & Defenses**: If target code attempts malicious binary execution or reverse shells, Layer 1 denies kernel-level syscalls and network egress fail-closed.

2. **Layer 2: Permission Engine (`recommended-security-audit-permissions.json`)**
   - **Boundary**: AGY CLI runtime tool dispatch engine evaluated in strict `deny > ask > allow` order, configured via recommended role profile templates in Antigravity operator settings.
   - **Objective**: Restricts available agent tools by assigned role (`coordinator`, `discovery`, `verifiers`, `remediation`) under Default-Deny.
   - **Failure Modes & Defenses**: When the recommended profile is configured into Antigravity operator settings, if a subagent attempts privilege escalation or unauthorized actions (e.g. discovery agent attempting code edits or network access), Layer 2 blocks tool dispatch before model execution.

3. **Layer 3: Shadow Context Guard (`hooks/shadow-context-guard.mjs`, PreToolUse Hook)**
   - **Boundary**: Workspace application layer intercepting file read operations (`view_file`, `grep_search`, `list_dir`, `find_by_name`).
   - **Objective**: Intercepts direct access to raw workspace files during active security audit sessions, transparently redirects agents to the sanitized shadow context (`scratch/context/`), and blocks symlink directory traversal escaping repository roots (CWE-59). Command-line regex matching serves to reduce accidental egress misuse.
   - **Failure Modes & Defenses**: During an active audit session with initialized shadow context, direct inspection of raw or escaping files is intercepted and denied fail-closed. In the absence of an active audit context, or in the event of an unhandled hook exception/timeout, Layer 3 fails open to avoid breaking general, non-audit `agy` developer workflows. Hard isolation, persistent write protection, and complete outbound network blocking fundamentally rely on **Layer 1 (`agy --sandbox`)**.

4. **Layer 4: Deterministic Path Containment & TOCTOU-Resistant TCB (`path-containment.mjs`)**
   - **Boundary**: Trusted Computing Base (TCB) atomic filesystem I/O boundary.
   - **Objective**: Centralizes containment algebra and uses dedicated file descriptor inspection (`fs.openSync` + `fs.fstatSync` + `fs.readSync`) to prevent filesystem race conditions (TOCTOU) and sibling-prefix path collisions (e.g. `scratch/context-evil`).
   - **Failure Modes & Defenses**: If a symlink or file swap occurs between validation and read, Layer 4 descriptor binding guarantees containment against race conditions and out-of-boundary access.

### 2.9 Monotonic State & Anti-Rollback Threat Boundary (Milestone 5.4 Governance)
- **Local Multi-Anchor Defense**: Anti-rollback for cryptographic trust registries and revocation journals relies on multi-anchor monotonic witnesses persisted across separate local storage locations (`PLUGIN_DATA` + user home directory `~/.three-lens/witness/`) combined with in-process memory tracking and unbroken historical digest commitment (`registryDigests`).
- **Threat Model & Bounded Guarantee**:
  - *Covered Scenarios*: Detects single-anchor rollback, uncoordinated file deletion or corruption, intermediate historical divergence, transaction crash interruption (via signed COMMITTED and PREPARED WAL), and concurrent multi-process race conditions under standard POSIX/Windows DAC permissions (0o600).
  - *Boundary & Non-Claim*: For adversaries possessing simultaneous arbitrary write access across all separate local storage locations who also restart the host process (full state wipeout and snapshot restore), local storage locations alone cannot mathematically provide external wall-clock freshness. Full state rollbacks under full-host compromise require external hardware trust anchors or append-only transparency log endpoints. Absent an active external witness, local anti-rollback guarantees are bounded to multi-anchor local consistency, continuous ancestor history verification, and atomic WAL crash recovery.

---

## 3. Reporting Vulnerabilities

If you discover a potential security vulnerability within `three-lens`, please **do not** open a public GitHub issue.

Instead, report it responsibly via either of:
- **Private Security Disclosure** (preferred): Submit via [GitHub Security Advisories](https://github.com/arcobaleno64/three-lens/security/advisories/new). It keeps the report, the discussion, and the eventual advisory in one place.
- **Email**: <arcobaleno830623@gmail.com>, for anyone who cannot or would rather not use GitHub. This address is monitored by the maintainer; it is not a team inbox, so expect one person's response times.

### Response Expectations
- **Initial Response**: Within 48 hours.
- **Status Update**: Within 7 business days.
- **Fix & Patch Advisory**: Released in a timely patch release.

### Supported Versions

Only the current MINOR line is supported. Update this table with every MINOR bump.

| Version | Supported |
|---|---|
| 1.11.x | :white_check_mark: |
| 1.10.x | :x: |
| 1.9.x | :x: |
| 1.8.x | :x: |
| 1.7.x | :x: |
| 1.6.x | :x: |
| < 1.6.0 | :x: |
