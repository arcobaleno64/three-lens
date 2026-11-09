# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 29

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `f35b7ad93c5db20a126c1fa9565c23c36fa6d97c`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED** (P1 Blocking)

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52 — Round 29 Independent Cryptographic Systems & AppSec Review

正式裁定：REJECTED（P1 Blocking），不得合併至 main。

Review date: 2026-11-09 (Asia/Taipei)
Repository: arcobaleno64/three-lens
Pull Request: https://github.com/arcobaleno64/three-lens/pull/52
Branch: feat/m54-phase-2-governance
Frozen commit: f35b7ad93c5db20a126c1fa9565c23c36fa6d97c
Execution profile: Assurance / Cold-Start / Adversarial / Read-only
Scope: Historical and current Registry authorization, progressive Journal revocation screening, signer lifecycle, test evidence and CI. No GitHub modifications or publication.

1. Evidence integrity

Directly inspected files at the frozen SHA using the connected GitHub API and independently computed SHA-256 from returned source bytes:

| Artifact | Independent SHA-256 | Result |
| :--- | :--- | :--- |
| scripts/adapters/plugin-data-adapter.mjs | 0dca5f329d29f553c1e7bb222725c4f5071b43243352a38557badf8f03b6f143 | Matches claim |
| skills/3lens/scripts/adapters/plugin-data-adapter.mjs | 0dca5f329d29f553c1e7bb222725c4f5071b43243352a38557badf8f03b6f143 | Identical content and Git blob SHA (16751db54be7f1b4ee37cbf92aadfb7d42b5df78) |
| skills/3lens/tool-integrity-manifest.json | d96d72a709541aae18732c725b92d35bf23960e24390491b1f5ac6bb69a842ae | Matches claim |
| evals/evidence-matrix.json | aaf06a9215246ef9c9d1da792acd00727fc98c775756af9b23a64a2f80189371 | Includes expected Adapter SHA declaration |

GitHub Actions records retrieved for this commit:
- Pull Request CI run 42577212048: SUCCESS, 3 platform jobs successful. Raw Ubuntu and Windows job logs confirm test-plugin-data-adapter.mjs: 105/105 pass, documentation integrity gate PASS and 29-file release-evidence PASS.
- Semgrep run 42577212126: SUCCESS, 1 job successful.

2. Historical finding disposition

| Finding | Disposition | Evidence judgment |
| :--- | :--- | :--- |
| R27-B01 — Genesis Root binding | CLOSED in inspected resolver path | Historical Genesis v1 requires matching configured or embedded Root key ID and PEM at Adapter L750–769 |
| R27-B02 — Current Registry revoked-signer screening | PARTIAL, not complete | Current next-version branch tests journalRevokedKeyIds, but the set can remain empty because of a legitimate historical HWM=-1 |
| R28-B01 — Historical Registry revoked-signer screening | NOT CLOSED | New history branch uses the same incompletely advanced journalRevokedKeyIds set |
| R29-B01 — Revocation replay gating by historical HWM | OPEN / P1 / BLOCKING | Signer can be admitted before a valid earlier Journal revocation is processed |

3. R29-B01 — First-journal-entry revocation is skipped when history HWM=-1

Severity: P1 / High, merge blocker. Status: OPEN.

Threat assumptions: attacker controls the on-disk candidate current Registry and can inject a candidate historical Registry version, holds an earlier legitimate but subsequently revoked delegate private key K, does not possess the trusted Root private key. No signature forgery is required. A clean-slate witness or a witness whose Journal head digest remains consistent with the intact Journal prefix is within scope. Other upper-level authorization checks remain unproven.

Direct code evidence and causality:
resolveJournalTrustedKeyWindows() sets the Genesis root's active journal index to hReg.revocationHighWaterMark.headIndex, or -1 if missing (L770–777). The verifier advanceJournalRevocations() stops scanning at entry i whenever i > maxIdx (L681–710). Therefore, with HWM=-1, even a legitimate Root-signed KEY_REVOCATION at Journal index 0 is not consumed.
At historical v2, new keys are imported, and existing Root's maximum active index advances only to the historical v2 HWM (L825–844). If v2 HWM=-1, the replay still cannot inspect Journal #0.
At historical v3 authorization, the new code tests journalRevokedKeyIds.has(proof.authorizedBy) (L794–805) before it imports v3 keys and replays Journal under the v3 HWM (L822–844). K is therefore incorrectly considered not revoked, although Root has already signed Journal #0 revoking K.
K can sign v3 introducing attacker key A while Root's valid Journal #0 revocation remains intact. Give v3 a consistent Journal HWM at index 1. After accepting v3, the resolver imports A and advances the Journal; the K revocation is finally discovered, after v3's authority has already been granted.
When current Registry is identical to authenticated historical v3 in non-HWM identity, L862–876 accepts it via digest equality and L947–954 sets active A to Infinity. The main getJournalRevokedKeyMap() loop L1815–1900 accepts a Root-signed Journal #0 and an A-signed Journal #1 with a consistent digest chain; revocation of K at #0 does not undo v3 authorization.
The current Registry next-version authorization path L878–904 is vulnerable to the same empty set when only history v1/v2 exists; historical v3 injection is not required for this variant.

The computeRegistryAuthorizationPayload() at L1914–1942 signs schema/version/keys/revoked IDs but does not include revocationHighWaterMark; consequently, an HWM adjustment does not invalidate the Registry's existing authorizationProof. The full identity digest includes HWM (L1953 onward), but the direct getJournalRevokedKeyMap() path uses the Journal HWM physical anchors, not a complete Registry-version witness promotion prerequisite before adding A.

Code reference:
https://github.com/arcobaleno64/three-lens/blob/f35b7ad93c5db20a126c1fa9565c23c36fa6d97c/scripts/adapters/plugin-data-adapter.mjs#L661-L955

Why Test E misses this:
Test E at tests/test-plugin-data-adapter.mjs L6827–6835 replays the previous v3-in-history attack. Its inherited fixtures set historical Genesis v1 (L6691–6704) and v2 (L6751–6765) to revocationHighWaterMark.headIndex = 0, including a synthetic zero-filled headDigest. This opens the Root's window to parse Journal #0 before v3 authorization. It does not exercise the legitimate baseline HWM=-1 before the first journal entry. Passing Test E therefore does not establish that all Journal revocations are incorporated at the v3 authentication boundary.

4. Required closure criteria:
- Authenticate each Registry transition against a complete, valid Journal revocation prefix as of the transition; historical Registry HWM=-1 must not suppress known signed revocation entries applicable to that transition. Define a secure transition ordering or authenticated event boundary instead of relying on an unverified historical HWM as an upper bound for reading revocations.
- Make revocation replay and failure states explicit: missing, unparseable, unverifiable, or improperly bounded prefix cannot be converted into an empty journalRevokedKeyIds authorization decision. Avoid retroactive validation of a version using keys it introduces itself.
- Add two independent negative tests using v1/v2 HWM=-1: (a) only current v3 signed by revoked K; (b) v3 also in historical progression, with malicious A signing Journal #1. Both must fail before A enters trustedKeys; valid Root signature at Journal #0 and an intact Journal hash chain must be retained.
- Check counterexamples with an existing consistent external Witness as well as first initialization, and verify the repaired result in both public getJournalRevokedKeyMap() and the higher-level load/save paths. Do not treat an integrity-manifest update or CI green status as closure evidence.
- Freeze and re-check the next commit, two Adapter copies, SHA-256 declarations, targeted negatives, and CI; a separate read-only closure verification must cite the exact repaired lines and executed results.

5. What would overturn the ruling:
A successful execution of the unmodified exact commit with the two-scenario HWM=-1 fixture that necessarily rejects the candidate before accepting K's v3 authorization or A's journal signature, due to an additional mandatory check not included in the traced call path, would refute or narrow R29-B01. An active external Witness barrier may block some deployments, but does not on its own prove that the public entrypoint rejects clean-slate or Journal-prefix-consistent counterexamples.

6. Uncertainty ledger:
- Not verified: New counterexample was not executed against the full source module; only the scoped independent control-flow model ran. 8/8 check-run count was not independently enumerated.
- Assumptions: Attacker retains revoked K's private key; adversarial on-disk current/history Registry writes are possible; Journal entry 0 is authentic; no Root private key compromise. Preconditions must be assessed against actual deployment permissions.
- Inference: Upper-level trust promotion and persistence consequences beyond successful direct Registry/Journal processing require their own full-stack regression tests.

Final Round 29 ruling: REJECTED. R28-B01 remains NOT CLOSED across the HWM=-1 boundary.
```
