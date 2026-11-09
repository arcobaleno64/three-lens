# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 08

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `4f66ba3f4efa7034dc4326b33c09396c97af11ba`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Executive Summary & Verdict

The independent auditor evaluated commit `4f66ba3f4efa7034dc4326b33c09396c97af11ba` under adversarial threat modeling with High Reasoning Effort. While GitHub Actions CI is 100% GREEN (Run 42389213329 on ubuntu/windows/macos, Run 42389213338 on Semgrep, Run 42389209812 on CodeQL), several critical authority bypasses and transaction integrity vulnerabilities were identified in the implementation.

### Blockers Breakdown:
1. **R08-B01 (P1 · Critical)**: WAL Snapshot Arbitrary File Overwrite & Deletion Vulnerability in `recoverAbortedRevocationTransaction()`.
2. **R08-B02 (P1 · High)**: WAL Recovery Must Execute Exclusively Under Joint Governance Lock & Corrupted WAL Must Fail Closed.
3. **R08-B03 (P1 · High)**: Tool Provenance Authority Anchoring Priority Inversion (`compactOptions.expectedToolManifestDigest` prioritized over runtime provenance).
4. **R08-B04 (P1 · Critical)**: Registry History Tail Deletion Anti-Rollback Bypass (deleting latest history file allows replay of legitimate prior versions).
5. **R08-B05 (P1 · High)**: Revoked Signer Lifecycle & High-Water Mark Re-signing Continuity.
6. **R08-B06 (P2 · High)**: Unauthenticated Pre-Compaction State Passes `compactGate` (compactGate must require `status: 'VERIFIED'`).
7. **R08-B07 (P2 · High)**: Stale Lock Reclamation TOCTOU in `withFileLock()`.
8. **R08-B08 (P2 · High)**: Layer 2 Corpus Lacks Universal `blobSha256` Binding Across All 14 Cases.

---

## 2. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 08 獨立安全審查

初步裁定：REJECTED 存在可證明的阻擋項

審查基準： 4f66ba3f4efa7034dc4326b33c09396c97af11ba

截至 2026-11-08，本輪已直接取得指定 Commit 的原始程式碼、PR 差異、測試程式及治理實作。不是依照修復摘要進行紙面審查。

首先確認兩件事：
- 指定 SHA 確實存在，且是 feat/m54-phase-2-governance 的合併 main 提交。
- GitHub API 回報 PR #52 仍為 open、merged: false，merge_commit_sha 為 null。因此，分支同步不能解讀為 PR 已正式合併。

一、已確認的阻擋項

R08-B01：WAL 復原存在任意檔案覆寫／刪除風險
P1 · Critical
recoverAbortedRevocationTransaction() 將 WAL 中的 journalPath、checkpointPath、regPath、histPath 當成可信任路徑。
復原時直接執行：
- fs.truncateSync(txnData.journalPath, ...)
- fs.writeFileSync(txnData.checkpointPath, ...)
- fs.writeFileSync(txnData.regPath, ...)
- fs.writeFileSync(txnData.histPath, ...)
- fs.unlinkSync(...)
這些路徑沒有重新驗證是否位於 PLUGIN_DATA，也沒有經過 safeOpenStorageFile() 的路徑及檔案描述元驗證。

R08-B02：WAL 復原未受 Unified Governance Lock 完整保護 & 損壞狀態 Fail-Closed
P1 · High
WAL JSON 解析失敗時，程式選擇直接刪除 WAL 並回傳 recovered: false，而非拒絕載入。這不符合 Default-Deny：無法判斷交易狀態時，不應把交易標記當成不存在。

R08-B03：F-02 的可信工具摘要仍允許較低信任來源覆寫
P1 · High
在 skills/3lens/scripts/finalize-scan.mjs 第 2983 行：
const trustedToolDigest = compactOptions?.expectedToolManifestDigest || effectiveToolProvenance?.toolIntegrityDigest || null;
compactOptions.expectedToolManifestDigest 具有較高優先權，執行時期可信的 effectiveToolProvenance.toolIntegrityDigest 反而退居第二順位。只要上游允許不可信輸入進入 compactOptions，攻擊者就可能提供自選摘要。

R08-B04：歷史註冊表尾端刪除仍可繞過反回滾
P1 · Critical
位置：loadTrustRegistry()，L1025–1210；saveTrustRegistry()，L1453–1608
Round 07 修復了整個 history/ 目錄遭刪除，以及創世 v1 歷史缺失的問題。但目前仍然沒有防禦歷史紀錄的尾端刪除。
安裝目錄目前為 Registry v3（已撤銷某個委任金鑰 D）。攻擊者將磁碟上的 Registry 換回舊版合法簽名的 Registry v2，同時從 history/ 目錄刪除 trust-registry.v3.json，只保留 v1 和 v2。
parsed.registryVersion (2) 不小於 maxHistVersion (2)（PASS）。攻擊者成功以合法簽名的舊版本 v2 覆蓋新版 v3！

R08-B05：已撤銷金鑰仍可簽署新 Registry 及 HWM 金鑰輪替生命週期
P1 · High
已撤銷的金鑰仍可能簽署新 Registry。
已撤銷的金鑰曾經合法簽署的歷史 HWM，又可能使 Registry 無法載入。

R08-B06：CASE 未驗證前態仍能通過最終安全閘門
P2 · High
未驗證前態仍能通過 compactGate。在 compacted session 中，未達 VERIFIED 不得通過需要可信連續性的安全閘門。

R08-B07：withFileLock() 的 stale-lock 回收仍存在競爭視窗
P2 · High
兩個等待程序可能同時判定舊鎖已失效，其中一個程序建立新鎖後，另一個程序卻依照先前的判斷刪除新鎖。這可能導致兩個程序同時進入臨界區。

R08-B08：語料庫實體內容雜湊綁定非全覆蓋
P2 · High
目前語料庫共 14 個案例，但只有 L2-08-FIX-PROTOTYPEPOLLUTION 具有 blobSha256。validate-v2-corpus.mjs 的 requiredFields 沒有包含 blobSha256，必須全覆蓋 14 個案例。

四、F-01～F-07 修復驗收矩陣
| 原阻擋項 | Round 08 裁定 | 原因 |
| --- | --- | --- |
| F-01 | FAIL | 歷史尾端刪除仍可回滾 (R08-B04) |
| F-02 | PARTIAL | 仍有 expectedToolManifestDigest 覆寫入口 (R08-B03) |
| F-03 | FAIL | WAL 路徑注入、損壞標記 fail-open (R08-B01, R08-B02) |
| F-04 | FAIL | stale-lock 回收 TOCTOU (R08-B07) |
| F-05 | PARTIAL | 內容雜湊驗證範圍有限 (R08-B08) |
| F-06 | FAIL | 未驗證前態仍能通過 compactGate (R08-B06) |
| F-07 | PASS | 明確指定的檔案解析失敗會終止 |

五、最終裁定
【REJECTED】
```
