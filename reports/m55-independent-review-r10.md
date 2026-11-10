# Milestone 5.5 Independent Architecture & AppSec Review R10 Receipt

**Date**: `2026-11-10T07:51:00Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Branch**: `feat/v1.13.0-dev`  
**GitHub HEAD at Review**: `c7cffaa4dcd4c36c1d5731bcd878a651b8ffb0ed`  
**Verdict**: **NOT APPROVED / RELEASE GATE BLOCKED (MILESTONE ACCEPTANCE REJECTED)**  

---

## Summary of Determinations

| Finding | Severity | Core Defect & Independent Reproducer |
| :--- | :--- | :--- |
| **R10-CommitSHA** | **Blocker (Discrepancy)** | Review requested SHA `c7cffaa218...` but actual GitHub branch HEAD was `c7cffaa4dcd4c36c1d5731bcd878a651b8ffb0ed` (short hash prefix identical, full 40-char SHA mismatched). |
| **R10-F01** (prev R09-F01) | **HIGH** | `scripts/adapters/internal/test-root-capability.mjs` exports `TEST_SUPERVISOR_ROOT_TOKEN`, `testKeyStorage`, and `withTestSupervisorRootKey`. Any caller importing this internal module can obtain the token and override the key via `testKeyStorage.run()` or setting `NODE_TEST_CONTEXT`. |
| **R10-F02** (prev R09-F02) | **MEDIUM** | If multiple `session/prompt` requests arrive for the same `sessionId`, subsequent requests overwrite `pendingPromptRequests[sid]` without resolving or rejecting previous pending requests. Also `completePromptTurn` could transition state to `COMPLETED` even without pending requests. |
| **R10-F03** (prev R09-F03) | **HIGH** | TOCTOU in `07-adm-zip-path-traversal.js`: If an ancestor directory is swapped to a symlink right before `renameSync`, the rename overwrites the external target, and the post-check `unlinkSync` then deletes the external file. Post-check fail-closed cannot undo external filesystem side effects. |
| **R10-F04** (prev R09-F04) | **HIGH** | Git remote subsection matching in INI parser used `.toLowerCase()`. Git remote subsection names are case-sensitive (`[remote "Origin"]` vs `[remote "origin"]`). Parser returned the wrong remote URL when `[remote "Origin"]` preceded `[remote "origin"]`. |
| **R10-F05** (prev R09-F05) | **MEDIUM** | Narrow fix for `requestId: 0` verified, but `cancelledRequests` has unbounded growth without lifecycle eviction, and emissions can omit `requestId`. |
| **R10-F06** (NEW) | **MEDIUM** | `evals/v2-corpus/layer2-external-validity-corpus.json`: `governance.provenanceDiscipline` header declared commit `681ac5f27...` while all 26 cases were frozen with commit `966d9c976...`. Provenance metadata drifted. |

---

## Full Review Content

```markdown
# Milestone 5.5：Independent Architecture & AppSec Review R10

NOT APPROVED / RELEASE GATE BLOCKED初步裁定：審查標的身分不一致，尚不得接受 Round 10 的修復驗收宣告。

本次以 GitHub 原始資料為準，首先發現一項實質差異。

| 驗證項目 | 結果 |
| --- | --- |
| Repository | `arcobaleno64/three-lens` |
| 指定 Branch | `feat/v1.13.0-dev` |
| 要求審查的 Commit | `c7cffaa218579d4692797a7a5146c6fcbf1c3045` |
| GitHub 實際 Branch HEAD | `c7cffaa4dcd4c36c1d5731bcd878a651b8ffb0ed` |
| 第一 Parent | `966d9c9761aef7683e9c6b8c93d77da5308ccdea` |
| 第二 Parent | Branch HEAD 的 GitHub Commit 資料並未列出 |

來源：GitHub Branch API

這是可直接查驗的身分差異，不等於已證明程式有安全漏洞，但足以阻止將目前分支的證據直接套用到指定 Commit。

審查遵守以下邊界：

`V2_RELEASE_AUTHORIZED ≠ BLOCKING_AUTHORITY_PROMOTED ≠ CLEAN_ATTESTED`

即使後續驗證全部通過，也只可能支持對應範圍的 Advisory Baseline 驗收，不得自動提升為 Blocking Authority 或 Clean Certification。

## 1. 已完成的獨立實證

補充審查使用 GitHub 實際 HEAD `c7cffaa4dcd4c36c1d5731bcd878a651b8ffb0ed`。

我將兩個關鍵原始檔案重建到隔離暫存目錄，以 `git hash-object` 比對 GitHub Blob SHA，兩者完全一致，再使用 Node.js v22.16.0 執行反例測試。未修改儲存庫。

R09-F01：Test Root Key Capability Isolation

REOPENED來源：`scripts/adapters/internal/test-root-capability.mjs`，第 8–10、22–40 行

已比對 Blob：`0fd8de89f8f6e043f8eaa6629ffbf7597e7e39b1`

 反例成立

`TEST_SUPERVISOR_ROOT_TOKEN`、`testKeyStorage`、`withTestSupervisorRootKey` 仍以具名匯出公開在 internal 模組。Node.js ESM 模組的路徑名稱包含 `internal`，並不構成安全隔離。

實測確認，取得模組存取權的呼叫者可使用模組匯出的 token，並以可設定的 `NODE_TEST_CONTEXT` 進入覆寫範圍；亦可直接呼叫匯出的 `testKeyStorage.run()`。

這推翻「capability token 不可被未授權呼叫者取得」的主張。是否可從正式發行套件觸及，仍須另行驗證打包邊界。

R09-F03：Ancestor Symlink Race

REOPENED來源：`evals/oss-corpus/post-fix/07-adm-zip-path-traversal.js`，第 69–88 行

已比對 Blob：`817220ca46648fca4937dab3c3112853d0907ad2`

 反例成立，造成隔離環境中的外部檔案遺失

使用受控的 `renameSync` 呼叫攔截，精確模擬檢查完成後、實際搬移前，祖先目錄被替換為指向外部目錄的符號連結。

實驗結果：
Ancestor replaced:       true
Containment error:       raised
External file survived:  false
Original content lost:   true
程式雖在搬移後偵測出路徑逃逸並拋出錯誤，但外部既有檔案已先被覆寫，接著又被 `unlinkSync` 刪除。這不是有效的 Fail-Closed，因為拋出錯誤不能撤銷已發生的外部副作用。

此反例證明的是固定呼叫時序下仍存在可利用的競態窗口，並非宣稱已在實際系統觀察到並行攻擊。

R09-F04：Git Remote Identity Matching

REOPENED來源：`scripts/fetch-upstream-oss-fixture.mjs`，第 62–85 行

 Git 原生命令與程式解析結果不同

Git 的 remote subsection 名稱區分大小寫，但目前程式以 `.toLowerCase()` 比對名稱。

受控測試的 `.git/config` 同時含有 `[remote "Origin"]` 與 `[remote "origin"]`，前者先出現。

| 驗證方式 | 取得的 URL |
| --- | --- |
| `git config --get remote.origin.url` | `https://github.com/minimistjs/minimist.git` |
| 現行解析邏輯 | `https://example.invalid/decoy.git` |

因此，即使已修復一般 `[remote "decoy"]` 的錯誤歸屬，仍可藉由大小寫不同的 remote subsection 誤導解析器。

這影響 `safePurgeHarnessTarget()` 對 Git remote 身分的驗證；在其他刪除前置條件同時成立時，可能使不應被清除的目錄通過驗證。此處已證實身分誤判，但尚未執行實際目錄清除的端對端反例。

## 2. Round 09 五項 Finding 覆審矩陣

| 原 Finding | R10 獨立判定 | 嚴重度 | 裁定依據 |
| --- | --- | --- | --- |
| R09-F01 | REOPENED | High | Internal token 與 storage 仍可存取；已執行反例 |
| R09-F02 | PARTIALLY HOLDS | Medium | 已延後完成回應，但仍可覆寫未完成的 request |
| R09-F03 | REOPENED | High | TOCTOU 仍存在；已重現外部檔案遺失 |
| R09-F04 | REOPENED | High | Remote subsection 大小寫誤判；已與 Git 原生命令比對 |
| R09-F05 | Narrow Fix Verified | Medium residual | 數值 `0` 的 falsy 缺陷已修正，但取消權限生命週期仍有缺口 |

### R09-F02：Prompt Turn 的生命週期仍未完整封閉
同一 session 僅允許一筆 pending prompt，或明確完成／取消前一筆 request，再接受下一筆。所有終止轉換必須保證每筆 request 最多收到一次終止回應，且不會無故遺失。

### R09-F05：數值 ID 修正成立，但取消狀態管理不足
`cancelledRequests` 增加生命週期淘汰（或完成後清除），且 emission 的 request 關聯與生命週期維護。

## 3. 新增 Finding：Layer 2 Ground Truth 證據一致性

R10-F06：Frozen Corpus Provenance Metadata Drift
`evals/v2-corpus/layer2-external-validity-corpus.json` 中的 `governance.provenanceDiscipline.commitSha` 仍指向舊 commit，與 26 筆案例的 `commitSha` 不一致。
```
