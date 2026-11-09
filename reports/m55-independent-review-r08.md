# Milestone 5.5 Independent Architecture & AppSec Review R08

**Date**: `2026-11-10T02:56:00Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Commit**: `ac86018d121c093fabca021a77d4432b8b9aca0a` (HEAD of `feat/v1.13.0-dev`)  
**Parent Commit**: `ad25e2cbdbcd7dd3940505cbf622c88fdf0bf543`  
**Verdict**: **NOT APPROVED / REJECTED (MILESTONE ACCEPTANCE REJECTED)**  

---

## 1. Summary of Determinations

| Finding | Severity | Core Defect & Independent Reproduction |
| :--- | :--- | :--- |
| **R08-F01** (prev R07-F01) | **HIGH** | **Finding Digest Incompleteness**: `formatAcpDiagnostic` outputs unauthenticated fields: `remediation`, `securityProperty`, `findingType`, `proofKind`, `description`, `cwe`. Tampering with `remediation` leaves digest unchanged. |
| **R08-F02** (prev R07-F02) | **HIGH (Blocker #1)** | **Caller Self-Enabled Root Override**: `allowConfiguredRoot: true` is an untrusted option passed by the caller. An untrusted caller passes both `allowConfiguredRoot: true` and their own `trustedRootPublicKeyPem`, allowing attacker keys to forge verified findings. |
| **R08-F03** (prev R07-F03) | **HIGH** | **ACP Lifecycle Non-Conformance**: (1) `session/new` accepts caller arbitrary `sessionId` resetting existing state; (2) `session/prompt` returns `end_turn` synchronously without awaiting real analysis; (3) `session/cancel` responds with ID when ACP v1 specifies notification. |
| **R08-F04** (prev R07-F04) | **HIGH** | **Non-Enforced Generation Token**: Missing `turnId` in async work allows old tasks to emit in new turns if token is omitted (`isEmissionAllowed` falls back to current turn). |
| **R08-F05** (prev R07-F05) | **HIGH** | **Allowed Base Symlink Escape**: `canonicalAllowedBases` and `canonicalResolvedOutDir` share same resolution; if allowed base itself is a symlink pointing outside sandbox, comparison passes. `getCanonicalRealPath` falls back to `path.resolve` on error instead of fail-closed. |
| **R08-F06** (prev R07-F06) | **HIGH*** | **Adm-Zip TOCTOU & Error Handling**: Inspection and write are not atomic under concurrent directory modification; certain filesystem errors are caught and swallowed. |
| **R08-F07** (prev R07-F07) | **HIGH** | **Git Config String Containment Bypass**: `fs.readFileSync(gitConfig).includes(expectedRemote)` can match comments in `.git/config` rather than active remote entry `[remote "..."] url = ...`. |

---

## 2. Review Transcript Receipt

```markdown
# Milestone 5.5 獨立架構與 AppSec 審查報告：Round 08

NOT APPROVED / REJECTED審查裁定：Milestone 5.5 暫不符合正式驗收條件。

已透過 GitHub 連接器讀取指定 Commit 的實際原始碼，並對照 R07 的七項缺失及 ACP v1 官方規格。R08 確實改善了 Finding Digest、ACP 訊息結構及路徑驗證，但仍存在可直接從程式碼推導的信任邊界繞過。

## 1. 審查基準

| 項目 | 查驗結果 |
| --- | --- |
| Repository | `arcobaleno64/three-lens` |
| Branch | `feat/v1.13.0-dev` |
| 固定 Commit | `ac86018d121c093fabca021a77d4432b8b9aca0a` |
| Git Tree | `9d613cb831c5585485f47cec0fc580f78c25650f` |
| 審查日期 | 2026-11-10 |
| 審查模式 | Cold-Start / Adversarial / Evidence-Bound / Read-Only |
| 正式驗收 | 拒絕 |

原始碼基準：[GitHub 固定 Commit](https://github.com/arcobaleno64/three-lens/commit/ac86018d121c093fabca021a77d4432b8b9aca0a?utm_source=chatgpt.com)

GitHub 確認該 Commit 只有一個直接 Parent：`ad25e2cbdbcd7dd3940505cbf622c88fdf0bf543`。提交資料列出的 `c16bd0e...` 不是這個 Commit 的第二個直接 Parent。

本次裁定不將「未證明安全」直接視為「已證實可利用的漏洞」，而是分開標註已確認的程式碼缺失、條件式攻擊路徑及尚未完成的驗證。

## 2. R07 七項缺失逐項覆審

| Finding | R08 覆審狀態 | 風險 | 主要原因 |
| --- | --- | --- | --- |
| R07-F01 | REOPENED | HIGH | Digest 未涵蓋所有驗證後輸出的欄位 |
| R07-F02 | REOPENED | HIGH | 呼叫端仍可自行啟用自訂信任根 |
| R07-F03 | REOPENED | HIGH | ACP 工作階段與 Prompt 生命週期不完整 |
| R07-F04 | REOPENED | HIGH | 未附 Turn Token 的舊工作仍可輸出 |
| R07-F05 | REOPENED | HIGH | 允許的基底目錄本身可解析至沙盒外 |
| R07-F06 | PARTIALLY VERIFIED | HIGH* | 靜態 Symlink 防禦改善，但競態與錯誤處理仍未充分封閉 |
| R07-F07 | REOPENED | HIGH | Git Remote 使用字串包含比對，雙重證明可被偽造 |

*F06 的 HIGH 是依可同時修改檔案系統的攻擊者模型評定；若執行環境能證明目標目錄不可受並行修改，風險需重新評估。

### 已獨立重現的反例

在 Node.js v22.16.0 隔離目錄中，使用固定 Commit 對應的核心判斷邏輯，執行五組最小反例：

| 測試 | 實際觀察 |
| --- | --- |
| 修改未簽章的 `remediation` | Finding Digest 完全相同 |
| 攻擊者公鑰搭配 `allowConfiguredRoot: true` | 簽章驗證回傳 `true` |
| 舊工作省略 `turnId` | `isEmissionAllowed()` 回傳 `true` |
| Allowed Base 本身為指向沙盒外的 Symlink | 字串檢查、實體路徑檢查均回傳 `true` |
| Git Config 只在註解內包含預期 Remote URL | `gitRemoteValid` 回傳 `true` |

這些是獨立執行的核心邏輯重現，不是聲稱已執行完整儲存庫測試。重現腳本與環境限制會一併保留於審查紀錄。

## 3. 主要技術發現與修復要求

### R07-F01：簽章保護範圍仍不完整
來源：acp-adapter.mjs L45–75、L229–263。
`computeFindingDigest()` 已涵蓋原先缺少的 `title`、`location` 與 `ballots`，這部分修復成立。
然而，`formatAcpDiagnostic()` 還會輸出下列未受簽章約束的欄位：
`remediation`、`securityProperty`、`findingType`、`proofKind`，以及特定條件下作為替代來源的 `description`、`cwe`。
因此，已驗證的 Finding 仍可攜帶被修改的安全相關資訊。
修復要求： 定義版本化的 canonical signed payload，完整綁定所有具有安全意義的輸出欄位，並建立逐欄竄改測試。

### R07-F02：信任根替換權限未隔離
來源：acp-adapter.mjs L114–137。
目前的判斷是：
```javascript
options.allowConfiguredRoot === true &&
options.trustedRootPublicKeyPem
```
但 `allowConfiguredRoot` 本身也是呼叫端提供的選項。
只要不受信任的呼叫端能控制這兩個參數，就能使用自行產生的金鑰建立可通過驗證的 Finding。這並未真正建立可信設定與不可信資料間的權限隔離。
修復要求： 正式環境由可信設定管理信任根。測試金鑰應使用獨立的測試介面，而非一般 Finding 格式化函式的選項。

### R07-F03：ACP v1 生命週期仍有不一致
來源：acp-adapter.mjs L485–570。
雖然 `session/update` 的 `agent_message_chunk` 結構已改善，但仍有三項主要問題：
- `session/new` 可沿用呼叫端指定的 `sessionId`，並重設既有狀態。
- `session/prompt` 不等待實際工作完成，就回傳 `end_turn`。
- `session/cancel` 在收到 `id` 時會回覆，但 ACP v1 將它定義為 Notification。
其中第二項與官方 Prompt Turn 生命週期直接衝突。
修復要求： 使用真正的 Session State Machine，並以官方 ACP SDK/schema 進行相容性驗證，而非僅以自有格式測試判定符合 ACP v1。

### R07-F04：Generation Token 並非強制
來源：acp-adapter.mjs L408–427。
新版本確實拒絕過期或未來的明確 `turnId`，但未提供 Token 時，仍會採用目前的 Turn 判斷是否允許輸出。
因此，舊工作只要省略 Token，就可能在新 Turn 開始後繼續輸出。
修復要求： 所有非同步輸出都必須攜帶與 Session、Turn 綁定的有效 Generation Handle；未知 Session 或缺失 Handle 應拒絕。

### R07-F05：實體路徑檢查存在共同信任根問題
來源：fetch-upstream-oss-fixture.mjs L164–187。
`canonicalAllowedBases` 和 `canonicalResolvedOutDir` 使用同樣的解析機制。如果允許的基底目錄本身就是指向外部的 Symlink，兩者可能同時指向沙盒外，卻仍通過比對。
而 `getCanonicalRealPath()` 在 `realpath` 失敗後仍回退至 `path.resolve()`，不符合宣稱的全面 Fail-Closed 原則。
修復要求： 以獨立可信的實體 Repository Root 作為邊界，不得讓可變動的 Allowed Base 自行決定信任範圍。

### R07-F06：靜態防禦改善，但尚未完成封閉
來源：07-adm-zip-path-traversal.js。
目前 `lstatSync()` 可以辨識預先存在的 dangling symlink，這項修復方向正確。
剩餘問題是檢查與實際寫入之間未形成不可分割的安全操作，以及部分檔案系統檢查錯誤被忽略。
修復要求： 明確定義是否允許具備目錄寫入權限的並行攻擊者，並據此採用受保護的 Staging Directory 或具備 no-follow 保證的檔案描述元操作，同時補上錯誤處理測試。

### R07-F07：雙重證明仍無法確立所有權
來源：fetch-upstream-oss-fixture.mjs L233–277。
`markerValid && gitRemoteValid` 的 AND 邏輯已成立，但：
```javascript
fs.readFileSync(gitConfig, 'utf8').includes(expectedRemote)
```
並未驗證真正設定的 Git Remote。
只要 `.git/config` 的註解含有預期 URL，就可能通過此條件。若 Metadata Marker 亦可被同一個不可信行為者修改，兩項證據並不獨立。
修復要求： 精確解析 Remote 設定，並使用具備獨立信任來源的 Checkout 所有權資訊，不能單靠兩份可任意修改的檔案授權刪除。

## 4. Layer 2 與正式驗收證據

查閱固定 Commit 的 Corpus 與驗證器後，已確認資料集包含 26 筆案例，組成為 11 筆 Synthetic Regression、3 筆 Synthetic Clean Control、12 筆標示為 Upstream Verified OSS 的案例。
此外，Framework 文件對 Layer 2 的規模仍記載 12–16 筆，Acceptance Criteria JSON 則允許 12–32 筆。兩份治理文件必須統一後，才能明確判斷 26 筆資料集的正式驗收效力。

## 5. 三權分離不變量裁定

| 權限狀態 | 獨立裁定 |
| --- | --- |
| `V2_RELEASE_AUTHORIZED` | NOT ESTABLISHED |
| `BLOCKING_AUTHORITY_PROMOTED` | NOT AUTHORIZED |
| `CLEAN_ATTESTED` | NOT ESTABLISHED |

下一步： 先將 `R07-F02` 標記為 Round 09 的首要阻擋項，要求移除由一般呼叫端自行啟用 `allowConfiguredRoot` 的權限。
```
