# Milestone 5.5 Independent Architecture & AppSec Review R09

**Date**: `2026-11-10T07:26:00Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Commit**: `50503434dfc2d72d9371b21f9f1f10fb5a72e22f` (HEAD of `feat/v1.13.0-dev`)  
**Parent Commit**: `5a07b3ac5c9cfe815fe273f92f7f405aa2e68772`  
**Verdict**: **NOT APPROVED / REJECTED (MILESTONE ACCEPTANCE REJECTED)**  

---

## 1. Summary of Determinations

| Finding | Severity | Core Defect & Independent Reproduction |
| :--- | :--- | :--- |
| **R09-F01** (prev R08-F02) | **HIGH (Blocker #1)** | **Exported Test Root Key Override**: `withTestSupervisorRootKey` is exported from public module `acp-adapter.mjs`. Caller can invoke it in non-production environments to inject attacker public key into `AsyncLocalStorage`. Needs complete removal or internal symbol encapsulation. |
| **R09-F02** (prev R08-F03) | **HIGH** | **Premature ACP Prompt Turn Completion**: `session/prompt` immediately returned `status: 'completed', stopReason: 'end_turn'` without awaiting analysis or binding request ID to completion lifecycle. |
| **R09-F03** (prev R08-F06) | **HIGH (Conditional)** | **Adm-Zip Ancestor Symlink Race**: `O_NOFOLLOW` only protects leaf file; ancestor directory can be swapped via symlink race between `lstatSync` and write. Needs isolated temporary staging directory or descriptor traversal. |
| **R09-F04** (prev R08-F07) | **HIGH** | **Git Remote Section Misattribution**: `parseGitRemoteOriginUrl()` matched first `[remote "..."]` section rather than specifically verifying `[remote "origin"]` (or matching expected remote name). |
| **R09-F05** (prev R08-F04) | **MEDIUM** | **Falsy Request ID `0` Bypass**: `if (requestId && cancelledRequests.has(requestId))` evaluates to false when `requestId === 0`. Must use `requestId !== undefined && requestId !== null`. |

---

## 2. Review Transcript Receipt

```markdown
# Milestone 5.5：Round 09 獨立架構與 AppSec 審查

NOT APPROVED / REJECTED審查基準： 50503434dfc2d72d9371b21f9f1f10fb5a72e22f
審查日期： 2026-11-10
模式： Cold-Start / Adversarial / Evidence-Bound / Read-Only

已透過 GitHub 連接器確認指定 Commit 存在，且 feat/v1.13.0-dev 的 HEAD 與指定 SHA 一致。

本輪已確認一個足以阻擋驗收的信任邊界問題：

R09-F01：測試用 Supervisor Root Key 仍可由公開 API 替換。

scripts/adapters/acp-adapter.mjs 第 38–53 行將 withTestSupervisorRootKey(pem, fn) 公開匯出，而唯一的執行環境限制是：

if (process.env.NODE_ENV === 'production') {
  throw new Error(...);
}

這並不構成可靠的 Capability Isolation。一般模組呼叫端仍能在非 production 環境呼叫該函式，傳入自行控制的公鑰，再讓驗證器從 AsyncLocalStorage 讀取這把金鑰。

因此，R08-F02 移除一般函式的 allowConfiguredRoot 選項，確實消除原來的繞過形式，但尚未消除呼叫端控制信任根的根本問題。

這項發現足以暫停正式驗收，但不代表其他六項修復均失敗。以下續行逐項覆審，區分已確認缺失、條件式攻擊路徑及尚待證明的部分。

## 一、固定版本與獨立反例結果

| 查核項目 | 結果 |
| --- | --- |
| Commit SHA | 已核對 |
| Git Tree | ce45131ce8419f45b06642d1706162f6ceaadcb1 |
| 實際直接 Parent | 5a07b3ac5c9cfe815fe273f92f7f405aa2e68772 |
| R08-F02 信任根替換 | 繞過仍成立 |
| R08-F03 Prompt 生命週期 | 尚未修復 |
| R08-F06 Zip 寫入競態 | 繞過仍成立 |
| R08-F07 Remote 身分驗證 | 繞過仍成立 |

### 獨立執行的三個最小反例

使用 Node.js v22.16.0，在隔離暫存目錄重現從固定 Commit 擷取的核心邏輯：
1. 攻擊者自訂公鑰：正常驗證 false；進入公開測試金鑰作用域後變成 true。
2. 偽裝 Git Remote：[remote "decoy"] 的 URL 被當成 origin 返回。
3. Zip 祖先目錄 Symlink 競態：啟用 O_NOFOLLOW 後，若祖先目錄被並行替換，仍可寫入外部位置。

## 二、R08 七項 Finding 最終覆審

| R08 Finding | R09 狀態 | 嚴重性 | 查核依據 |
| --- | --- | --- | --- |
| F01 Digest 完整性 | CLOSED（限審查範圍） | 已修復 | L78–115 |
| F02 Root Override | REOPENED | HIGH | L38–53 |
| F03 ACP Lifecycle | REOPENED | HIGH | L622–654 |
| F04 Mandatory Turn Token | CLOSED（原反例） | 已修復 | L449–474 |
| F05 Sandbox Realpath | PARTIALLY VERIFIED | 條件式 HIGH | 實體路徑驗證 |
| F06 Adm-Zip TOCTOU | REOPENED | 條件式 HIGH | L17–49 |
| F07 Git Remote Identity | REOPENED | HIGH | Remote 解析與驗證 |

F01 的 remediation 篡改已在獨立最小測試中使驗證失敗；F04 也確實明確拒絕缺少 turnId 的發送。F05 對原本的靜態 Symlink Escape 已有有效修復。

### 仍須處理的缺失

R09-F02｜ACP Prompt Turn 過早結束（HIGH）
session/prompt 收到訊息後立即回傳 completed / end_turn，沒有等待分析完成，completePromptTurn() 也沒有與這個請求的完成事件形成必要連結。
修復條件： 將 Prompt 的完成、取消及回應綁定同一個尚未結束的請求。

R09-F03｜O_NOFOLLOW 未防止祖先目錄替換（條件式 HIGH）
O_NOFOLLOW 主要保護最後一個路徑元件，無法保證所有祖先目錄都沒有在檢查後遭到替換。
修復條件： 使用不可受不可信行為者並行修改的隔離 staging，或原子化搬移。

R09-F04｜Git Remote 解析仍可錯認身分（HIGH）
parseGitRemoteOriginUrl() 未檢查 remoteMatch[1] === 'origin'（或指定 remote 名稱），第一個符合格式的 Remote 就可能被採用。
修復條件： 只解析預期的 Remote 名稱（如 origin），並要求明確的唯一身分。

R09-F05｜取消 Request ID 0 仍可能輸出（MEDIUM）
isEmissionAllowed() 使用 if (requestId && cancelledRequests.has(requestId))，數值 ID 0 被視為 falsy。
修復條件： 改用明確的 null/undefined 判斷 (requestId !== undefined && requestId !== null)。

## 三、Layer 2 與治理規格查核

Framework Markdown 與 Acceptance Criteria JSON 的主要數量門檻（12–32 筆）已同步。
```
