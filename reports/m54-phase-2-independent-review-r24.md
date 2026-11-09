# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 24

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `24dc68491596e39e56de40b81d75fa051579641b`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 24 獨立安全審查
REJECTED · 禁止合併

正式裁定：R23-B01 尚未完全收斂。 指定 Commit 修復了空白與尾端截斷的部分情境，但仍存在可繞過撤銷檢查的 Journal 內容替換與索引偽造路徑。

本輪發現新的 P1 阻擋項 R24-B01：未驗證 Journal 內容即用於金鑰撤銷授權判定。

一、審查基準與驗證結果

項目

	

獨立查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




審查分支

	

feat/m54-phase-2-governance




固定 Head SHA

	

24dc68491596e39e56de40b81d75fa051579641b




PR 狀態

	

OPEN、Mergeable




GitHub Check Runs

	

8/8 SUCCESS




Plugin Data 測試

	

CI 紀錄確認 102/102 PASS




Render SARIF 測試

	

CI 紀錄確認 121/121 PASS




雙路徑程式碼

	

位元組一致，Git Blob SHA 相同




Layer 1 / Layer 2 雜湊

	

獨立重新計算並確認相符




最終安全門禁

	

FAIL

檢查時間：2026 年 11 月 9 日（臺灣時間）。

本輪直接透過 GitHub 連線讀取指定 Commit 的程式碼、測試、GitHub Actions 工作紀錄及完整性清單，沒有使用開發者提供的測試結果代替原始證據。

獨立重新計算的 SHA-256：

產物

	

SHA-256




plugin-data-adapter.mjs（兩份一致）

	

8702afc4af12471cdbc74dfd1dea53fee58a60b60aa8e226a581e511347b65d7




tool-integrity-manifest.json

	

edeb42f5163d678ecf45b5be9c2e0a3a54b01f938f17d77b09a3e8a3414c472f

雜湊一致只能證明受檢產物與聲明的版本相符，不能證明其中的授權邏輯安全。

二、Round 24 新增阻擋項
R24-B01｜P1 · Journal 前綴截斷與偽造索引可繞過金鑰撤銷檢查
OPEN · Blocking

判定：確認存在可導致錯誤撤銷判定的程式碼路徑。

直接程式碼證據：

plugin-data-adapter.mjs 第 1441–1572 行

問題集中於三個地方。

首先，第 1541–1564 行直接解析 JSON 並根據 revocationType 建立撤銷 Map，但沒有執行：

Ed25519 簽章驗證。

prevEntryDigest 雜湊鏈連續性驗證。

entryIndex === i 的實際序列驗證。

Journal 內容與 Checkpoint／Witness headDigest 的一致性驗證。

其次，第 1555 行允許從 JSON 提供任意數字作為 entryIndex：

JavaScript
const entryIdx = typeof parsed.entryIndex === 'number'
  ? parsed.entryIndex
  : i;

最後，第 1567 行只比較最大索引：

JavaScript
if (expectedMinHeadIndex >= 0 &&
    maxJournalIndex < expectedMinHeadIndex) {
  throw new Error(...);
}

這不是完整性驗證。最大索引達標，只能證明資料中存在一個足夠大的數字。

對抗性反例 A：刪除 Journal 前綴

假設原始 Journal 已完成合法簽署：

原始狀態：Checkpoint、Registry、Witness 均記錄 headIndex = 1

Index 0

KEY_REVOCATION(A)

Index 1

NONCE_REVOCATION(X)

攻擊者刪除第一筆

Index 1

NONCE_REVOCATION(X)

快速 Map 的 maxJournalIndex = 1，符合 expectedMinHeadIndex = 1，因此返回空的撤銷集合。

留下的第二筆甚至可以保有原來的合法簽章。問題是它的雜湊鏈前驅已經消失，而快速 Map 根本不檢查這件事。

這代表 R23-B01 新增的部分截斷防線仍可被繞過。

對抗性反例 B：偽造高索引

攻擊者只需把 Journal 改成：

JSON
{
  "entryIndex": 999999,
  "targetId": "DUMMY",
  "revocationType": "NONCE_REVOCATION"
}

當磁碟信任錨點記錄的 headIndex 小於或等於 999999 時，這筆沒有簽章、沒有雜湊鏈的內容仍能通過快速 Map 的索引下限檢查。

獨立邏輯重播結果：

測試案例

	

返回 Map

	

應有安全行為




原始 KEY_REVOCATION(A)

	

包含 A

	

包含 A




無簽章非撤銷紀錄替換

	

空集合

	

拒絕




刪除 index 0、保留 index 1

	

空集合

	

拒絕




偽造 entryIndex = 999999

	

空集合

	

拒絕

上述重播是依固定 SHA 的原始程式碼分支建立的隔離邏輯模型，不是宣稱完整模組的端到端測試已成功重現。

為什麼構成授權阻擋項？

以下三個入口都會使用這個 Map：

授權入口

	

原始碼行號

	

影響




createAuthorizedRegistryUpdate()

	

2354–2376

	

撤銷金鑰可能錯誤通過更新建立前的檢查




saveTrustRegistry()

	

3784–3801

	

儲存前使用同一個未完整驗證的 Map




validateTrustRegistry()

	

1880–1897

	

Registry 驗證可能錯誤判定簽署金鑰未撤銷

完整的 loadRevocationJournal() 確實具備索引、雜湊鏈與 Ed25519 驗證（第 4142–4213 行），但上述授權路徑沒有執行該完整驗證。

在攻擊者能修改 Journal 且持有已撤銷金鑰私鑰的威脅模型下，這是實質的授權檢查缺口。

修復要求： 將完整 Journal 完整性驗證納入授權決策，建立經驗證後的撤銷集合；必須驗證連續索引、逐筆簽章、雜湊鏈、完整筆數，以及 Checkpoint、Registry 與 Witness 的 digest 一致性。不可只增加 maxJournalIndex 比較。

R24-B02｜P2 · Registry 授權簽章未涵蓋聲稱的完整 HWM
OPEN · Evidence Gap

computeRegistryAuthorizationPayload() 第 1594–1621 行

實際的授權 Payload 包含 registryVersion、keys、revokedKeyIds 等欄位，但沒有 revocationHighWaterMark、headIndex 或 headDigest。

R23-B03 的測試雖然建立了包含 HWM 的 Registry 物件，並使用 computeRegistryAuthorizationPayload() 簽署，實際簽署資料仍未包含 HWM。

需要區分：程式另有 HWM 專屬 Ed25519 簽章及 Witness digest 約束，因此目前不能直接裁定 HWM 可被任意竄改。然而，「完整 HWM 已受 Registry authorizationProof 綁定」這項聲明已被實際程式碼推翻。

修復應先釐清規格要求的是單一簽章綁定，還是可驗證的雙簽章組合。若變更 canonical payload，須處理既有簽章相容性，不應直接更改格式並覆蓋原 Registry。

三、R23 三項阻擋項收斂裁定

前輪項目

	

Round 24 結論

	

依據




R23-B01（P1）

	

PARTIALLY_HOLDS

	

空 Journal、空白 Journal 與部分尾端截斷得到改善，但前綴刪除及偽造索引仍可繞過




R23-B02（P2）

	

HOLDS（限指定範圍）

	

兩種 Registry 路徑皆檢查；實際進入 readdirSync、readFileSync、JSON 解析時的錯誤會拒絕




R23-B03（P2）

	

PARTIALLY_HOLDS

	

測試確實寫入兩種 Registry，且使用正式 Payload 函式；但完整 HWM 授權簽章涵蓋聲明不成立

測試證據：tests/test-plugin-data-adapter.mjs 第 6195–6396 行。

現有負向測試涵蓋無效 JSON、缺失 targetId、空檔案與缺失檔案，並且有完整授權流程測試；但不足以推翻 R24-B01 的有效 JSON／索引偽造反例。

四、CI 與安全保證界線

已檢查 Ubuntu CI 原始執行紀錄，確認：

test:plugin-data：102 pass、0 fail。

npm test：121/121 PASS。

Release evidence check：29 files verified。

文件完整性驗證：PASS。

GitHub Check Runs：8 項全部 SUCCESS。

這些都是成立的執行證據，但沒有提供對 R24-B01 反例的拒絕證據。

另外，本輪無法透過工作容器取得完整 Git repository，因此未在本地執行整套原始測試，亦未宣稱已完成端到端未授權 Registry 寫入重播。

五、正式安全裁示

裁示項目

	

結果




Cryptographic integrity

	

FAIL




Revocation authorization

	

FAIL




Journal rollback／truncation resistance

	

FAIL




Evidence and test sufficiency

	

FAIL




Artifact integrity／CI execution

	

PASS




R23 阻擋項全數 CLOSED

	

NO




Merge authorization

	

REJECTED

本輪維持 Default-Deny：不得合併 PR #52 至 main，不得宣稱三項 R23 阻擋項已完全關閉。

能推翻主要裁定的證據是：在同一固定 Commit、相同既有授權狀態下，直接執行完整原始模組，證明上述有效 JSON 替換或前綴截斷不僅無法產生錯誤撤銷結果，也無法讓撤銷金鑰通過任何授權入口。目前的原始碼靜態路徑與邏輯重播均不支持該安全主張。

不確定清單

未查證：完整原始模組的端到端攻擊重播，以及所有部署環境的檔案權限配置。

預設前提：攻擊者可修改 Journal，並持有已撤銷金鑰私鑰，但不能修改 Checkpoint 或 Witness。

推測：錯誤的撤銷 Map 最終可促成未授權 Registry 持久化；此部分尚待完整模組執行驗證。Map 本身的錯誤結果已有直接邏輯證據。

下一步（2 分鐘內）： 將 R24-B01 登錄為 P1 OPEN 阻擋項，記錄「保留 index 1、刪除 index 0 的 KEY_REVOCATION」作為必要負向回歸測試，維持 PR #52 禁止合併。
```
