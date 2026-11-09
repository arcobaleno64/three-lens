# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 25

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `bb3a39911028b11d13772bc4b05236c38502a8d9`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 25 獨立安全審查
REJECTED · 禁止合併

審查日期：2026-11-09（臺灣時間）

審查模式：Cold-Start / Adversarial / Evidence-Bound / Read-Only

正式裁定：R24-B01 尚未完全收斂，R24-B02 的雙簽章設計說明則與程式碼相符。

指定 Commit 已實作 Journal 索引連續性、雜湊鏈、逐筆 Ed25519 簽章及多來源摘要比對。然而，快速撤銷驗證路徑仍存在獨立 Witness 遺漏與歷史金鑰信任來源未驗證的問題，無法核發完整安全通過聲明。

本輪已直接透過 GitHub 連線讀取指定 Commit 的程式碼、測試、完整性清單及 CI 紀錄。

一、審查基準與已確認證據

項目

	

獨立查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




固定 Head SHA

	

bb3a39911028b11d13772bc4b05236c38502a8d9




PR 狀態

	

OPEN、Mergeable




GitHub Check Runs

	

8/8 SUCCESS




Plugin Data 測試

	

CI 確認 103/103 PASS




Render SARIF 測試

	

CI 確認 121/121 PASS




Release Evidence

	

CI 確認 29 個檔案通過檢查




雙路徑程式碼

	

Git Blob SHA 相同，SHA-256 相同




Layer 1 / Layer 2

	

已核對 SHA-256 與證據矩陣




最終安全門禁

	

FAIL

本輪獨立重新計算的 SHA-256：

產物

	

SHA-256




scripts/adapters/plugin-data-adapter.mjs

	

3f16a89f9cf058a7cb15172e89f6f8a8abbbbdd4ca33d241a201fb0d6c4418ab




skills/3lens/scripts/adapters/plugin-data-adapter.mjs

	

3f16a89f9cf058a7cb15172e89f6f8a8abbbbdd4ca33d241a201fb0d6c4418ab




skills/3lens/tool-integrity-manifest.json

	

84144e929b5eddd3b37ba85d33cb39edae34d87726c5c47c0e59307e85ddad83

GitHub 原始 Blob SHA 亦確認兩份 Adapter 為相同內容。證據矩陣記錄的兩項對應雜湊值正確。

上述查核證明提交完整性與 CI 執行結果，不等於證明所有攻擊路徑均已封閉。

二、Round 25 新增阻擋項

R25-B01：Witness 讀取路徑不一致，撤銷狀態可失去獨立錨定

P1 · OPEN

程式碼證據

getJournalRevokedKeyMap() 第 1448 行使用：

JavaScript
const witnessPath = path.join(
  dir, '.irv-monotonic-witness.json'
);

但 getWitnessStoragePaths() 第 3113–3121 行實際定義的 Witness 是：

JavaScript
const localWitnessFile =
  path.join(normDir, '.monotonic-witness.json');

另有位於 ~/.three-lens/witness/ 的獨立 System Witness。

因此，快速撤銷驗證函式並未讀取系統實際維護的兩個 Witness。第 1955、2438、3861 行呼叫該函式時所傳入的 candidateHwm，也沒有在函式內形成有效的驗證下限。

對抗性反例（靜態推導）

假設金鑰 A 已被合法撤銷，攻擊者仍持有 A 的私鑰，並可將本機 Registry、Checkpoint、Journal、History 回復至撤銷前的有效快照，但無法修改外部 System Witness。

在這種情況下：

getJournalRevokedKeyMap() 找不到已遭回滾的 Journal 撤銷紀錄。

真正保存較新 HWM 的 Witness 不會被該函式讀取。

createAuthorizedRegistryUpdate() 因撤銷 Map 不包含 A，可能使用 A 的私鑰產生新的 authorizationProof。

這構成已確認的 API 授權檢查缺口。 但目前尚不能宣稱產生的 Registry 一定可成功持久化。saveTrustRegistry() 另有 assertMonotonicWitnessFreshness()，正常情況下可能阻止最終寫入。

推翻此發現的條件：證明所有使用該快速驗證結果的授權出口，都會在產生任何具效力的權威結果前，以正確 Witness 完成強制驗證；並以撤銷後的跨檔案回滾負向測試證實。

證據：Journal 快速驗證與 Witness 讀取 · 證據：實際 Witness 儲存路徑

R25-B02：未驗證的歷史 Registry 可注入 Journal 可信簽署者

P1 · OPEN

resolveJournalTrustedKeyWindows() 第 661–739 行直接解析 history/trust-registry.v*.json。

其中第 694–719 行從歷史 Registry 的 keys 收集公鑰與金鑰有效索引，卻沒有先對該歷史 Registry 執行根信任鏈驗證。

因此，getJournalRevokedKeyMap() 第 1560 行取得的 trustedKeys，可能包含尚未證明由合法 Root 授權的公鑰。

具體反例構造

在無其他可信實體錨點的測試目錄內，建立一份偽造的歷史 Registry，包含攻擊者自己的 ACTIVE 公鑰，並宣告 HWM headIndex: 0，但不提供有效 headDigest。

接著建立一筆由攻擊者私鑰簽署、entryIndex: 0、prevEntryDigest 為 64 個零的 KEY_REVOCATION Journal。

依目前控制流程：

歷史 Registry 的金鑰可加入 trustedKeys，並取得索引 0 的有效簽署視窗。

缺少 headDigest 的歷史 HWM 不會加入 physicalAnchors。

Journal 的 Ed25519 驗證可使用攻擊者自行植入的公鑰通過。

getJournalRevokedKeyMap() 可能回傳攻擊者偽造的撤銷紀錄。

這是信任來源驗證不足，不是 Ed25519 演算法遭破解。有效簽章只能證明私鑰持有者簽署過內容，不能自行證明該公鑰獲得 Root 授權。

此反例針對匯出的 getJournalRevokedKeyMap()。完整的 loadTrustRegistry() 另有歷史完整性檢查，因此尚未證明正常載入流程會接受同一份偽造狀態。

推翻條件：在公鑰進入 trustedKeys 之前強制驗證完整歷史授權鏈，並證明上述偽造歷史檔案必然遭拒。

證據：歷史金鑰生命週期解析 · 證據：Journal 簽章與摘要驗證

R25-B03：錨點摘要負向測試未真正驗證目標條件

P2 · OPEN

新增測試的 Sub-test E 原意是驗證 [JOURNAL_HEAD_MISMATCH]。

但測試首先建立了兩筆 Journal，Checkpoint 已記錄 headIndex: 1，隨後只寫入一筆被重新簽署的 fakeEntry0。

這使程式在進行摘要比較之前，就可能因 Journal 長度不足而拒絕。

測試斷言卻允許兩種結果：

JavaScript
/\[JOURNAL_HEAD_MISMATCH\]|\[JOURNAL_TRUNCATION_DETECTED\]/

所以即使完全移除新加入的錨點摘要比對，這個測試仍可能通過。

修正驗證方式： 保留完整兩筆 Journal，只修改最後一筆的 reason，使用有效私鑰重新簽署，保留索引與雜湊鏈連續性，並要求唯一可接受的結果是 [JOURNAL_HEAD_MISMATCH]。

推翻條件：提供相同長度、完整有效簽章及連續雜湊鏈，但與已保存錨點摘要不同的測試，並確認確實執行至摘要比對分支。

證據：R24-B01 新增測試
三、R24-B01 與 R24-B02 覆審結論

原阻擋項

	

Round 25 結果

	

理由




R24-B01：Journal 完整性

	

PARTIALLY HOLDS

	

索引、雜湊鏈及簽章檢查確實存在，但 Witness 與歷史信任來源仍有缺口




R24-B02：雙簽章說明

	

CLOSED（限說明修正）

	

程式碼與本輪說明的簽章職責一致

R24-B02 的具體驗證結果是：

computeRegistryAuthorizationPayload() 不涵蓋 HWM，但涵蓋 Registry 核心授權欄位；validateTrustRegistry() 會獨立驗證 HWM 的 Ed25519 簽章；computeRegistryIdentityPayload() 則將 authorizationProof 與 revocationHighWaterMark 一起納入 computeRegistryDigest() 的內容。

這確實符合所描述的雙簽章設計。不過，SHA-256 Identity Commitment 本身不是第三個授權簽章，其防回滾效力仍依賴可信且未遭替換的 Witness。

四、Round 25 正式決策
REJECTED

Merge Authorization：DENIED

R25-B01	OPEN · P1
R25-B02	OPEN · P1
R25-B03	OPEN · P2
R24-B02	CLOSED（說明修正）

本輪的確定性結論是：目前程式碼不足以支撐「所有 Journal 授權入口均完成獨立 Witness 與歷史信任鏈驗證」的聲明。

本輪未修改 Repository、未提交 GitHub Review，也未重新執行原始專案的本地測試。負向攻擊路徑為依固定 Commit 的實際控制流程進行的靜態反例推導，不能冒充已完成動態重播。正式阻擋裁定不代表三項反例都已證明能突破完整持久化流程。

不確定清單：未驗證的是三項反例在原始測試環境中的完整執行結果；使用預設的是攻擊者具備指定本機檔案回滾能力；推測的是對實際部署環境可能造成的最終特權影響，目前尚未證明端對端權限提升。

下一步（兩分鐘內）： 在 PR #52 建立 R25 阻擋紀錄，先將 R25-B01 指派為下一輪必須執行的 Witness 保留、Journal 回滾負向測試，固定 Head SHA 不變後再覆審。
```
