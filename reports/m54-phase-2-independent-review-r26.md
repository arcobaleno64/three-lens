# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 26

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `15028d007201698771c4e72d114ebdeb5934b293`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 26 獨立安全審查
Default-Deny · 安全放行須有正面證據

審查日期： 2026-11-09（臺灣時間）
審查模式： Cold-Start / Adversarial / Evidence-Bound / Read-Only
固定 Commit： 15028d007201698771c4e72d114ebdeb5934b293

已直接向 GitHub 查證：

項目

	

獨立查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Target

	

main




Head SHA

	

與指定 SHA 完全一致




PR 狀態

	

OPEN




Mergeable

	

TRUE




GitHub Actions

	

Pull Request CI、Semgrep 均回報 SUCCESS




審查依據

	

指定 Commit 的實際程式碼及測試

Mergeable: TRUE 僅表示 GitHub 的合併條件允許，不能取代密碼學與權限安全驗證。同樣地，CI 成功不是安全性證明。

一、已完成的完整性及 CI 查核

已從 GitHub 取得兩份 Adapter 原始內容，獨立計算 SHA-256，並核對 Layer 1 與 Layer 2。

產物

	

獨立計算 SHA-256

	

結果




scripts/adapters/plugin-data-adapter.mjs

	

259e214e74ed1356151abb596286e27910c6dcffa4c70ea7a2b0283400934fa5

	

MATCH




skills/3lens/scripts/adapters/plugin-data-adapter.mjs

	

259e214e74ed1356151abb596286e27910c6dcffa4c70ea7a2b0283400934fa5

	

MATCH




skills/3lens/tool-integrity-manifest.json

	

71bf1f47a1d41c58928e3f137c26f218491a06c4e7a4cae5e03d842e4d250334

	

MATCH

兩份 Adapter 的 Git Blob SHA 也同為 fd1441702fed583bddead3d036f4ffae84016c4a，內容一致。evals/evidence-matrix.json 內亦可找到兩項對應的正確雜湊值。

GitHub Actions 原始日誌進一步確認：

Plugin Data：104/104 PASS，0 FAIL。

Render SARIF：121/121 PASS。

Ubuntu、macOS、Windows 三個 CI Job 均 SUCCESS。

Semgrep Job SUCCESS。

文件與 Release Evidence 檢查步驟均 SUCCESS。

已確認的 CI 執行紀錄：Pull Request CI #42567801522、Semgrep #42567801784。

完整性證據成立，但這些成功結果不能證明歷史金鑰的授權來源可信。

二、Round 26 正式安全裁定
REJECTED

Merge Authorization：DENIED

決定性原因：R25-B02 尚未完全修復。

指定 Commit 新增的歷史 Registry 驗證雖然會檢查相鄰版本的 Ed25519 授權簽章，但 Genesis v1 的驗證條件不足，且沒有強制核對歷史檔名版本與 Registry 內部版本是否一致。

這讓未獲 Root 授權的公鑰，仍存在進入 trustedKeys 的程式路徑。

R26-B01：偽造 Genesis 與版本重置可污染歷史信任鏈
P1 · OPEN · Merge Blocking

主要證據：plugin-data-adapter.mjs L661–785

實際程式碼有三個相互關聯的缺口。

缺口 A：Genesis 只檢查 Root 是否存在

第 710–718 行：

JavaScript
if (hReg.registryVersion === 1) {
  const rootKey = hReg.keys?.find(
    k => k.keyId === rootId &&
         k.status === 'ACTIVE_PINNED_ROOT'
  );
  if (!rootKey || rootKey.publicKeyPem !== rootPem) {
    // reject
  }
  priorVerifiedReg = hReg;
}

這證明 Registry 包含正確的 Root 公鑰，卻沒有證明其他公鑰獲得 Root 授權。

相較之下，完整的 validateTrustRegistry() 在第 2241–2254 行，明確要求 Genesis keys.length === 1，且唯一金鑰就是預設 Root。

兩個驗證入口對 Genesis 的安全定義不一致。

缺口 B：歷史檔名版本沒有與內部版本綁定

第 686–691 行依檔名排序，但第 710 行直接根據 JSON 的 registryVersion === 1 接受 Genesis。

因此，名為 trust-registry.v99.json 的檔案，即使內部宣告 registryVersion: 1，也可能進入 Genesis 分支。

缺口 C：後續 Genesis 可以重設已驗證的祖先狀態

第 718 行直接執行：

JavaScript
priorVerifiedReg = hReg;

沒有檢查先前是否已經接受過 Genesis，也沒有禁止版本從 v2、v3 等倒退回 v1。

接著，第 756–768 行會把這份歷史 Registry 中的 ACTIVE 公鑰加入 trustedKeys，並依其 HWM 設定可簽署的 Journal 索引範圍。

這使驗證歷史檔案的過程反而可能成為提升金鑰信任等級的入口。

對抗性反例：歷史檔案注入與未授權 Journal 簽署

依指定 Commit 控制流程推導，尚非原始專案動態重播

原本的可信狀態

Root R 已授權合法 Registry 與 Journal。外部 Witness 保存原有 Journal 的可信摘要。

攻擊者注入歷史檔案

新增 history/trust-registry.v99.json，內部卻宣告 registryVersion: 1，同時包含真實 Root R 與攻擊者公鑰 K。

驗證器錯誤建立信任

程式重新接受 Genesis，將 K 加入 trustedKeys，並以未驗證的歷史 HWM 擴張 K 的有效索引範圍。

未授權 Journal 簽署可能被接受

攻擊者以 K 簽署新增 Journal Entry，保留原有可信前綴與其摘要。簽章本身有效，但 K 從未獲得 Root 授權。

關鍵是：攻擊者不必破解 Ed25519，也不必修改既有可信 Journal 前綴。利用尚未受驗證的歷史 HWM，可以使新增條目的索引符合該金鑰的簽署視窗。

這是可由程式分支直接支持的信任來源驗證缺陷。完整端對端特權提升尚未動態證明，不能把靜態攻擊路徑冒充已完成的實測。

推翻此發現的條件：在相同 SHA 上證明上述偽造歷史檔案於公鑰加入 trustedKeys 前必定遭拒，且拒絕並非僅來自後續其他 API 的補救檢查。

R26-B02：未驗證的 Current Registry 可直接注入可信簽署者
P1 · OPEN · Merge Blocking

除了歷史 Registry，還有一條獨立的信任注入路徑。

實際程式碼：

L1525–1527：從磁碟解析 Registry，但此處沒有密碼學驗證。

L1614–1616：直接把 options.registry || onDiskRegForKeys 傳入信任金鑰解析器。

L668–681：把該 Registry 中狀態為 ACTIVE 的金鑰加入 trustedKeys，簽署上限設成 Infinity。

L1650–1665：使用這份信任集合驗證 Journal 簽章。

因此，即使歷史 Registry 驗證完全正確，未經驗證的當前 Registry 仍可以先行污染可信簽署者集合。

對抗性情境是：攻擊者能修改本機 Registry，加入自己的 ACTIVE 公鑰，保留原有可信 Journal 前綴，再用自己的私鑰簽署新的 Journal Entry。外部 Witness 保存的舊前綴摘要仍然可以完全相符。

這個問題不能單靠驗證歷史 Registry 解決。必須先建立當前 Registry 的可信性，才能使用其中的公鑰驗證 Journal。若兩者存在循環依賴，應以可信 Root、已驗證歷史快照與可信 Witness 解開，而非讓尚待驗證的 Registry 自行提供信任根據。

影響界線： 此處確認的是 Journal 驗證 API 的授權來源缺陷，不宣稱 saveTrustRegistry() 或完整持久化交易必定接受後續未授權變更。

推翻條件：證明任何未經 Root 授權的當前 Registry 公鑰，在所有對外授權入口中均不可能成為 Journal 的有效簽署者。

三、R25 三項阻擋點的覆審結果

原阻擋項

	

Round 26 結果

	

說明




R25-B01：Witness 路徑與 candidateHwm

	

PARTIALLY VERIFIED

	

正規路徑及摘要比對邏輯存在，但完整回滾重播證據不足




R25-B02：歷史 Registry 授權鏈

	

OPEN · P1

	

Genesis 注入、版本重置及當前 Registry 信任注入仍有缺口




R25-B03：Sub-test E

	

CLOSED

	

兩筆條目保留，重新簽章，單獨要求 HEAD_MISMATCH

R25-B01 的正面證據可以確認：getMonotonicWitness() 確實讀取本機及系統 Witness（第 3355–3356 行），candidateHwm 也參與 Journal 長度及摘要驗證。

但第 1555–1560 行對 candidateHwm.headDigest 採條件式納入，缺少或空白的摘要不會在此直接被拒絕。因此，尚不能把「任何提供的 candidateHwm 都必須進行完整摘要驗證」當成已證明的不變量。此外，新增的 R25 測試主要驗證候選索引下限，尚未直接覆蓋 getJournalRevokedKeyMap() 在保留外部 Witness、回滾本機多檔案後的冷啟動行為。

R25-B03 則具有實際修正證據。測試 L6525–6542 保留兩筆 Journal、重新簽署最後一筆、維持原有雜湊鏈，且斷言只接受包含 [JOURNAL_HEAD_MISMATCH] 的錯誤。原先允許單純截斷錯誤通過的問題已排除。

四、修復與重新驗證要求

1. 統一 Genesis 驗證。 讓歷史解析器與 validateTrustRegistry() 共用同一個嚴格 Root 驗證契約，拒絕 Genesis 出現任何額外 ACTIVE 金鑰。

2. 強制歷史版本單調性。 檢查檔名版本等於 JSON 內部版本，每條歷史鏈只能有一個 Genesis，後續版本必須逐一遞增，不能重新初始化。

3. 分離未驗證 Registry 與可信金鑰集合。 不可直接把 options.registry 或磁碟原始 Registry 的公鑰提升成 Journal 簽署權限。

4. 補齊三個負向測試。 包括偽造 Genesis 插入金鑰、歷史 v99 檔案宣告內部版本 v1，以及當前 Registry 注入未授權公鑰。每個測試都應保留合法 Journal 前綴，並驗證未授權簽署必然被拒。

5. 補強 Witness 冷啟動測試。 在獨立系統 Witness 未被回滾的情況下，還原整個本機狀態，從全新 Node.js 程序直接呼叫 getJournalRevokedKeyMap()，驗證確實 Fail-Closed。

不需要清空現有資料、重建 Repository 或重寫整套治理框架。修復應限制在信任解析、驗證前置條件及測試案例。

五、審查限制與最終門禁

本輪直接讀取 GitHub 指定 Commit 的原始碼、測試與 CI 日誌，並獨立計算 TCB 檔案雜湊；未修改 Repository、未提交 Review、未重新執行完整本地測試，也未宣稱完成端對端攻擊重播。

不確定清單

未查證：R26-B01、R26-B02 的原始專案動態攻擊重播，以及所有 8 個 Check Runs 的逐項清單。

使用預設：攻擊者能修改本機 Registry、History、Journal，但無法修改獨立系統 Witness。

推測：上述缺陷最終能否突破完整持久化與 Release Authorization；目前僅確立相關驗證 API 的信任邊界問題。

本次正式裁定維持 REJECTED，禁止以此輪審查結果授權合併。要推翻裁定，必須在新的固定 Commit 上，以代碼修正與具針對性的負向測試證明兩條未授權金鑰注入路徑均已封閉。

下一步（兩分鐘內）：將 R26-B01 與 R26-B02 登記為 PR #52 的 P1 Merge Blocking Findings，保留目前 Commit 作為未通過基準。
```
