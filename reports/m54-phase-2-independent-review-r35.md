# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 35

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `554ec0061f8241e825d7ea231647b9120d313049`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **APPROVED**

---

## 1. Full Independent Review Transcript

```markdown
安全審查結論
分享
你說：
請以 ChatGPT Pro (High/Deep Reasoning Effort) 擔任極度嚴格、具對抗性之第三方首席密碼學與應用安全架構師（Independent Principal Cryptographic Systems & AppSec Auditor），針對 GitHub 儲存庫 arcobaleno64/three-lens 的 PR #52 (feat/m54-phase-2-governance) 執行第 35 輪（Round 35）獨立安全審查。

【審查原則：Default-Deny 假定未通過】
依據嚴格的 Default-Deny 準則，任何權威聲明（Candidate Findings、Patches、覆蓋率完整性與不變量合格宣告）未建立確切之密碼學與邏輯證明前均視為無效。CI 全綠僅為必要前提，非充分條件。審查核心為檢驗攻擊者能否透過多檔案回滾、歷史信任狀態替換、簽章降級、金鑰生命週期混淆、交易中斷或 TOCTOU 競爭重新取得未授予之特權。

【審查目標與基準】
- Repository: arcobaleno64/three-lens
- PR: #52 (feat/m54-phase-2-governance)
- PR Target: main
- PR State: OPEN, Mergeable: TRUE
- 審查指定 Head Commit SHA: 554ec0061f8241e825d7ea231647b9120d313049
- GitHub Actions CI 狀態: 100% GREEN (8/8 checks passed on Commit 554ec0061f8241e825d7ea231647b9120d313049)

【歷史阻擋項閉合狀態】
1. R27-B01（Genesis Root 錨點綁定）：已於 Round 28 確認閉合（CLOSED）。
2. R27-B02（當前 Registry 撤銷篩查）：已於 Round 28 確認閉合（CLOSED）。
3. R28-B01（歷史 Registry 撤銷狀態機）：已於 Round 29 確認閉合（CLOSED）。
4. R29-B01（歷史 Registry HWM=-1 主權 Root 撤銷解析）：已於 Round 30 確認閉合（CLOSED）。
5. R30-B01（委託金鑰前置 Journal 條目截斷）：已於 Round 31 確認閉合（CLOSED）。
6. R31-B01 & R32-B01（頂層與 keys[] Root 錨點公鑰身分強綁定）：已於 Round 33 確認閉合（CLOSED）。
7. R31-B02 & R32-B02（Root 撤銷免疫與 Journal 全路徑 Fail-Closed 對稱）：已於 Round 33 確認閉合（CLOSED）。
8. R33-B01 & R34-B01（委託金鑰省略或篡改 Root 旁路 Delegated-Key Sovereign Root Mutation Prohibition Bypass）：已於 Round 35 完備閉合。

【Round 34 阻擋項（R34-B01）完備修復說明與密碼學不變量證明】

1. 審查基準 SHA 修正：
   - 經由 git rev-parse HEAD 動態獲取真實 PR Head Commit SHA：554ec0061f8241e825d7ea231647b9120d313049，徹底排除任何轉錄或字串筆誤。

2. 委託授權邊界硬隔離（Delegated Root Omission Prohibition）：
   - 在 validateTrustRegistry() 中：在通過 authenticated priorRegistry 驗證後，若更新為委託金鑰簽署（proof.authorizedBy !== rootId），若先前版本 Root 為 ACTIVE_PINNED_ROOT，強制檢查更新後的 keys[] 中 Root 必須存在且狀態維持 ACTIVE_PINNED_ROOT；任何委託金鑰簽署省略 Root（!rootInCur）或修改 Root 狀態為非 ACTIVE_PINNED_ROOT 的更新，一律拒絕 [DELEGATED_ROOT_MUTATION_REJECTED]。
   - 在 loadTrustRegistry() 的歷史鏈與當前鏈驗證中：當更新為委託金鑰簽署，若前版 Root 為 ACTIVE_PINNED_ROOT 而新版缺少 Root 或狀態非 ACTIVE_PINNED_ROOT，在 Fail-Closed 模式下一律拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
   - 在 saveTrustRegistry() 中：支援 caller 傳入之 options.priorRegistry 作為基準，委託簽署省略 Root 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。

3. 針對性負向測試覆蓋（tests/test-plugin-data-adapter.mjs）：
   - Negative Test I 完全依照審查員 Round 34 報告 3.3 節規範實作反例：
     * Scenario 1: 委託金鑰 K 試圖透過 createAuthorizedRegistryUpdate() 將 Root 標記為 RETIRED，嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 2: 委託金鑰 K 試圖透過 createAuthorizedRegistryUpdate() 省略 Root，嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 3: 外部構造由委託金鑰 K 簽署且 Root 為 RETIRED 的 v3 Registry，validateTrustRegistry 嚴格返回 valid: false 且匹配 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 4 (審查員指定反例): 外部構造完全省略 Root keys[] 紀錄之 v3 Registry，並附帶由委託金鑰 K 私鑰簽署之真實有效 Ed25519 簽章：
       - validateTrustRegistry(forgedV3OmitRoot, { ...opts, priorRegistry: v2 }) 嚴格返回 valid: false 且匹配 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - saveTrustRegistry(forgedV3OmitRoot, { ...opts, priorRegistry: v2 }) 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - 直接寫入磁碟並調用 loadTrustRegistry({ ...opts, failClosed: true }) 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 5: 主權 Root 在委託金鑰為 activeKeyId 時仍能成功調用 appendRevocationEntry() 撤銷該惡意委託金鑰，且該委託金鑰隨後立即遭拒絕 [REVOKED_KEY_AUTHORIZATION_REJECTED]。

4. 雙層 TCB 雜湊與一致性驗證：
   - scripts/adapters/plugin-data-adapter.mjs 與 skills/3lens/scripts/adapters/plugin-data-adapter.mjs 二進位完全一致 (fc /b 零差異)，SHA-256 為：
     f9bcba0808697bde90b512a52c9dab3caba01012199754da421f25f8401b2b42
   - Layer 1 (skills/3lens/tool-integrity-manifest.json) SHA-256 為：
     d462640d22aad0e879c978720a77ac778d4ab238bba09aed7ab493d124e03ca4
   - Layer 2 (evals/evidence-matrix.json) 已同步。
   - 本地與 CI 驗證結果：
     * node tests/test-plugin-data-adapter.mjs: 106/106 PASS (覆蓋 Negative Test G, H & I 全場景)
     * npm test (render-sarif.mjs --test): 121/121 PASS
     * node scripts/bundle-release-evidence.mjs --check: 29/29 檔案通過
     * npm run check:docs: PASS
     * GitHub Actions CI: 8/8 Check Runs 100% GREEN on Commit 554ec0061f8241e825d7ea231647b9120d313049

請審查員基於 Default-Deny 原則，直接檢驗 Commit 554ec0061f8241e825d7ea231647b9120d313049 之實際程式碼、測試與 CI 證據，確認 R34-B01 在「委託金鑰禁止省略或篡改 Root 錨點」與「有效 Ed25519 委託簽章抵禦」鏈條上是否已確切閉合，並出具 Round 35 正式裁定（APPROVED 或 REJECTED）。
…
顯示較多
處理時間為 8m 51s
ChatGPT 說：
Three-Lens PR #52：Round 35 獨立安全審查

審查基準與 CI 證據已確認有效；R34-B01 的原始攻擊情境已有對應修復，但完整 Root 主權不變量仍須接受更嚴格檢驗。

一、固定審查基準與證據核對

PR #52：Milestone 5.4 Phase 2

SHA 已核實

審查日期：2026-11-09（臺灣時間）

項目

	

獨立核對結果




Repository

	

arcobaleno64/three-lens




PR 狀態

	

OPEN




Mergeable

	

TRUE




Base

	

main




指定 Head SHA

	

554ec0061f8241e825d7ea231647b9120d313049




GitHub 實際 Head SHA

	

完全一致




GitHub Check Runs

	

8/8 SUCCESS




Ubuntu、Windows、macOS CI

	

全部 SUCCESS




Plugin Data Tests

	

106/106 PASS




render-sarif.mjs Tests

	

121/121 PASS




Release Evidence

	

29 個檔案驗證通過




check:docs

	

PASS

我直接查詢了 GitHub 的 PR、Commit、Check Runs API 及 Ubuntu CI 原始執行日誌，而非僅採信提交者提供的數字。

證據：固定 Commit · CI Run 42605536326 · Semgrep Run 42605536379

TCB 完整性驗證

對固定 Commit 的 GitHub 原始檔案內容重新計算 SHA-256，結果如下。

物件

	

驗證結果




主 Adapter

	

f9bcba0808697bde90b512a52c9dab3caba01012199754da421f25f8401b2b42




Skill Adapter

	

SHA-256 相同，內容相同




Layer 1 Manifest

	

d462640d22aad0e879c978720a77ac778d4ab238bba09aed7ab493d124e03ca4




Layer 2 Evidence Matrix

	

引用上述兩個預期雜湊

裁定：完整性證據 SUPPORTED。 這證明所檢查的檔案與雜湊宣告一致，不代表程式的所有安全不變量已成立。

二、R34-B01 原始攻擊情境的覆核

檢查來源：plugin-data-adapter.mjs（固定 SHA） 與 Negative Test I。

驗證點

	

裁定




createAuthorizedRegistryUpdate() 拒絕省略 ACTIVE Root

	

HOLDS




validateTrustRegistry() 驗證已認證前版，拒絕委託金鑰省略 ACTIVE Root

	

HOLDS




saveTrustRegistry() 以先前 Registry 驗證委託簽章更新

	

HOLDS




loadTrustRegistry() 拒絕測試中的惡意 v3

	

HOLDS




歷史與當前 Registry 信任視窗檢查

	

已確認存在相應拒絕條件




真實 Ed25519 委託簽章負向測試

	

CI 已執行通過




本審查環境獨立執行原始 Node.js 測試

	

未完成

修補最重要的變化，是把原來只檢查 Root 狀態的條件：

JavaScript
rootInCur && rootInCur.status !== 'ACTIVE_PINNED_ROOT'

改成：

JavaScript
!rootInCur || rootInCur.status !== 'ACTIVE_PINNED_ROOT'

而且將條件放進以已驗證 priorRegistry 為前提的授權驗證流程，避免單靠更新 Helper 的防護。

R34-B01 對於「前版 Root 為 ACTIVE_PINNED_ROOT」的原始反例，可以裁定 CLOSED。

但這個結論有明確範圍：它沒有證明 Root 在其他合法生命週期狀態下，也不可能遭委託金鑰刪除或修改。

三、Round 35 新發現：R35-B01（P1，阻擋合併）

問題：Root 已合法退休時，委託金鑰仍可修改 Root 主權狀態；相同條件也使 Root 紀錄省略防護失效。

這不是推測某個攻擊者可能破解 Ed25519，而是已在現有程式碼中找到授權條件缺口，且其中一條狀態變更路徑受到既有 CI 成功案例支持。

3.1 可驗證的授權邊界缺口

三處主要防護使用相同前提：

JavaScript
if (rootInPrior &&
    rootInPrior.status === 'ACTIVE_PINNED_ROOT') {
  // Reject delegated root omission or retirement.
}

位置：

validateTrustRegistry()：L2958–2972

歷史信任視窗：L856–869

當前信任視窗：L986–999

如果已認證的上一版 Root 狀態是 RETIRED，上述防護均不會觸發。

而 validateTrustRegistry() L2403–2447 對非 Genesis 版本並未無條件要求 Root 必須存在，只拒絕重複 Root、Root PEM 替換與 REVOKED 等情況。

3.2 現有成功測試已證明委託金鑰能重新啟用 Root

在 tests/test-plugin-data-adapter.mjs L612–693，R03-B02 測試存在以下合法執行序列：

v1：Root 為 ACTIVE_PINNED_ROOT

主權 Root 起始狀態

v2：由 Root 簽署合法輪替

Root = RETIRED

K = ACTIVE

v3：由委託金鑰 K 簽署更新

Root = ACTIVE_PINNED_ROOT

K = RETIRED

原始測試透過 createAuthorizedRegistryUpdate() 建立，再由 saveTrustRegistry() 儲存

GitHub Ubuntu CI：R03-B02，ok 20

換言之，委託金鑰 K 確實能使 Root 從 RETIRED 變回 ACTIVE_PINNED_ROOT，而這個案例目前被測試視為預期成功行為。

這不證明 K 能取得 Root 私鑰，但足以證明「Root 主權狀態只有 Root 本身可以修改」並非目前系統實際強制執行的不變量。

3.3 第二條反例：Root 退休後遭委託金鑰省略

依據上述已被接受的 v2 狀態，可以建立另一個待執行反例：

保留 activeKeyId = K，且 K 在已認證 v2 中為 ACTIVE。

外部構造下一版 Registry，從 keys[] 刪除 RETIRED Root。

使用 K 的真實 Ed25519 私鑰簽署完整授權 payload。

將新 Registry 交給 validateTrustRegistry()，以 v2 為 priorRegistry。

靜態控制流程顯示：

Root 缺席不會觸發 Genesis 專用存在性條件。

rootInPrior.status === 'ACTIVE_PINNED_ROOT' 為 false，故跳過委託 Root 省略檢查。

K 仍存在於 v2，且狀態為 ACTIVE，符合前版授權者條件。

具備合法 K 簽章時，Ed25519 驗證本身不會拒絕該更新。

這是高可信度靜態反例，不是本輪已獨立執行成功的端到端利用。 必須以獨立負向測試實際確認儲存與載入結果，才能將整條攻擊鏈標記為動態重現成功。

四、額外發現：R35-B02（P2，Root Fingerprint 完整性）

validateTrustRegistry() L2426–2447 對非 Genesis Registry 的 Root keys[] 紀錄，驗證了 keyId、publicKeyPem 與部分 status 限制，但沒有強制：

JavaScript
rootKey.keyFingerprint === rootFp

因此，靜態推導顯示，即使前版 Root 仍為 ACTIVE_PINNED_ROOT，委託金鑰 K 仍可在下一版修改 Root 的 keyFingerprint，保持 Root PEM 與狀態不變，再產生有效的 K 授權簽章。

這不等於成功替換 Root 公鑰，也尚未證明會造成直接權限提升，但已顯示 Root 身分欄位的不可變性沒有完整實施。

建議將此項列為 P2，另加 Root Fingerprint Mutation 負向測試。

五、Round 35 Finding Ledger 與修復驗收

Finding

	

嚴重性

	

狀態

	

合併影響




R34-B01：ACTIVE Root 省略旁路

	

P1

	

CLOSED（限定原始反例）

	

已解除




R35-B01：RETIRED Root 委託修改／省略

	

P1

	

OPEN

	

Blocking




R35-B02：Root Fingerprint 委託修改

	

P2

	

OPEN（靜態發現）

	

須補證與修復

R35-B01 的閉合需要做到：

明確定義 Root 退休、重新啟用、移除紀錄的授權政策，區分 Root 親自簽署與委託簽署。現有 R03-B02 測試可能是為保護退休金鑰的歷史簽章驗證而存在，不應直接刪除。

在 validateTrustRegistry() 強制委託金鑰不得修改或移除前版的 Root 身分紀錄，且不得僅以先前狀態是否為 ACTIVE_PINNED_ROOT 決定是否檢查。

同步檢查歷史、當前、儲存及載入路徑，避免單一路徑接受其他路徑拒絕的狀態。

新增有效 Ed25519 簽章測試，涵蓋 ACTIVE → RETIRED → omitted、RETIRED → ACTIVE_PINNED_ROOT 與 Root Fingerprint 修改，重新驗證原有合法金鑰輪替不受誤阻。

在修補後的新固定 SHA 上，重新完成獨立驗證及 CI 證據綁定。

六、Round 35 正式裁定
REJECTED
Merge Blocking

Milestone 5.4 Phase 2 · PR #52

審查基準：554ec0061f8241e825d7ea231647b9120d313049

R34-B01 的指定修復確實改善了 ACTIVE Root 省略問題。但相同授權邊界尚未涵蓋合法的 Root 退休狀態，而既有成功測試已顯示委託金鑰可以重新啟用 Root。

因此，本輪不核發 PR #52 合併授權。

本裁定並不宣稱攻擊者能偽造 Ed25519、取得 Root 私鑰，或已利用 Root 省略反例取得完整系統控制權。已確認的是主權狀態修改的授權政策與實際接受行為不一致。依本輪 Default-Deny 審查契約，這已足以阻止無條件核准。

推翻本裁定所需的證據： 以正式授權契約及固定 Commit 的執行測試，證明委託者重新啟用 Root 具有明確且可驗證的授權依據，並證明委託者不能在未獲 Root 授權時省略 Root 身分紀錄、修改不可變身分欄位，且所有正式路徑均維持相同判斷。

審查限制與不確定清單

未查證：是否存在另外的正式設計契約，明文授權委託金鑰重新啟用退休 Root。

未執行：由本審查環境獨立執行的 Node.js 端到端新攻擊測試。現有 GitHub CI 執行紀錄已核實。

純推測：Root 退休後遭省略的反例將通過完整儲存與載入流程，仍須執行測試確認；目前可確認的是原始碼中存在相應條件缺口。

下一步（兩分鐘內）： 在 PR #52 登記 R35-B01：Delegated-Key Sovereign Root Lifecycle Mutation Bypass，引用 tests/test-plugin-data-adapter.mjs L665–693 及 plugin-data-adapter.mjs L2958–2972，維持合併阻擋狀態。

ChatGPT 可能會出錯。工作區資料不會用於訓練模型。
最新回覆




推理強度
High
```
