# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 36

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `b4e75275790e1b489c3b1ddf9a48efa934f4b02a`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED** (Blocking · R36-B01)

---

## 1. Full Independent Review Transcript

```markdown
安全審查拒絕判定
分享
你說：
請以 ChatGPT Pro (High/Deep Reasoning Effort) 擔任極度嚴格、具對抗性之第三方首席密碼學與應用安全架構師（Independent Principal Cryptographic Systems & AppSec Auditor），針對 GitHub 儲存庫 arcobaleno64/three-lens 的 PR #52 (feat/m54-phase-2-governance) 執行第 36 輪（Round 36）獨立安全審查。

【審查原則：Default-Deny 假定未通過】
依據嚴格的 Default-Deny 準則，任何權威聲明（Candidate Findings、Patches、覆蓋率完整性與不變量合格宣告）未建立確切之密碼學與邏輯證明前均視為無效。CI 全綠僅為必要前提，非充分條件。審查核心為檢驗攻擊者能否透過多檔案回滾、歷史信任狀態替換、簽章降級、金鑰生命週期混淆、交易中斷或 TOCTOU 競爭重新取得未授予之特權。

【審查目標與基準】
- Repository: arcobaleno64/three-lens
- PR: #52 (feat/m54-phase-2-governance)
- PR Target: main
- PR State: OPEN, Mergeable: TRUE
- 審查指定 Head Commit SHA: b4e75275790e1b489c3b1ddf9a48efa934f4b02a
- GitHub Actions CI 狀態: 100% GREEN (8/8 checks passed on Commit b4e75275790e1b489c3b1ddf9a48efa934f4b02a)

【歷史阻擋項閉合狀態】
1. R27-B01（Genesis Root 錨點綁定）：已於 Round 28 確認閉合（CLOSED）。
2. R27-B02（當前 Registry 撤銷篩查）：已於 Round 28 確認閉合（CLOSED）。
3. R28-B01（歷史 Registry 撤銷狀態機）：已於 Round 29 確認閉合（CLOSED）。
4. R29-B01（歷史 Registry HWM=-1 主權 Root 撤銷解析）：已於 Round 30 確認閉合（CLOSED）。
5. R30-B01（委託金鑰前置 Journal 條目截斷）：已於 Round 31 確認閉合（CLOSED）。
6. R31-B01 & R32-B01（頂層與 keys[] Root 錨點公鑰身分強綁定）：已於 Round 33 確認閉合（CLOSED）。
7. R31-B02 & R32-B02（Root 撤銷免疫與 Journal 全路徑 Fail-Closed 對稱）：已於 Round 33 確認閉合（CLOSED）。
8. R33-B01 & R34-B01（ACTIVE Root 省略與篡改旁路）：已於 Round 35 確認閉合（CLOSED）。
9. R35-B01（RETIRED Root 委託修改與省略旁路）：已於 Round 36 完備閉合。
10. R35-B02（Root Fingerprint 完整性與不可變性）：已於 Round 36 完備閉合。

【Round 35 阻擋項（R35-B01 & R35-B02）完備修復說明與密碼學不變量證明】

1. 審查基準 SHA 鎖定：
   - 經由 git rev-parse HEAD 動態獲取真實 PR Head Commit SHA：b4e75275790e1b489c3b1ddf9a48efa934f4b02a。

2. R35-B01 完備閉合：主權 Root 生命週期與存在性代數固定（Sovereign Root Lifecycle Pinning）：
   - 根因分析：先前的防護限定於 if (rootInPrior && rootInPrior.status === 'ACTIVE_PINNED_ROOT')，導致當上一版 Root 處於 RETIRED 時，委託金鑰（proof.authorizedBy !== rootId）可在後續更新中省略 Root 或將 Root 狀態改回 ACTIVE_PINNED_ROOT。
   - 修復不變量（全路徑同構對齊）：
     * 在 validateTrustRegistry()（L2958–2972）：無論先前 Root 為何種狀態（ACTIVE_PINNED_ROOT 或 RETIRED），委託金鑰授權更新中 Root 必須存在於 registry.keys[]，且 Root 狀態必須與先前版本完全一致（rootInCur.status === rootInPrior.status）；任何委託更新省略 Root 或試圖改變 Root 狀態（如將 RETIRED 改回 ACTIVE_PINNED_ROOT，或將 ACTIVE 改為 RETIRED），嚴格拒絕並返回 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * 在 loadTrustRegistry() 歷史鏈（L856–868）與當前鏈（L986–998）：委託金鑰授權更新若省略 Root 或 Root 狀態與先前版本不一致，Fail-Closed 模式下一律拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * 在 createAuthorizedRegistryUpdate()（L3030–3046）：若 signerKeyId !== effectiveRootId，Root 必須存在於 updates.keys[] 且狀態必須嚴格等於 rootInCur.status，違者嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * 歷史測試 R03-B02（L667–685）對齊：更新為由委託金鑰輪替至新委託金鑰 operator2Auth，維持 Root 歷史 RETIRED 狀態不可變，確實驗收退休金鑰歷史簽章有效性而不違背主權固定原則。

3. R35-B02 完備閉合：Root 公鑰指紋不可變性（Root Key Fingerprint Invariance）：
   - 在 validateTrustRegistry()（L2426–2436）：對非 Genesis 及 Genesis Registry 中 keys[] 內的 Root 紀錄，強制檢驗 rootKey.keyFingerprint === rootFp（與 publicKeyPem === rootPem 一致）；指紋不符或被竄改者，嚴格返回 [ROOT_KEY_SUBSTITUTION_REJECTED]。
   - 在 loadTrustRegistry() 歷史鏈（L808）與當前鏈（L965）：同步強化對 Root 紀錄之指紋校驗，任何竄改指紋之行為一律視為替換拋出 [ROOT_KEY_SUBSTITUTION_REJECTED]。
   - 在 createAuthorizedRegistryUpdate()（L3040）：委託簽署更新若試圖修改 Root 指紋，嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。

4. 針對性負向測試覆蓋（tests/test-plugin-data-adapter.mjs）：
   - Negative Test I 擴充 Scenario 6、7、8（均包含由真實 Ed25519 委託私鑰簽署之授權證明）：
     * Scenario 6 (R35-B01): 委託金鑰 K 試圖省略已合法退休（RETIRED）的 Root：
       - createAuthorizedRegistryUpdate 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - 帶真實 K Ed25519 簽章的 forged v3 遭 validateTrustRegistry 拒絕（[DELEGATED_ROOT_MUTATION_REJECTED]）。
       - saveTrustRegistry 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - loadTrustRegistry(failClosed) 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 7 (R35-B01): 委託金鑰 K 試圖將已退休（RETIRED）的 Root 重新啟用為 ACTIVE_PINNED_ROOT：
       - createAuthorizedRegistryUpdate 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - 帶真實 K Ed25519 簽章的 forged v3 遭 validateTrustRegistry 拒絕（[DELEGATED_ROOT_MUTATION_REJECTED]）。
       - saveTrustRegistry 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - loadTrustRegistry(failClosed) 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
     * Scenario 8 (R35-B02): 委託金鑰 K 試圖在保持 Root PEM 與狀態不變的情況下篡改 Root keyFingerprint：
       - createAuthorizedRegistryUpdate 嚴格拋出 [DELEGATED_ROOT_MUTATION_REJECTED]。
       - 帶真實 K Ed25519 簽章的 forged v3 遭 validateTrustRegistry 拒絕（[ROOT_KEY_SUBSTITUTION_REJECTED]）。
       - saveTrustRegistry 嚴格拋出 [ROOT_KEY_SUBSTITUTION_REJECTED]。
       - loadTrustRegistry(failClosed) 嚴格拋出 [ROOT_KEY_SUBSTITUTION_REJECTED]。

5. 雙層 TCB 雜湊與一致性驗證：
   - scripts/adapters/plugin-data-adapter.mjs 與 skills/3lens/scripts/adapters/plugin-data-adapter.mjs 二進位完全一致 (fc /b 零差異)，SHA-256 為：
     27a3f6dd7a2744d73b585db25167824281a143feeb93f373b52f43fb0b269a22
   - Layer 1 (skills/3lens/tool-integrity-manifest.json) SHA-256 為：
     e091162fb30453bc30cc7359722ac1d5be69197f85bb1aaafd455fd68b386e47
     manifestDigest 為：
     391ea571f652c1388131c955a85b4b2945b3a1b182e980b8d034a6bf1877acb8
   - Layer 2 (evals/evidence-matrix.json) 已同步。
   - 本地與 CI 驗證結果：
     * node tests/test-plugin-data-adapter.mjs: 106/106 PASS (包含 Negative Test I Scenario 1–8 全覆蓋)
     * npm test (render-sarif.mjs --test): 121/121 PASS
     * node scripts/bundle-release-evidence.mjs --check: 29/29 檔案通過
     * npm run check:docs: PASS
     * GitHub Actions CI: 8/8 Check Runs 100% GREEN on Commit b4e75275790e1b489c3b1ddf9a48efa934f4b02a

請審查員基於 Default-Deny 原則，直接檢驗 Commit b4e75275790e1b489c3b1ddf9a48efa934f4b02a 之實際程式碼、測試與 CI 證據，確認 R35-B01 與 R35-B02 在「委託金鑰禁止修改或省略任何生命週期狀態之主權 Root」與「Root 指紋不可變性」鏈條上是否已確切閉合，並出具 Round 36 正式裁定（APPROVED 或 REJECTED）。
…
顯示較多
處理時間為 7m 23s
ChatGPT 說：
REJECTED · BLOCKING

Round 36 正式裁定：REJECTED。PR #52 不得合併至 main。

R35-B01 與 R35-B02 的指定負向情境已有實際修復證據，但本輪發現新的 Root 存在性狀態轉移缺口：當合法的前一版 Registry 已不含 Root 紀錄時，委託金鑰可能重新加入 Root，並自行指定其生命週期狀態。

此缺口使「委託金鑰無法變更主權 Root 狀態」的不變量尚未完整成立。

1. 審查基準與證據

項目

	

獨立核驗結果




Repository

	

arcobaleno64/three-lens




PR

	

#52




固定 SHA

	

b4e75275790e1b489c3b1ddf9a48efa934f4b02a




PR 狀態

	

OPEN、Mergeable




GitHub Check Runs

	

8/8 SUCCESS




Plugin Data 測試

	

106/106 PASS




SARIF 測試

	

121/121 PASS




Release evidence

	

29 檔 PASS




TCB 雙副本

	

Git Blob SHA 完全一致

已讀取指定 SHA 的實際原始碼、測試與 GitHub Actions 工作日誌。三個作業系統的 Plugin Data 測試均為 106 PASS、0 FAIL。

GitHub Commit · CI 證據

2. 歷史阻擋項覆核

Finding

	

Round 36 判定

	

依據




R35-B01：RETIRED Root 遭省略

	

指定情境 CLOSED

	

委託更新檢查前版 Root 存在與狀態




R35-B01：RETIRED Root 遭重新啟用

	

指定情境 CLOSED

	

rootInCur.status !== rootInPrior.status 拒絕




R35-B02：Root 指紋篡改

	

CLOSED（指定範圍）

	

keyFingerprint !== rootFp 拒絕




完整主權 Root 生命週期固定

	

NOT CLOSED

	

發現 R36-B01

原有 Scenario 6、7、8 使用真正的 Ed25519 簽章，並分別驗證 createAuthorizedRegistryUpdate()、validateTrustRegistry()、saveTrustRegistry() 與 Fail-Closed 載入路徑。這些測試不是假陽性。

但它們共同假設前一版 Registry 仍包含 Root，因此無法覆蓋本輪新發現。

3. 新增阻擋項 R36-B01

Finding：Delegated Sovereign Root Reintroduction Bypass

HIGH
BLOCKING
OPEN

受影響檔案：scripts/adapters/plugin-data-adapter.mjs，以及相同內容的 skills/3lens/scripts/adapters/plugin-data-adapter.mjs。

根因涉及三個條件：

validateTrustRegistry() L2414–2442 僅要求 Genesis v1 必須包含唯一 Root；非 Genesis 版本允許 rootKeyMatches.length === 0。

createAuthorizedRegistryUpdate() L3035–3050 僅在 rootInCur 存在時比較 Root 狀態及身分。

validateTrustRegistry() L2958–2972，以及歷史、當前載入路徑，均以 if (rootInPrior) 作為保護前提。

因此出現以下未受完整限制的狀態轉移：

依實際條件分支推導的攻擊路徑；尚未以原始模組執行端對端 PoC。

這不是簽章偽造問題。委託金鑰 K 可使用自己的合法 Ed25519 私鑰簽署新增 Root 的 v3 Registry，而現有跨版本檢查未限制「Root 原本不存在，現在重新出現」的情形。

若後續驗證也接受 v3，便可能讓原本已不在 Registry 授權鏈中的 Root 私鑰重新取得 Registry 更新能力。

程式碼證據：Root 存在性檢查 · 委託更新檢查

證據等級：靜態程式邏輯支持、高信心；端對端可利用性尚待動態重現。

可推翻此 Finding 的觀察是：對指定 SHA 使用有效 Root 與 K 私鑰執行完整 v1→v2→v3 測試時，某個已存在且不可繞過的檢查會明確拒絕 v2 的 Root 移除，或 v3 的 Root 重新加入。目前檢視的程式碼尚未找到這項防護。

4. 修復與重新驗收條件

明確定義非 Genesis Registry 是否一律必須保留唯一主權 Root 紀錄。建議固定為必須存在，除非另有 Root 專屬、不可逆且經簽章的移除協定。

在 validateTrustRegistry()、歷史與當前 loadTrustRegistry()、createAuthorizedRegistryUpdate() 中，拒絕委託金鑰執行 Root 缺席至重新出現的轉移。

新增真實 Ed25519 負向測試：Root 簽署 v2 移除 Root 並啟用 K，接著 K 簽署 v3 重新加入 Root，必須在政策指定的檢查點 Fail-Closed。同步檢查 save、load 與歷史鏈。

修復後重新驗證雙副本雜湊、TCB Manifest、Evidence Matrix，以及跨平台 CI。

5. 最終安全裁定

項目

	

結果




R35-B01 指定攻擊修復

	

通過




R35-B02 指紋不可變性

	

通過




Sovereign Root 全域生命週期不變量

	

未通過




新增阻擋項

	

R36-B01




Round 36

	

REJECTED




Merge Authorization

	

DENIED

本輪沒有修改儲存庫、推送 Commit、執行合併，也沒有在獨立 Node.js 環境重跑原始測試。CI 結果來自直接核對 GitHub 工作日誌，不能冒充獨立動態重現。

不確定清單：

未查證：R36-B01 的端對端動態 PoC 結果。

預設：委託金鑰不得自行恢復曾經缺席的主權 Root。

推測：重新加入 Root 後，舊 Root 私鑰可重新執行其專屬 Registry 授權操作，尚須完整流程驗證。

**下一步：**先在 tests/test-plugin-data-adapter.mjs 新增「Root 合法移除後，由委託金鑰重新加入」的負向測試，保留現有程式不修改，確認是否能重現 R36-B01。

ChatGPT 可能會出錯。工作區資料不會用於訓練模型。
最新回覆




推理強度
高
```
