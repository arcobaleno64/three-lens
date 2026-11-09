# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 30

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `b4ae489b1b435ccbab8098292ea741547c5d561f`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
跳至內容
首頁
空間
已排程
外掛程式
探索
網站
各
ChatGPT
新對話
已釘選
系統與網路檢查紀錄表
DIVE Sites POC 接手與驗證
ChatGPT與Codex協作流程
ChatGPT與Gemini協作流程
推進 CCC 研究與網站
外部審查結論
three-lens
獨立安全審查報告
安全審查裁定
Round 08 安全審查
Round 11 安全審查
安全審查裁定
顯示更多
triad-flow
評估 Rust 改寫 马会
G1 核驗與 G2 授權 恒一
回覆丁
治理驗收條件審查
審查結案回覆授權
顯示更多
星哨視界
SatenVision 星哨視界
教育部第二方稽核
專案
腦力激盪
沙龍
DIVE
consilium-fabri
最近項目
Round 30 安全審查
Round 29 安全審查
雲林職缺比較
安全審查拒絕合併
Round 27 安全審查
確認公司選項
填入測試資料
查核狀態頁設定
瀏覽器測試 blocked
安全架構審查回覆
Round 30 安全審查
分享
你說：
請以 ChatGPT Pro (High/Deep Reasoning Effort) 擔任極度嚴格、具對抗性之第三方首席密碼學與應用安全架構師（Independent Principal Cryptographic Systems & AppSec Auditor），針對 GitHub 儲存庫 arcobaleno64/three-lens 的 PR #52 (feat/m54-phase-2-governance) 執行第 30 輪（Round 30）獨立安全審查。

【審查原則：Default-Deny 假定未通過】
依據嚴格的 Default-Deny 準則，任何權威聲明（Candidate Findings、Patches、覆蓋率完整性與不變量合格宣告）未建立確切之密碼學與邏輯證明前均視為無效。CI 全綠僅為必要前提，非充分條件。審查核心為檢驗攻擊者能否透過多檔案回滾、歷史信任狀態替換、簽章降級、金鑰生命週期混淆、交易中斷或 TOCTOU 競爭重新取得未授予之特權。

【審查目標與基準】
- Repository: arcobaleno64/three-lens
- PR: #52 (feat/m54-phase-2-governance)
- PR Target: main
- PR State: OPEN, Mergeable: TRUE
- 審查指定 Head Commit SHA: b4ae489b1b435ccbab8098292ea741547c5d561f
- GitHub Actions CI 狀態: 100% GREEN (8/8 checks passed on Commit b4ae489b1b435ccbab8098292ea741547c5d561f)

【歷史阻擋項閉合狀態】
1. R27-B01（Genesis Root 錨點綁定）：Round 28 審查員確認閉合（CLOSED）。
2. R27-B02（當前 Registry 撤銷篩查）：Round 28 審查員確認當前版本修補成立。
3. R28-B01（歷史 Registry 撤銷狀態機）：Round 29 審查員確認逐級驗證框架已建立，但在基準 HWM=-1 邊界處受阻，延伸出 R29-B01。

【Round 29 阻擋項（R29-B01）完整修復說明與證據】

1. R29-B01 (P1 · 歷史 Registry HWM=-1 抑制 Root 簽署之 Journal 撤銷條目解析漏洞)：
   - 問題（Round 29 審查確定性阻擋項）：
     resolveJournalTrustedKeyWindows() 在 Genesis v1 及歷史 v2 的 HWM 為 -1（首筆 Journal 撤銷前之乾淨基線狀態）時，將 Root 的 maxActiveIndexPerKey 設為 -1。使得 advanceJournalRevocations() 在遇到即使是由主權 Root 親簽之 Journal entry 0 (KEY_REVOCATION) 時，因 entryIndex 0 > -1 而強制中斷掃描，導致 journalRevokedKeyIds 為空，遭撤銷委託金鑰 K 依然能授權 v3。
   - 修復（scripts/adapters/plugin-data-adapter.mjs）：
     (a) 主權 Root 撤銷永不截斷（Sovereign Root Authority Invariant）：
         在 advanceJournalRevocations() 中明確定義主權 Root 特權判準：
         const isRootSigner = entry.signedBy === rootId && signerPem === rootPem;
         if (!isRootSigner) {
           const maxIdx = maxActiveIndexPerKey.get(entry.signedBy);
           if (typeof maxIdx === 'number' && maxIdx !== Infinity && entry.entryIndex > maxIdx) break;
         }
         只要由受信 Root 錨點親簽之 Journal 條目，其有效性絕不受歷史 Registry 檔案之 past HWM=-1 所截斷。任何合法 Root KEY_REVOCATION 均在 Genesis 認證後立即無條件解析入 journalRevokedKeyIds，並即時以 entryIndex 上限截斷被撤銷金鑰在 maxActiveIndexPerKey 中的權限視窗。
     (b) 委託與輪換金鑰（Delegated Keys）維持嚴格生命週期約束：
         非 Root 之委託簽署者（isRootSigner === false）依然嚴格受 maxActiveIndexPerKey 限制，退役或輪換金鑰絕無法授權退役點之後的 Journal 條目或 HWM。
     (c) 當前 Registry 授權入口對等 Fail-Closed：
         Step 2 在認證 next-version candidate registry 時，若 proof.authorizedBy 存在於 journalRevokedKeyIds 或 priorVerifiedReg.revokedKeyIds，無條件拋出 [UNTRUSTED_CURRENT_REGISTRY] [REVOKED_SIGNER_AUTHORIZATION_REJECTED]，絕不進入 trustedKeys。

2. 針對性負向測試覆蓋（tests/test-plugin-data-adapter.mjs 3b & 3c）：
   - 負向測試 D (Scenario a · 審查員必檢要求)：
     歷史 v1 與 v2 之 HWM 均為基準 -1 (headIndex: -1)，Root 在 Journal entry 0 撤銷金鑰 K。攻擊者持 K 舊私鑰簽署當前 v3 Registry (引入公鑰 A)，且 Journal entry 1 由 A 簽署。
     斷言 getJournalRevokedKeyMap 必然拋出 [UNTRUSTED_CURRENT_REGISTRY] / [REVOKED_SIGNER_AUTHORIZATION_REJECTED] Fail-Closed 拒絕，公鑰 A 絕不進入 trustedKeys。
   - 負向測試 E (Scenario b · 審查員必檢要求)：
     歷史 v1 與 v2 之 HWM 均為基準 -1 (headIndex: -1)，攻擊者將 K 簽署之 v3 同時寫入 history/trust-registry.v3.json 與 supervisor-trust-registry.json。
     斷言 getJournalRevokedKeyMap 必然拋出 [UNTRUSTED_HISTORICAL_REGISTRY] / [REVOKED_SIGNER_AUTHORIZATION_REJECTED] Fail-Closed 拒絕。

3. 雙層 TCB 雜湊與雙路徑同步驗證：
   - scripts/adapters/plugin-data-adapter.mjs 與 skills/3lens/scripts/adapters/plugin-data-adapter.mjs 二進位完全一致 (fc /b 零差異)，SHA-256 為：
     cbeca100856c6147206fd1c1923707e74991075d2c7030a0fef4d927c8c51fa9
   - Layer 1 (skills/3lens/tool-integrity-manifest.json) SHA-256 為：
     c11415f99e450503e9228871915ffafaa8960440c59e061b0db34c296e74f088
   - Layer 2 (evals/evidence-matrix.json) 已同步。
   - 本地與 CI 驗證結果：
     * node tests/test-plugin-data-adapter.mjs: 105/105 PASS (覆蓋 Scenario a & b 雙重 HWM=-1 負向測試)
     * npm test (render-sarif.mjs --test): 121/121 PASS
     * node scripts/bundle-release-evidence.mjs --check: 29/29 檔案通過
     * npm run check:docs: PASS
     * GitHub Actions CI: 8/8 Check Runs 100% GREEN on Commit b4ae489b1b435ccbab8098292ea741547c5d561f

請審查員基於 Default-Deny 原則，直接檢驗 Commit b4ae489b1b435ccbab8098292ea741547c5d561f 之實際程式碼、測試與 CI 證據，確認 R29-B01 在 HWM=-1 基準邊界與歷史/當前 Registry 認證路徑上是否已確切閉合，並出具 Round 30 正式裁定（APPROVED 或 REJECTED）。
顯示較少
處理時間為 9m 46s
ChatGPT 說：
REJECTED · P1 Blocking

Round 30 正式裁定：拒絕合併 PR #52。

審查基準為 b4ae489b1b435ccbab8098292ea741547c5d561f，截至 2026 年 11 月 9 日。

R29-B01 原指定的 Root 簽署 Journal entry 0 情境已局部閉合，但整體 HWM=-1 撤銷驗證不變量尚未成立。 本輪發現新阻擋項 R30-B01：委託金鑰簽署的前置 Journal 紀錄，可能遮蔽後續 Root 撤銷，導致遭撤銷的 K 仍能在 Registry 預驗證階段授權攻擊者金鑰 A。

1. R30-B01：新發現的 P1 阻擋項

依照固定 SHA 的實際程式碼建立對抗性重播：

歷史 v1/v2 的有效 HWM 起始狀態為 -1，Root 已合法授權 K。

Journal entry 0 由當時合法的 K 簽署；entry 1 由 Root 簽署，撤銷 K。

advanceJournalRevocations() 因 K 的 maxActiveIndex=-1 在 entry 0 提前 break，未處理 entry 1。

K 簽署的惡意 v3 因撤銷集合不完整而通過該階段驗證，A 被導入 trustedKeys。

完整 Journal 讀取階段可能接受 A 簽署的 entry 2，包含未獲授權的 Root 撤銷紀錄。

原始碼證據：L661–717、L790–976。

這個反例已在獨立 Node.js 精簡控制流程模型中重現，並使用真實 Ed25519 簽章驗證。不過，尚未在完整原始 Adapter 上實際執行，因此不能宣稱所有高階載入、儲存或 WAL 路徑都已遭繞過。

2. 證據查核

查核項目

	

結果




PR Head SHA

	

完全符合




GitHub Check Runs

	

8/8 SUCCESS




Plugin Data Adapter 測試

	

105/105 PASS




render-sarif 測試

	

121/121 PASS




Release Evidence

	

29 檔通過




Adapter 雙路徑 SHA-256

	

獨立重算一致




R29-B01 原始 D/E 情境

	

局部閉合




R30-B01 委託前置紀錄反例

	

精簡模型重現，完整模組待驗證

CI 證據：GitHub Actions Run 42581284227。

3. 正式審查附件

Round 30 獨立安全審查報告（Markdown）

含證據、阻擋項、原始碼行號、閉合條件與不確定清單

R30-B01 對抗性重播程式（Node.js）

兩種 Registry 注入情境；獨立精簡模型，非原始模組測試
4. 推翻裁定的必要觀察

若固定 SHA 的完整原始 getJournalRevokedKeyMap() 能在上述合法簽章、連續 Journal 前綴的兩種情境中，於引入 A 之前必然拒絕 K 的 v3 授權，且拒絕不是由無關的無效測試資料造成，即可推翻或縮小 R30-B01。

不確定清單： 完整 Adapter 未獨立執行；高階 API 的實際影響範圍未建立；攻擊成立以前述候選歷史狀態可被替換為前提。

下一步：在 PR #52 的修復追蹤中標記 R30-B01 · P1 · BLOCKING，先保留未合併狀態。

round-30-independent-security-review.md
文件
delegated-prefix-repro.mjs
程式碼
ChatGPT 可能會出錯。工作區資料不會用於訓練模型。
最新回覆




推理強度
高
回覆完畢
```
