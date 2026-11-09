# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 37

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `6cb7f3e4bf323415c97cea7868ac10fda6b13492`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **APPROVED**

---

## 1. Full Independent Review Transcript

```markdown
Round 37 安全審查
分享
你說：
請以 ChatGPT Pro (High/Deep Reasoning Effort) 擔任極度嚴格、具對抗性之第三方首席密碼學與應用安全架構師（Independent Principal Cryptographic Systems & AppSec Auditor），針對 GitHub 儲存庫 arcobaleno64/three-lens 的 PR #52 (feat/m54-phase-2-governance) 執行第 37 輪（Round 37）獨立安全審查。

【審查原則：Default-Deny 假定未通過】
依據嚴格的 Default-Deny 準則，任何權威聲明（Candidate Findings、Patches、覆蓋率完整性與不變量合格宣告）未建立確切之密碼學與邏輯證明前均視為無效。CI 全綠僅為必要前提，非充分條件。審查核心為檢驗攻擊者能否透過多檔案回滾、歷史信任狀態替換、簽章降級、金鑰生命週期混淆、交易中斷或 TOCTOU 競爭重新取得未授予之特權。

【審查目標與基準】
- Repository: arcobaleno64/three-lens
- PR: #52 (feat/m54-phase-2-governance)
- PR Target: main
- PR State: OPEN, Mergeable: TRUE
- 審查指定 Head Commit SHA: 6cb7f3e4bf323415c97cea7868ac10fda6b13492
- GitHub Actions CI 狀態: 100% GREEN (8/8 checks passed on Commit 6cb7f3e4bf323415c97cea7868ac10fda6b13492)

【歷史阻擋項閉合狀態】
1. R27-B01（Genesis Root 錨點綁定）：已於 Round 28 確認閉合（CLOSED）。
2. R27-B02（當前 Registry 撤銷篩查）：已於 Round 28 確認閉合（CLOSED）。
3. R28-B01（歷史 Registry 撤銷狀態機）：已於 Round 29 確認閉合（CLOSED）。
4. R29-B01（歷史 Registry HWM=-1 主權 Root 撤銷解析）：已於 Round 30 確認閉合（CLOSED）。
5. R30-B01（委託金鑰前置 Journal 條目截斷）：已於 Round 31 確認閉合（CLOSED）。
6. R31-B01 & R32-B01（頂層與 keys[] Root 錨點公鑰身分強綁定）：已於 Round 33 確認閉合（CLOSED）。
7. R31-B02 & R32-B02（Root 撤銷免疫與 Journal 全路徑 Fail-Closed 對稱）：已於 Round 33 確認閉合（CLOSED）。
8. R33-B01 & R34-B01（ACTIVE Root 省略與篡改旁路）：已於 Round 35 確認閉合（CLOSED）。
9. R35-B01（RETIRED Root 委託修改與省略旁路）：已於 Round 36 確認閉合（CLOSED）。
10. R35-B02（Root Fingerprint 完整性與不可變性）：已於 Round 36 確認閉合（CLOSED）。
11. R36-B01（Delegated Sovereign Root Reintroduction Bypass）：已於 Round 37 完備閉合。

【Round 36 阻擋項（R36-B01）完備修復說明與密碼學不變量證明】

1. 審查基準 SHA 鎖定：
   - 經由 git rev-parse HEAD 動態獲取真實 PR Head Commit SHA：6cb7f3e4bf323415c97cea7868ac10fda6b13492。

2. R36-B01 完備閉合：禁止委託金鑰重新引入主權 Root（Prohibit Delegated Sovereign Root Reintroduction）：
   - 根因分析：在 Round 36 中發現，先前的防護限定於 if (rootInPrior) 檢查。當合法的前一版 Registry（如先前由 Root 本身簽署之 v2 退休/移除自身）已無 Root 紀錄時（!rootInPrior），委託金鑰 K（proof.authorizedBy !== rootId）可在後續更新中重新將 Root 加入 keys[]，並自行指定其生命週期狀態（如宣告為 ACTIVE_PINNED_ROOT）。
   - 修復不變量（全路徑同構對齊）：
     * 在 validateTrustRegistry()（L2958–2980）：委託金鑰授權更新（proof.authorizedBy !== rootId）若前版缺 Root（!rootInPrior），當前更新若包含 Root（rootInCur），一律嚴格拒絕並返回 [DELEGATED_ROOT_MUTATION_REJECTED] [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。
     * 在 loadTrustRegistry() 歷史鏈（L856–878）與當前鏈（L994–1018）：委託金鑰授權更新若試圖重新引入不存在於前版之 Root，Fail-Closed 模式下一律拋出 [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。
     * 在 createAuthorizedRegistryUpdate()（L3056–3085）：委託簽署者在當前版本無 Root（!rootInCur）時，若 updates.keys 包含 Root，立即拋出 [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。

3. 針對性負向測試覆蓋（tests/test-plugin-data-adapter.mjs）：
   - Negative Test I 擴充 Scenario 9 (R36-B01)（包含由真實 Ed25519 委託私鑰簽署之授權證明）：
     * Root 簽署合法 v2 移除 Root 並啟用委託金鑰 K；委託金鑰 K 試圖在 v3 重新將 Root 加回 keys[] 並宣告為 ACTIVE_PINNED_ROOT：
       - createAuthorizedRegistryUpdate 嚴格拋出 [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。
       - 帶真實 K Ed25519 簽章的 forged v3 遭 validateTrustRegistry 拒絕（[DELEGATED_ROOT_MUTATION_REJECTED] [DELEGATED_ROOT_REINTRODUCTION_REJECTED]）。
       - saveTrustRegistry 嚴格拋出 [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。
       - loadTrustRegistry(failClosed) 嚴格拋出 [DELEGATED_ROOT_REINTRODUCTION_REJECTED]。

4. 雙層 TCB 雜湊與一致性驗證：
   - scripts/adapters/plugin-data-adapter.mjs 與 skills/3lens/scripts/adapters/plugin-data-adapter.mjs 二進位完全一致 (fc /b 零差異)，SHA-256 為：
     70d1ce8a3380ecab4af86c5252a1d71e4f706078198c73a46cd286f37709e65c
   - Layer 1 (skills/3lens/tool-integrity-manifest.json) SHA-256 為：
     f1c0dcf1c1b6332951d9486e4344dcc6f97571dd63e7a9b2d94b6d8a6f792734
     manifestDigest 為：
     380f03e8893077fbfbf88f12bfecf855691180a4037e4ecd819cc269dbba9f1f
   - Layer 2 (evals/evidence-matrix.json) 已同步。
   - 本地與 CI 驗證結果：
     * node tests/test-plugin-data-adapter.mjs: 106/106 PASS (包含 Negative Test I Scenario 1–9 全覆蓋)
     * npm test (render-sarif.mjs --test): 121/121 PASS
     * node scripts/bundle-release-evidence.mjs --check: 29/29 檔案通過
     * npm run check:docs: PASS
     * GitHub Actions CI: 8/8 Check Runs 100% GREEN on Commit 6cb7f3e4bf323415c97cea7868ac10fda6b13492

請審查員基於 Default-Deny 原則，直接檢驗 Commit 6cb7f3e4bf323415c97cea7868ac10fda6b13492 之實際程式碼、測試與 CI 證據，確認 R36-B01 在「委託金鑰禁止重新引入主權 Root」鏈條上是否已確切閉合，並出具 Round 37 正式裁定（APPROVED 或 REJECTED）。
…
顯示較多
處理時間為 7m 44s
ChatGPT 說：
Three-Lens PR #52：Round 37 獨立安全審查

審查日期：2026-11-09｜Assurance Profile｜Cold-Start / Read-Only / Default-Deny

一、已驗證的審查基準

已透過 GitHub 連線直接讀取指定 Commit 的原始程式碼、負向測試與 GitHub Actions 執行紀錄。

審查項目

	

獨立核對結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Target

	

main




PR 狀態

	

OPEN、Mergeable




Head SHA

	

6cb7f3e4bf323415c97cea7868ac10fda6b13492，完全符合




CI

	

Pull Request CI、Semgrep 工作流程成功

GitHub Actions 原始 Job 紀錄進一步確認：

test-plugin-data-adapter.mjs：106/106 PASS。

render-sarif.mjs：121/121 PASS。

Release Evidence Check：29 個必要檔案驗證通過。

Windows、macOS、Ubuntu 三個 CI Job 全部成功。

對應證據為 Pull Request CI Run #42614486744 與 Semgrep Run #42614486591。

上述是直接核實的 CI 紀錄，不是單純引用開發團隊的陳述。不過，CI 成功只證明現有測試通過，不自動證明安全不變量完整成立。

二、Round 37 正式裁定
APPROVED

R36-B01：CLOSED

裁定範圍： PR #52 指定 Commit 中，R36-B01 所涉及的「委託金鑰禁止重新引入主權 Root」安全不變量，已具備足以支持閉合的程式碼、密碼學簽章驗證及負向測試證據。

本輪未在這項修復鏈中確認新的可利用繞過路徑。此 APPROVED 僅對固定 SHA 的已審查範圍有效，不等於宣稱整個 PR 所有安全性質已獲形式化證明。

三、核心不變量驗證

令：

𝐾
K：合法委託金鑰，且 
𝐾
≠
𝑅
𝑜
𝑜
𝑡
K

=Root。

𝑃
P：經驗證的前一版 Registry。

𝐶
C：候選 Registry。

𝑅
(
𝑋
)
R(X)：Registry 
𝑋
X 的 keys[] 是否包含主權 Root。

本輪要求的不變量為：

𝐾
≠
𝑅
𝑜
𝑜
𝑡
 
∧
 
¬
𝑅
(
𝑃
)
 
∧
 
𝑅
(
𝐶
)
⇒
𝑅
𝐸
𝐽
𝐸
𝐶
𝑇
K

=Root ∧ ¬R(P) ∧ R(C)⇒REJECT

實際程式碼符合此規則，並保留既有 Root 狀態不得由委託金鑰變更的檢查。

前版 Root

	

候選 Root

	

委託更新結果




存在

	

不存在

	

REJECT




存在

	

存在但狀態改變

	

REJECT




不存在

	

重新加入

	

REJECT




不存在

	

仍不存在

	

不因本規則拒絕，仍須通過其他驗證

這是 Root 存在性與狀態不變量的分支分析，並非對所有系統行為的形式化證明。

實際程式碼檢查

防線

	

來源位置

	

裁定




validateTrustRegistry()

	

L2973–2998

	

HOLDS




歷史 Registry 信任鏈

	

L856–878

	

HOLDS




當前 Registry 信任鏈

	

L994–1018

	

HOLDS




createAuthorizedRegistryUpdate()

	

L3056–3085

	

HOLDS




saveTrustRegistry()

	

L4689

	

HOLDS，呼叫正式驗證器

此外，validateTrustRegistry() 會對前版 Registry 進行遞迴驗證，而非直接信任呼叫者提交的前版物件。這是本輪閉合所需的重要前提。

負向測試品質

Scenario 9 原始測試 包含：

Root 合法簽署 v2，移除自身並保留委託金鑰 K。

K 嘗試透過更新 API 將 Root 加回 v3。

K 使用真實 Ed25519 私鑰簽署偽造 v3。

驗證器與儲存路徑拒絕偽造 v3。

將偽造 Registry 寫入磁碟，確認 Fail-Closed 載入拒絕。

測試直接覆蓋原先 R36-B01 的攻擊先決條件。簽章有效但授權不合法的情況受到拒絕，這比單純驗證錯誤簽章更有意義。

四、雙層 TCB 完整性核驗

本輪直接取得兩份 Adapter 原始碼，獨立計算 SHA-256，並比較 GitHub Blob SHA。

項目

	

核驗結果




主要 Adapter SHA-256

	

70d1ce8a3380ecab4af86c5252a1d71e4f706078198c73a46cd286f37709e65c




Skills Adapter SHA-256

	

完全相同




Git Blob SHA

	

兩份均為 2e69a4b76c138ab579aa92cd8eb540377f022d5d




Layer 1 Manifest SHA-256

	

f1c0dcf1c1b6332951d9486e4344dcc6f97571dd63e7a9b2d94b6d8a6f792734




Layer 2 Evidence Matrix

	

兩項對應 Hash 均吻合

兩份 TCB 程式內容與相應完整性紀錄一致。

但 manifestDigest 的產生演算法未在本輪獨立重新執行，因此只確認 Manifest 記載的值，沒有將它列為獨立驗證成功的結論。

五、Finding Ledger

Finding

	

嚴重性

	

狀態




R36-B01：Delegated Sovereign Root Reintroduction Bypass

	

HIGH

	

CLOSED




Round 37 新增且已確認之阻擋項

	

無

	

無 OPEN Finding

歷史 R27 至 R35 的 CLOSED 狀態，本輪未全面重新執行所有攻擊案例，因此保留既有結案紀錄，但不將它們視為本輪重新建立的證明。

六、審查限制與推翻條件

本輪使用 GitHub 原始碼、CI Job Logs 與獨立 Hash 計算。因執行環境無法透過網路 Clone 儲存庫，因此沒有在本地重新執行 Node.js 測試，也沒有進行新的故障注入或 TOCTOU 競爭實驗。

足以推翻 APPROVED 的觀察： 在相同 SHA、未偽造 Root 私鑰的情況下，能讓合法 K 簽署的 Root 重新引入 Registry，通過 validateTrustRegistry()、持久化載入或歷史信任鏈驗證，並取得本不應授予的權威。

不確定清單：

未查證：8/8 個 Check Run 的逐項清單、manifestDigest 獨立重算。

預設：採用原始碼中的固定 Root 錨點及預設 Fail-Closed 安全邊界。

推測：無新增且具確切證據的漏洞；不代表所有未測攻擊類別均不存在。

Round 37 最終決議：APPROVED，R36-B01 CLOSED。

本裁定未在 GitHub 提交 Review、修改程式或執行 Merge。

下一步：將本輪裁定記入 reports/m54-phase-2-independent-review-r37.md，固定標示審查 SHA 與上述驗證限制。

ChatGPT 可能會出錯。工作區資料不會用於訓練模型。
最新回覆




推理強度
高
```
