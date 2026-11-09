# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 28

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `32ae3b7f47ba91c6069e9187aae6645ef9de2cb6`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 28 獨立安全審查

正式裁定：PR #52 在指定 Commit 32ae3b7f47ba91c6069e9187aae6645ef9de2cb6 尚未滿足 Default-Deny Authority 放行條件。

R27-B01 的 Genesis Root 綁定缺口已取得閉合證據；R27-B02 的當前 Registry 撤銷篩查亦已修補，但同一安全不變量仍能透過歷史 Registry 認證路徑繞過。

本輪新增一項 P1 阻擋發現：R28-B01。

一、審查基準與證據

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Target

	

main




固定 Commit

	

32ae3b7f47ba91c6069e9187aae6645ef9de2cb6




PR 狀態

	

OPEN、Mergeable TRUE




Pull Request CI

	

SUCCESS




Semgrep

	

SUCCESS




執行模式

	

Cold-Start / Adversarial / Read-Only




審查日期

	

2026-11-09

已透過 GitHub 連線直接取得固定 SHA 的原始碼、測試程式與 GitHub Actions Job Logs。

獨立比對確認兩份 Adapter 的內容相同，Git Blob SHA 均為 3e1478f206f9c4845585cd2533eda05c588a7272。

獨立重新計算 SHA-256，結果如下：

Artifact

	

SHA-256 比對




兩份 plugin-data-adapter.mjs

	

36917ae47bffe49663b89073a8d2b60d9c19fcef78b6ace5b455aea9f7152ee4，一致




tool-integrity-manifest.json

	

b828d604d50b9a534387dbf0318d13f52d031dc26fcbfc178caa49c7b485e6b0，一致




evals/evidence-matrix.json

	

已確認包含對應宣告值

GitHub Actions 原始紀錄確認：

test-plugin-data-adapter.mjs：105 passed、0 failed。

render-sarif.mjs：121/121 passed。

Release evidence：29 files verified。

Documentation integrity gate：PASSED。

來源：Pull Request CI Run 42574381887、Semgrep Run 42574381902。

以上證明指定 Commit 的既有測試成功，不代表所有安全不變量均成立。

二、Round 27 阻擋項覆審

Finding

	

Round 28 裁定

	

證據




R27-B01：偽造 Genesis Root

	

CLOSED

	

預設 Root 不再為 null，歷史 Genesis 與當前 Genesis 均強制比對可信 Root




R27-B02：撤銷金鑰授權 Registry

	

NOT CLOSED

	

當前版本的檢查已修復，但歷史版本認證仍可繞過撤銷狀態




獨立 System Witness 測試

	

指定測試成立

	

外部目錄確實與 tempDir 分離，但不等同正式部署的獨立信任保證

R27-B01 的直接修補證據位於 L665–L666、L713–L729。

R27-B02 的新增撤銷集合與當前 Registry 篩查位於 L789–L868。

三、新增阻擋項 R28-B01
P1 · BLOCKING

歷史 Registry 認證早於 Journal 撤銷驗證，導致已撤銷金鑰仍可經由歷史版本引入新可信金鑰。

受影響函式：resolveJournalTrustedKeyWindows()

直接程式碼證據

歷史 Registry v2 → v3 的驗證只要求：

JavaScript
const signerInPrior = priorVerifiedReg.keys?.find(
  k => k.keyId === proof.authorizedBy &&
    ['ACTIVE_PINNED_ROOT', 'ACTIVE'].includes(k.status)
);

然後使用 signerInPrior.publicKeyPem 驗證 authorizationProof.signature。

此處沒有查詢已驗證 Journal 中的撤銷紀錄。

來源：plugin-data-adapter.mjs L730–L764。

新增的 journalRevokedKeyIds 在歷史 Registry 全部完成認證後才建立，位於 L789–L824。因此，歷史 v3 即使由已撤銷的 K 簽署，也可能先被納入 priorVerifiedReg。

更關鍵的是，當當前 Registry 與這份已接受的歷史 v3 具有相同的 non-HWM digest 時，程式會直接認證當前版本：

JavaScript
if (curDigest === histDigest) {
  currentRegAuthenticated = true;
}

來源：L830–L851。

這個分支沒有再檢查 v3 的授權者是否存在於 journalRevokedKeyIds。

隨後，新金鑰 A 可以取得：

JavaScript
trustedKeys.set(k.keyId, k.publicKeyPem);
maxActiveIndexPerKey.set(k.keyId, Infinity);

來源：L919–L936。

靜態攻擊反例

以下是依實際控制流程建立的攻擊假說，尚未在完整原始專案完成動態重播。

建立合法歷史 Genesis v1 與 Registry v2，其中委派金鑰 K 為 ACTIVE，且歷史 Journal HWM 與已簽署紀錄一致。

讓合法 Root 簽署 Journal entry #0，透過 KEY_REVOCATION 撤銷 K。

攻擊者持有 K 的舊私鑰，在 history/ 注入由 K 簽署的 v3，導入新金鑰 A，並將同一 v3 寫為當前 Registry。

使用 A 簽署 Journal entry #1，維持連續索引、正確 hash chain、有效 Ed25519 簽章及一致的既有 HWM 錨點，再呼叫 getJournalRevokedKeyMap()。

依目前控制流程，歷史 v3 會先因 K 的有效密碼學簽章被接受；雖然 Step 1.5 隨後辨識 K 已撤銷，但當前 v3 仍可透過歷史 digest 相符分支取得信任，使 A 獲得 Infinity 的簽署視窗。

getJournalRevokedKeyMap() 的路徑會比對 Witness 的 Journal HWM，卻沒有在授予這項歷史 Registry 信任時，額外以 Witness 的 Registry 身分承諾阻擋此候選版本。

相關來源：L1655–L1757。

這是具有直接程式碼證據的授權順序缺口。尚不能把它描述成已在完整系統動態證實的特權提升，也不能宣稱所有上層入口都會被繞過。

為什麼 Round 27 測試沒有發現？

目前的 Test D 只將攻擊者簽署的 v3 放在當前 Registry，歷史目錄則停留在 v2。

因此，程式走的是 currentRegistry.registryVersion === priorVerifiedReg.registryVersion + 1 分支，恰好會執行本輪新增的撤銷篩查。

測試並沒有把攻擊者 v3 同時放入 history/trust-registry.v3.json，所以沒有進入上述相同版本的 digest 比對捷徑。

來源：tests/test-plugin-data-adapter.mjs L6744–L6825。

必要修補條件

歷史 Registry 的每次版本提升，必須以已認證的前序 Registry 與可信 Journal 撤銷前綴共同驗證授權者，不能只依前版 ACTIVE 狀態與有效簽章決定。

此外，當前 Registry 與歷史版本的 digest 相符，只能證明兩者內容一致，不能取代歷史版本本身的授權有效性檢查。

驗收需要新增一組負向測試，覆蓋「K 已於 Journal #0 撤銷，卻授權歷史 v3 引入 A，且 A 簽署 Journal #1」的完整路徑，並確認 A 在加入 trustedKeys 之前被拒絕。

推翻 R28-B01 攻擊假說的觀察： 在固定 Commit 的原始 getJournalRevokedKeyMap() 執行上述具備一致有效錨點的完整樣本，若能證明存在本輪未涵蓋的必經驗證使其在授予 A 權限之前必然拒絕，則應撤銷或限縮此發現。

四、正式結案裁定

審查範圍

	

最終狀態




R27-B01 Root 身分綁定

	

CLOSED




R27-B02 當前 Registry 撤銷篩查

	

修補成立




R27-B02 全部 Registry 授權路徑

	

OPEN




R28-B01 歷史 Registry 撤銷後再授權

	

OPEN · P1




雙份 Adapter 與雜湊一致性

	

PASS




固定 Commit 既有 CI

	

PASS




新反例完整動態驗證

	

NOT EXECUTED




PR #52 合併裁定

	

REJECTED

本輪沒有修改 GitHub 程式碼、發表 Review 或合併 PR。

由於執行環境無法解析 github.com，無法完整 Clone 儲存庫後直接執行新增反例。此限制不影響已取得的固定版本原始碼及 GitHub Actions 證據，但降低了新攻擊路徑的動態確認程度。

不確定清單

未查證： R28-B01 尚無完整原始 Node.js 執行重現；8/8 Check Runs 的總數未獨立逐項核實，但已取得兩項 Workflow 及四個 Job 成功證據。

預設帶過： 攻擊者具有治理檔案寫入能力及已撤銷 K 的舊私鑰，但不持有內嵌 Root 私鑰。

純推測： R28-B01 能否進一步繞過 loadTrustRegistry()、isRevoked() 等所有上層防護並取得完整持久化特權，尚未建立證據。

下一步： 在 PR #52 登記 R28-B01 為 P1 Blocking，要求先補上「歷史 v3 由已撤銷 K 授權」的獨立負向測試，維持禁止合併。
```
