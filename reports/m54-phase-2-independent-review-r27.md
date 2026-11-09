# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 27

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `c628b4381bdde2f24b145b0da60fb8a2b8ac9a6a`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 27 獨立安全審查
REJECTED · 拒絕合併

正式裁定：PR #52 在指定 Commit c628b4381bdde2f24b145b0da60fb8a2b8ac9a6a 尚不符合 Default-Deny Authority 的放行條件。

本輪已直接讀取 GitHub 上的固定版本程式碼、Round 26 修補測試及 GitHub Actions 執行紀錄。靜態控制流程審查發現，resolveJournalTrustedKeyWindows() 仍存在信任錨點驗證與金鑰撤銷生命週期的缺口。

正式審查資訊

2026-11-09 · Round 27

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




目標分支

	

main




審查 Commit

	

c628b4381bdde2f24b145b0da60fb8a2b8ac9a6a




PR 狀態

	

OPEN、Mergeable TRUE




GitHub Actions

	

Pull Request CI、Semgrep 成功




執行模式

	

Cold-Start / Adversarial / Read-Only




放行裁定

	

REJECTED

此裁定以固定 SHA 為範圍，不因後續分支提交而自動改變。

一、Round 26 修補覆審

修補項目

	

Round 27 結果




Genesis 僅允許單一 Root 金鑰

	

部分成立，Root 身分綁定仍有缺口




歷史檔名與內部版本一致

	

靜態檢查成立




歷史 Registry 版本連續遞增

	

靜態檢查成立




當前 Registry 需經認證才授予 Journal 簽署權

	

部分成立，撤銷後授權仍有缺口




candidateHwm 64-hex 驗證

	

指定分支檢查成立




四項新增負向測試

	

測試存在，未覆蓋以下兩個反例

這些結論是程式碼路徑的靜態審查結果。由於本輪無法在執行環境完整取得儲存庫並重新執行 Node.js 測試，以下新增反例不宣稱已完成實際執行重現。

二、Round 27 阻擋項
R27-B01｜P1 · 偽造 Genesis 可取代內嵌 Root 信任錨點
OPEN · BLOCKING

問題位置： scripts/adapters/plugin-data-adapter.mjs

直接程式碼證據：L661–L738

函式初始化時：

JavaScript
let rootId = options.trustedRootKeyId || null;
let rootPem = options.trustedRootPublicKeyPem || null;

歷史 Genesis 驗證使用：

JavaScript
if (rootId && (
  rootKey.keyId !== rootId ||
  rootKey.publicKeyPem !== rootPem
)) {
  // Reject
}
if (!rootId) {
  rootId = rootKey.keyId;
  rootPem = rootKey.publicKeyPem;
}

這形成了明確的信任邊界缺口：當呼叫端未提供 trustedRootKeyId 時，驗證器會接受歷史檔案自行宣告的 Root，而不是強制使用 DEFAULT_SUPERVISOR_KEY_ID 與 DEFAULT_SUPERVISOR_PUBLIC_PEM。

validateTrustRegistry() 的 Genesis 驗證原本有使用預設內嵌 Root，但此歷史信任鏈解析器沒有套用同等要求。

此外，無歷史檔案但存在 Journal 的當前 Genesis 驗證，也使用 if (!rootId || ...)，存在相同的預設 Root 綁定問題。

證據：L834–L856

靜態攻擊路徑

攻擊者在可寫入的 PLUGIN_DATA/history 放置 trust-registry.v1.json，只包含自己的 ACTIVE_PINNED_ROOT 金鑰，並建立與偽造 Journal 相符的 HWM。

使用攻擊者私鑰產生具有效 Ed25519 簽章及連續摘要的 Journal 條目。

透過公開的 getJournalRevokedKeyMap(dir) 預設呼叫方式進行驗證。

解析器未比對內嵌 Root，卻將偽造 Genesis 金鑰納入 trustedKeys，並依歷史 HWM 計算可用簽署視窗。

因為 getJournalRevokedKeyMap() 在此路徑只使用 Witness 的 Journal HWM 資訊，沒有以 Witness 的 Registry 身分摘要重新認證歷史 Genesis，所以已有獨立 Registry Witness 的情境也不能直接認定安全。

相關證據：L1608–L1711

裁定：R26-B01 不得 CLOSED。

這是直接控制流程所支持的權威驗證缺口；完整攻擊樣本尚未在隔離環境執行。

修補必要條件是將內嵌或經可信管道明確指定的 Root 作為唯一初始信任來源。不得從正在驗證的歷史資料推導 Root 身分。

推翻此結論的觀察：以未提供自訂 Root 的預設入口執行上述偽造 Genesis 測試，且能證明固定版本的實際程式碼在讀取攻擊者金鑰之前必然拒絕。

R27-B02｜P1 · 已遭 Journal 撤銷的金鑰仍可授權新 Registry
OPEN · BLOCKING

問題位置： resolveJournalTrustedKeyWindows() 的當前 Registry 認證。

直接證據：L811–L890

當 currentRegistry.registryVersion === priorVerifiedReg.registryVersion + 1 時，程式檢查：

authorizationProof.authorizedBy 是否存在於歷史版 Registry。

該歷史金鑰的狀態是否為 ACTIVE 或 ACTIVE_PINNED_ROOT。

authorizationProof.signature 是否可以由歷史公鑰通過 Ed25519 驗證。

但這段認證並未先檢查該簽署者是否已被 Revocation Journal 撤銷。

一旦上述檢查通過，當前 Registry 中的 ACTIVE 金鑰便可能取得：

JavaScript
trustedKeys.set(k.keyId, k.publicKeyPem);
maxActiveIndexPerKey.set(k.keyId, Infinity);

Journal 中的 KEY_REVOCATION 直到後續重播條目時才會更新金鑰的簽署視窗。

直接證據：L1780–L1795

靜態攻擊路徑

歷史 Registry v2 中，委任金鑰 K 為 ACTIVE。

合法 Journal 條目 #0 已透過 KEY_REVOCATION 撤銷 K，但歷史 Registry 的 K 狀態仍保留為 ACTIVE。

持有 K 舊私鑰的攻擊者建立 Registry v3，使用 K 簽署 authorizationProof，加入攻擊者金鑰 A。

解析器只根據 v2 的 K 狀態驗證 v3，便將 A 設為可信且可持續簽署，再處理 A 簽署的 Journal 後續條目。

特別需要區分：validateTrustRegistry() 已有 Journal 撤銷檢查，但 resolveJournalTrustedKeyWindows() 的獨立認證路徑尚未證明具備等價保護。因此，不能用其他入口的防護證明此公開輔助驗證入口也安全。

這項問題的前提是攻擊者持有已撤銷的舊私鑰，且能篡改當前 Registry 及 Journal 後續內容。它不等於已證明所有最外層 API 均可被完整接管。

裁定：R26-B02 不得 CLOSED。

修補必要條件是讓新 Registry 的授權簽署者，除了歷史 ACTIVE 狀態及有效簽章之外，還必須通過已認證 Journal 撤銷狀態檢查，並確保不會形成候選 Registry 自我授權的循環依賴。

推翻此結論的觀察：以已被 Journal 撤銷的 K 簽署 v3，驗證器能在 A 被加入 trustedKeys 前確定拒絕，且該拒絕是由可信歷史狀態與 Journal 證據共同決定。

三、測試證據與涵蓋率缺口

GitHub Actions 實際工作流程紀錄支持下列結果：

查核項目

	

GitHub 證據




test-plugin-data-adapter.mjs

	

105 passed、0 failed




render-sarif.mjs

	

121/121 passed




Release evidence

	

29 個檔案檢查通過




Pull Request CI

	

Ubuntu、Windows、macOS 三個 Job 成功




Semgrep

	

Job 成功




兩份 Adapter 原始檔

	

GitHub Blob SHA 相同：96a974ff812f3d958a5e5537b12bbc2ce424e516

CI 來源：Pull Request CI Run 42571766965；Semgrep Run 42571766961。

Layer 1 Manifest 與 Layer 2 Evidence Matrix 已包含所宣告的 SHA-256 值，但本輪未獨立對原始位元組重新計算 SHA-256，因此不將宣告值與 CI 的完整性檢查混稱為獨立雜湊驗證。

本輪另外發現兩項測試證據缺口。

第一，R26 新增測試中的 opts 明確指定 trustedRootKeyId、trustedRootPublicKeyPem。所以測試會走已提供 Root 的分支，沒有驗證預設呼叫缺少 Root 時能否拒絕偽造 Genesis。

第二，所謂獨立 System Witness 測試，實際將 THREE_LENS_SYSTEM_WITNESS_DIR 指向 tempDir/.system-witness-store，並在清空本機狀態後重新建立該目錄及 Witness。它能驗證「Witness 存在而 Journal 消失」時的拒絕，但不能證明 Witness 位於獨立故障或攻擊邊界、能在整個 PLUGIN_DATA 被回滾時存活。

測試證據：tests/test-plugin-data-adapter.mjs L6616–L6759。

四、正式結案判定

審查對象

	

裁定

	

原因




R26-B01

	

REOPENED

	

無自訂 Root 時仍可採納歷史資料自稱的 Genesis Root




R26-B02

	

REOPENED

	

當前 Registry 認證未先排除已遭 Journal 撤銷的歷史簽署者




歷史版本與檔名一致性

	

靜態驗證通過

	

版本比較及連續遞增條件存在




CI 與既有負向測試

	

PASS

	

固定 Commit 的 GitHub Actions 執行成功




最終合併權威

	

REJECTED

	

兩項 P1 阻擋項未取得閉合證據

本輪沒有修改程式碼、推送 Commit、提交 GitHub Review 或合併 PR，也沒有宣稱執行了未完成的攻擊重現。

不確定清單

未查證：新發現的兩個攻擊反例尚未在原始 Node.js 專案中動態重現。

預設帶過：攻擊者具有本機治理檔案的寫入能力，符合此次審查要求的威脅模型。

純推測：兩條反例是否能進一步繞過所有上層入口並形成持久化完整特權提升，尚未證明。

下一步： 將 R27-B01 的「不提供 trustedRoot*，改用攻擊者 Genesis Root」新增為負向測試，先確立失敗案例，再修改生產驗證邏輯。
```
