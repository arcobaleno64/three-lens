# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 32

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `3cc6eb4cf5860b6886d1a22b07ac76e0410f1a89`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 32 獨立安全審查
REJECTED · 不得合併

正式裁定：REJECTED。固定審查 Commit 3cc6eb4cf5860b6886d1a22b07ac76e0410f1a89 尚未滿足 Default-Deny 安全驗收條件。

本輪已直接透過 GitHub 連線讀取指定 Commit 的程式碼、負向測試、完整 PR 中繼資料及 GitHub Actions 執行紀錄。

確認前輪兩項修補已實際進入程式碼，但仍發現兩個未充分防護的邊界：

Root 身分綁定仍不完整： keys[] 中的 Root 公鑰受到保護，但 Registry 頂層的 activeKeyId、activePublicKeyPem 與對應金鑰紀錄，並未在所有版本強制一致。

Root 撤銷免疫存在邏輯不對稱： Journal 驗證會忽略對 Root 的 KEY_REVOCATION，但後續寫入路徑仍會將同一條目當成 Root 已被撤銷的證據。

第一項構成可由程式碼直接證明的信任資料完整性缺口；第二項具有阻斷 Root 後續授權操作的可行攻擊路徑。兩者均不應由 CI 全綠直接豁免。

一、審查基準

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




PR

	

#52




Target

	

main




固定 Commit

	

3cc6eb4cf5860b6886d1a22b07ac76e0410f1a89




Head SHA

	

完全一致




PR State

	

OPEN




Mergeable

	

true




GitHub Actions

	

Semgrep 與 Pull Request CI 成功




CI Job

	

已確認 Linux、Windows、macOS、Semgrep 四項 Job 成功




兩份 Adapter

	

Git Blob SHA 相同，9a9a222baf5f848f8c0ddc3c82e43e4c29651502




本輪執行模式

	

唯讀、固定 SHA、直接程式碼查核

證據：指定 Commit、PR #52。

上述 CI 成功為 GitHub 執行紀錄的驗證結果，不代表我已在獨立環境重新執行全部測試。

二、阻擋項 R32-B01：Registry 頂層 Root 身分仍可被替換

P1 · OPEN · 信任身分綁定缺口

證據檔案：plugin-data-adapter.mjs L2223–2313、L2590–2834。

已確認的程式碼行為：

validateTrustRegistry() 對 registryVersion > 1 驗證 Registry 授權簽章，並要求 keys[] 內的 Root PEM 等於固定的 rootPem。但頂層欄位只驗證 activePublicKeyPem 的格式，以及其與 activeKeyFingerprint 的雜湊一致性。

沒有強制下列關係：

純文字
registry.activeKeyId === rootId
    =>
registry.activePublicKeyPem === rootPem

也沒有一般性的 activeKeyId、activePublicKeyPem、activeKeyFingerprint 與 keys[] 對應紀錄一致性檢查。

因此，持有 ACTIVE 委託金鑰 K 的攻擊者，可以構造下列 v3 Registry：

JavaScript
{
  registryVersion: 3,
  activeKeyId: rootId,
  activePublicKeyPem: attackerPublicKeyPem,
  activeKeyFingerprint: sha256Digest(attackerPublicKeyPem),
  revokedKeyIds: [],
  keys: [
    {
      keyId: rootId,
      publicKeyPem: rootPem,
      status: "ACTIVE_PINNED_ROOT"
    },
    {
      keyId: delegatedKeyId,
      publicKeyPem: delegatedPublicKeyPem,
      status: "ACTIVE"
    }
  ],
  authorizationProof: {
    authorizedBy: delegatedKeyId,
    signature: signatureByDelegatedK
  }
}

前提是 Registry 其他必要欄位與歷史授權鏈均合法，且相應簽章涵蓋實際 Registry 授權負載。

這個候選版本不會觸發 keys[] 的 Root PEM 替換檢查，因為 keys[] 內的 Root 仍是正確公鑰。

依據目前讀取的驗證控制流程，這種頂層身分不一致的 Registry 可能通過 validateTrustRegistry()。這是可直接由缺失的檢查條件推導的結果，尚未以完整執行環境重現。

必須區分兩件事：trustedKeys 仍以 rootPem 驗證 Journal，故本輪尚未證明攻擊者能直接偽造 Root 的 Journal 簽章；但已建立完整 Root 身分綁定未獲保證的反例。

修正要求：當 activeKeyId === rootId 時，必須驗證頂層 PEM 與 Fingerprint 均對應不可變 Root；所有 active key 也必須與 keys[] 中唯一的相同 keyId 紀錄一致。

推翻此阻擋項所需證據：在固定版本加入上述候選 Registry 的負向測試，證明所有可接受路徑均明確拒絕，而非僅由 Journal 驗證器忽略錯誤欄位。

三、阻擋項 R32-B02：Root 撤銷免疫與寫入授權不一致

P1 · OPEN · Root 授權可用性與撤銷語義

關鍵程式碼：

路徑

	

實際行為




getJournalRevokedKeyMap L1971–1979

	

Root 撤銷不納入 revokedMap




doLoadRevocationJournal L4736–4744

	

不撤銷 Root，卻仍將條目加入 entries




appendRevocationEntry L4944–4951

	

不排除 Root，對任何符合 targetId === signedBy 的撤銷條目拒絕寫入

這形成可檢驗的攻擊鏈：

攻擊者具有 ACTIVE 委託金鑰 K 的簽署能力，以及修改持久化 Journal 與必要錨點的能力。

攻擊者直接構造、簽署 KEY_REVOCATION，使 targetId = rootId，並維持合法的 Journal hash chain 與可驗證 HWM。

Journal 讀取路徑忽略 Root 的撤銷效果，但仍保留該條目。

合法 Root 後續透過 appendRevocationEntry() 寫入時，L4948 將該條目視為 Root 已遭撤銷，拋出 [REVOKED_SIGNER_REJECTED]。

這裡不是證明攻擊者已獲得 Root 私鑰，而是指出：一個按規格應當無效的 Root 撤銷紀錄，可能阻斷 Root 執行合法的新撤銷操作。

其安全影響是受委託金鑰 K 可能阻止 Root 在標準寫入路徑中撤銷 K。完整利用仍須驗證持久化錨點的可更新性及 witness 新鮮度檢查，因此攻擊可達性屬高可信度的程式碼推論，不是已完成的端到端實測。

修正要求：Journal 讀取與驗證路徑應明確拒絕 KEY_REVOCATION(rootId)，不能僅忽略其撤銷效果；寫入路徑也應使用一致的有效撤銷語義。

推翻此阻擋項所需證據：完整負向測試證明攻擊者簽署的 Root 撤銷條目會在讀取階段遭拒絕，或至少無法阻斷合法 Root 後續操作。

四、R31-B01 與 R31-B02 閉合裁定

原阻擋項

	

本輪判定

	

說明




R31-B01 Root 錨點替換

	

PARTIALLY_HOLDS

	

keys[] 替換已攔截，但頂層 Root 身分不一致未排除




R31-B02 Root 撤銷免疫

	

PARTIALLY_HOLDS

	

撤銷狀態處理已修補，Journal 讀取與後續授權仍不一致

本輪實際確認的修補內容包含：

歷史及當前 Registry 對 keys[] 的 Root PEM 比對。

trustedKeys 將 Root 固定為 rootPem。

Registry 的 revokedKeyIds 不允許包含 Root。

appendRevocationEntry() 拒絕正常 API 寫入 Root 撤銷紀錄。

但 Negative Test G 未覆蓋本輪兩項反例。它測試的是 keys[] 替換與正常 API 的撤銷拒絕，不是頂層 active-key 身分偽造及外部簽署 Journal 注入。

歷史 R27-B01 至 R30-B01 的 CLOSED 狀態，本輪僅作為既有審查紀錄，不宣稱已重新完整證明。

五、CI 與審查限制

已取得指定 Commit 的 GitHub Actions Job Log，確認：

驗證

	

結果




Adapter 測試

	

105 PASS、0 FAIL




SARIF 測試

	

121/121 PASS




Release evidence

	

29 files verified




Documentation integrity

	

PASS




Linux / Windows / macOS

	

Job success




Semgrep

	

Job success

Pull Request CI 執行紀錄

兩份 Adapter 的 Git Blob SHA 完全一致；Manifest 與 Evidence Matrix 亦記載使用者提供的 SHA-256 值。但本輪沒有獨立重新計算 SHA-256。

獨立執行限制：已嘗試取得固定 Commit 至隔離工作目錄，但執行環境無法解析 github.com 網域，因此無法在本地執行新的攻擊重現測試。這不影響已完成的原始碼與 CI 紀錄查核，但限制了漏洞可達性的證明強度。

Round 32 最終裁定
REJECTED

Merge Authorization: DENIED

審查對象： 3cc6eb4cf5860b6886d1a22b07ac76e0410f1a89

阻擋項： R32-B01、R32-B02

閉合條件： 補齊 active-key 身分一致性檢查、統一 Root 撤銷語義，並以兩項新增負向測試確認拒絕行為。

有效範圍： 僅限指定 Commit；後續 Commit 應重新驗證，不自動繼承裁定。

不確定清單

未查證：GitHub 宣稱的 8/8 個別 Check Run，已核實兩個 Workflow 與四個 Job 成功。

預設：攻擊者具備題述的 ACTIVE 委託金鑰及相關持久化狀態修改能力。

推測：兩條反例的完整執行可達性尚未獨立實測；未宣稱 Root 私鑰已可被偽造。

下一步（兩分鐘內）： 先在 tests/test-plugin-data-adapter.mjs 新增「keys[] Root PEM 正確，但頂層 activeKeyId=rootId、activePublicKeyPem=attackerPem」的負向測試，固定以 assert.strictEqual(result.valid, false) 驗證，避免再次出現修補通過、信任不變量卻仍有缺口的情況。

到目前為止，這段對話對你有幫助嗎？
```
