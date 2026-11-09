# Milestone 5.4 Phase 2 獨立安全審查報告：Round 16

審查日期： 2026-11-08（臺灣時間）  
儲存庫： `arcobaleno64/three-lens`  
Pull Request： [PR #52](https://github.com/arcobaleno64/three-lens/pull/52)  
固定審查版本： `06cddb097440612eb28d6c58541bf18de7769d60`  
審查模式： Cold-Start / Adversarial / Evidence-Bound / Read-Only  

裁定：**REJECTED**。不得依本輪證據核准合併。

---

## 審查全文存證

```markdown
REJECTED · Merge Blocked
# Milestone 5.4 Phase 2 獨立安全審查報告：Round 16

審查日期： 2026-11-08（臺灣時間）
儲存庫： arcobaleno64/three-lens
Pull Request： PR #52
固定審查版本： 06cddb097440612eb28d6c58541bf18de7769d60
審查模式： Cold-Start / Adversarial / Evidence-Bound / Read-Only

裁定：REJECTED。不得依本輪證據核准合併。

工程團隊確實實作了 R15 多項修復，但經檢查指定 Commit 的實際程式碼，仍發現足以阻擋合併的權威信任邊界問題。

最重要的問題不是單純漏傳 Digest，而是 Registry 的歷史版本摘要雖已記錄，正式驗證路徑卻沒有完整核對歷史內容承諾。攻擊者可能藉由建立較高版本的替代授權鏈，繞過原先只針對相同版本設計的分岔檢查。

此外，公開儲存 API 的內部寫入旗標仍可由呼叫端指定，不能視為已完成權限隔離。

本裁定依原始碼直接證據及邏輯反例作成；尚未宣稱已完成攻擊的端到端動態重播。

## 一、核心阻擋發現

### R16-B01 · Critical：藉由版本前進，繞過既有歷史 Registry Digest 承諾

狀態：OPEN · Blocking

受影響檔案： scripts/adapters/plugin-data-adapter.mjs

- 第 1873–1949 行：歷史檔案與目前註冊表的一致性檢查。
- 第 2145–2177 行：以磁碟上的前一版 Registry 建立授權驗證鏈。
- 第 2201–2203 行：正式載入時檢查目前 Registry 的 Digest。
- 第 2652–2661 行：依候選 Registry Version 查詢歷史摘要承諾。

問題在於：assertMonotonicWitnessFreshness() 只檢查候選版本對應的 Digest，沒有遍歷並驗證目前 Registry 所依賴的全部歷史 Registry，是否與 witness.registryDigests 中已承諾的內容一致。

假設合法 Registry 已從 Root A 的 v1 輪替為 Root B 的 v2，且見證檔已記錄：
maxSeenRegistryVersion = 2
registryDigests["2"]   = Digest(Legitimate_v2)

攻擊者事後取得已除役 Root A 私鑰，並具備更改 PLUGIN_DATA Registry 與歷史檔案的權限。

可能的攻擊鏈如下：
1. 使用 Root A 簽署替代 v2，指定攻擊者控制的 Root C 為 Active Key。
2. 使用 Root C 簽署替代 v3，形成表面上連續、簽章有效的 v1 → v2′ → v3′。
3. 將目前 Registry、history/v2、history/v3 及必要的相關狀態換成一致的替代鏈。
4. 正式載入 v3′ 時，現行程式只針對候選版本 3 查詢 Witness Digest。原本釘住合法 v2 的內容承諾沒有被拿來核對替代 v2′。

邏輯結果： 在相關 HWM 與 Checkpoint 條件也滿足的情況下，合法 v2 與替代 v2′ 的不一致可能被隱藏於歷史鏈中，而新版本 v3′ 被接受。

這與 R15-B03 要求防範「取得退休私鑰後重新編造歷史信任鏈」的安全目標直接衝突。

修復要求： 在接受新版本前，逐一核對其完整祖先鏈與全部既有可信歷史 Digest 承諾。不能只檢查目前版本，也不能將驗證後才新寫入的較高版本 Witness 視為歷史分岔已排除的證明。

推翻本發現的條件： 提供針對本 SHA 的程式碼路徑或隔離環境重播，證明歷史 v2′ 與 Witness 中合法 v2 Digest 不一致時，即使候選版本提升為 v3′，正式載入仍必定拒絕。

### R16-B02 · High：公開儲存 API 可直接取得 Witness 寫入特權

狀態：OPEN · Blocking

位置： plugin-data-adapter.mjs 第 148–153、227–248、296–309、2603–2605 行。

核心檢查：
```javascript
if (
  (baseName === '.monotonic-witness.json' ||
   baseName.endsWith('.witness.json')) &&
  options.__internalWitnessWrite !== true
) {
  throw new Error('[STORAGE_CONFINEMENT_VIOLATION]');
}
```

問題不是缺少檢查，而是檢查所依賴的 options.__internalWitnessWrite 完全由呼叫端控制。

例如，當呼叫端原本已能使用公開儲存 API，且具有目標檔案的作業系統寫入權限時，傳入：
```javascript
safeOpenStorageFile(
  witnessPath,
  'w+',
  0o600,
  {
    ...options,
    __internalWitnessWrite: true
  }
);
```
即可通過這一層特權檢查。w+ 還具有 O_TRUNC 效果。

這不是需要破解金鑰的密碼學攻擊，而是公開 API 存取控制繞過。

配合 R16-B01，若攻擊者有能力覆寫兩份 Witness、相關 Registry 及歷史檔案，再經過冷啟動清除程序內記憶體見證，即可能移除合法版本的歷史承諾。

R15-B04 的新增測試只檢查：
```javascript
safeWriteFileSync(localWitness, 'tampered', opts)
```
也就是未傳入內部旗標時應拒絕。它沒有測試主動傳入 __internalWitnessWrite: true 的情況。

修復要求： 不得將內部寫入授權設計成公開 API 可自行指定的布林旗標。需要隔離 Witness 專用寫入路徑，並明確界定作業系統權限。

特別注意：即使將旗標改為模組私有，也不能防禦能直接使用 node:fs、且與服務執行帳號擁有相同檔案權限的惡意程式。若威脅模型包含這類攻擊者，就必須額外建立受保護的信任錨點，不能把相同使用者帳號下的兩個檔案宣稱為獨立、不可回滾的證據。

推翻條件： 證明所有非授權呼叫端均不能透過公開 API 或其實際可使用的檔案系統能力修改任何可信 Witness，並以負向測試驗證。

### R16-B03 · High：COMMITTED WAL 復原可在完整授權驗證前污染永久 Witness

狀態：OPEN · Blocking

位置： plugin-data-adapter.mjs 第 689–755、757–838、2537–2585 行。

這裡的問題與 R15-B02 的修復順序不同。

R15-B02 確實將 updateMonotonicWitness() 移至刪除已提交 WAL 之前。但目前在 COMMITTED 分支中：
1. 依據磁碟上的 Registry 判定 WAL 簽署者是否已退休或撤銷。
2. 驗證 WAL 本身的簽章。
3. 比對 Registry、Checkpoint 與 Journal Tail 的 HWM。
4. 驗證 Journal Tail 簽章。
5. 直接使用目前 Registry 的版本及 Digest 推進永久 Witness。

第 771–838 行沒有對完整 curReg 執行 validateTrustRegistry()，也沒有完整驗證 Registry 歷史鏈與整條 Journal。

簽署者為預設可信 Root 時，第 715–716 行甚至可直接選用內嵌公開金鑰，而不需要走第 724–735 行的 Registry 載入驗證分支。

#### 對抗反例
假設攻擊者取得舊 Root 私鑰，並可修改 WAL、Registry、Checkpoint 和 Journal，但不能直接改寫系統 Witness。

攻擊者可能構造彼此一致、且使用舊 Root 正確簽署的 COMMITTED WAL 與 Journal Tail，並在尚未驗證完整授權鏈的 Registry 中聲稱極高的版本號與 HWM。

當這些值高於現有 Witness 時，updateMonotonicWitness() 的版本及索引比較會接納較大的數值並將其持久化。

其安全後果可能是：
- 原本有效的 Registry 隨後無法通過單調性驗證。
- 永久 Witness 被推進至不合法或無法正常到達的版本。
- 系統進入必須經過受控管理程序才能恢復的狀態。

這是一條 Witness Poisoning / Persistent Denial-of-Service 路徑，並不需要在攻擊前直接改寫 Witness。

目前可從原始碼確立的是「缺少完整授權驗證且存在持久化寫入路徑」。完整攻擊成功仍需要隔離環境重播，不能直接宣稱已實證。

修復要求： 在推進 Witness 前，必須驗證候選狀態的完整 Registry 信任鏈、歷史 Digest 承諾，以及相關 Journal 完整性。避免在復原函式中直接呼叫會再次觸發復原的公開載入函式，應使用不產生權威狀態寫入的內部驗證程序。

推翻條件： 在既有 Witness 維持合法版本時，提供偽造但正確簽署的 COMMITTED WAL 負向測試，證明不合法的較高版本不能修改任一持久化 Witness。

### R16-B04 · Medium：Registry Digest 未包含實際授權證明

狀態：OPEN · Content Commitment Incomplete

位置： plugin-data-adapter.mjs 第 1183–1219 行。

目前 Digest：
```javascript
const authPayload =
  computeRegistryAuthorizationPayload(registry);

const signature =
  typeof registry.signature === 'string'
    ? registry.signature
    : '';

return sha256Digest(authPayload + '|' + signature);
```

但 Registry 的實際授權證明在 registry.authorizationProof.signature，其驗證位於第 1545–1579、1581–1723 行。

因此，computeRegistryDigest() 並未如修復聲明所述，確實包含實際使用的 authorizationProof 簽章及簽署者資訊。

此外，computeRegistryAuthorizationPayload() 未包含 pinnedSince、rotationPolicy、authorizationProof 等欄位，也未包含聲明提到的 validFrom、validUntil。

這不代表目前能任意修改 Active Key，因為 Active Key 和 Keys 陣列已包含在 Payload 中，且 Registry 還有獨立的簽章驗證。但「完整 Registry 權威內容承諾」尚未成立。

尤其 Genesis v1 允許缺少 authorizationProof 的情況。這意味著在其餘 Payload 不變時，移除可選的 Genesis 授權證明，不一定改變目前計算的 Registry Digest。

修復要求： 區分「授權訊息簽署用 Payload」與「持久化 Registry 身分承諾」。後者應納入經規格明確界定的全部安全相關欄位及其授權證明，並使用固定的 Canonical Serialization 與 Domain Separation。

### R16-B05 · Medium：Witness 結構驗證仍不足以保證語意正確性

狀態：OPEN · Schema Hardening Required

位置： plugin-data-adapter.mjs 第 2370–2418 行。

已確認 {}、缺少必要欄位及不可解析 JSON 可以被拒絕，但仍存在以下可接受的異常值：
- raw.dir 只要求非空字串，未要求與目前正規化 Witness 目錄一致。
- maxSeenRegistryDigest、maxSeenHwmHeadDigest 只檢查字串型別，未要求必要時為 64 位十六進位 SHA-256。
- registryDigests 並非必要欄位，字典 Key 與 Digest 沒有完整結構及一致性驗證。

因此，結構驗證已改善，但不能稱為完整的 Strict Schema Validation。

另一份完好的 Witness 可能阻擋部分弱化狀態，但這不能取代對單一異常 Witness 採取 Fail-Closed。

修復要求： 強制檢查目錄身分、Digest 格式、版本與 Digest 字典對應關係，以及 HWM Index 和 Digest 的語意一致性。

## 二、R15 五項修復逐項覆審

| R15 議題 | Round 16 判定 | 審查結果 |
| --- | --- | --- |
| B01 · 同索引 HWM Digest | HOLDS（限縮） | 正式載入路徑已傳入 Digest，同索引不同 Digest 可被拒絕；仍依賴可信 Witness |
| B02 · COMMITTED WAL 持久化順序 | PARTIALLY_HOLDS | COMMITTED 分支順序已修正，但復原前的完整狀態驗證不足 |
| B03 · Registry 內容承諾 | OVERTURNED | 同版本比對已加入，但較高版本可繞過歷史版本承諾，見 R16-B01 |
| B04 · Witness Schema 與 API 隔離 | OVERTURNED | {} 拒絕已修復；公開旗標旁路與結構語意缺口仍存在 |
| B05 · Lock 0o600 DAC | HOLDS（限縮） | 一般鎖及回收鎖均明確傳入 0o600，但不等同跨平台 ACL 或完整 TOCTOU 安全證明 |

其中 B02 還有一項需要區分的事實：未提交 WAL 的回退復原在第 1056–1058 行仍直接刪除交易標記，並沒有先呼叫 updateMonotonicWitness()。

這與提交的修復敘述不完全一致。不過，正常回退本來就不一定需要推進 Witness；不能只因少了函式呼叫就判定為新漏洞。真正需要證明的是回退後 Witness 不落後於任何已正式提交的權威狀態。

## 三、CI、雙向同步與完整性查核

核對到兩份 Adapter 的 Git Blob SHA 均為：
a357c7ef265c9fcf92b82c7875a45c9e1eb5fec1

已查核的 Actions 紀錄：
- Pull Request CI：42460876934 (All matrix jobs SUCCESS)
- Semgrep：42460876908 (SUCCESS)

## 四、必要修復與重新驗收條件

在重新提請 APPROVED 前，至少需要完成以下四項：
1. 封閉歷史 Registry 分岔：正式載入較高版本時，必須驗證所有已見歷史版本的內容 Digest，不得僅比較目前版本。
2. 建立真正的 Witness 寫入權限邊界：移除公開旗標授權旁路；使用不可匯出的內部 Symbol 或閉包私有通道，確保外部無法藉由傳入旗標偽造內部呼叫。
3. 修正 COMMITTED WAL 的權威推進條件：在永久 Witness 更新之前，完成完整、無副作用的授權鏈與 Journal 驗證，並補上惡意 WAL 污染水位的負向測試。
4. 完成承諾格式與結構語意檢查：將 Registry 授權證明納入規格所要求的身分承諾，嚴格驗證 Witness 的目錄、版本、Digest 及其一致性。

## 五、本輪審查限制與最終處置

裁定維持 REJECTED，且 R15-B03、R15-B04 不得標記為 CLOSED。
```
