# Three-Lens Milestone 5.4 Phase 2

## Round 04 獨立第三方 AppSec 對抗性覆審報告

**審查日期**： 2026-11-07（臺灣時間）  
**審查員**： Independent Third-Party AppSec Auditor (ChatGPT Pro · High Reasoning Effort)  
**審查裁定**： `REJECTED` · 阻擋合併與發布  
**審查標的**： [GitHub PR #52](https://github.com/arcobaleno64/three-lens/pull/52)  
**目標版本**： v1.12.0  
**審查 Head Commit**： `f5093885d6fca1070a146a029d54b6601427b217`  
**執行模式**： 唯讀、冷啟動、對抗性原始碼審查 (High Reasoning Depth)  

---

## 審查裁定概述

本輪裁定：`REJECTED`。PR #52 目前不符合合併至 `main` 或發布 v1.12.0 的安全放行標準。

已透過 GitHub 核對 PR #52 的 HEAD、Base Commit，以及 R03 至 R04 的實際變更。R04 確實比 R03 前進一個 Commit，修復並非只有文字聲明。

不過，實際程式碼仍存在重要的安全邊界缺口。其中已確認的一項是：撤銷日誌與 Checkpoint 同時遺失時，預設讀取路徑仍可接受空白撤銷歷史。 這與宣稱的持久化反回滾、Fail-Closed 保證不一致。

這不是 CI 通過率的問題，而是測試案例是否真正覆蓋了攻擊者能控制的狀態。

---

## 一、R03-B01～R03-B07 修復覆審

本輪使用 `HOLDS`（修復成立）、`PARTIALLY_HOLDS`（部分成立）、`OVERTURNED`（原修復保證被反例推翻）三種狀態。

| 原阻擋項 | R04 覆審結果 | 主要判斷 |
| --- | --- | --- |
| R03-B01 · Critical | PARTIALLY_HOLDS | 新增 `minJournalEntries`，但它不是獨立持久化的可信高水位；雙檔刪除仍可繞過 |
| R03-B02 · Critical | PARTIALLY_HOLDS | 已補回退版本檢查與先驗註冊表驗證，但未解決整體持久化狀態回滾 |
| R03-B03 · High | OVERTURNED | `existsSync()` 條件使懸空 symlink 漏檢；hard link 也未防護 |
| R03-B04 · High | PARTIALLY_HOLDS | 既有日誌的讀寫加鎖已成立；日誌尚不存在時仍直接無鎖讀取 |
| R03-B05 · High | HOLDS | 13 項關鍵腳本已完整納入 Manifest，兩個新模組均有覆蓋 |
| R03-B06 · High | PARTIALLY_HOLDS | CLI 參數已接線，但 CASE 仍可在缺少可信上下文與必要 digest 時通過 |
| R03-B07 · High | PARTIALLY_HOLDS | 14 個檔案確實存在於指定 Commit；但時間與版本出處的自動驗證仍不足，報告仍有舊分類 |

因此，R03 七項修復中，只有 R03-B05 可以在本次核查範圍內完整結案。其餘項目不能僅因新增程式碼與負向測試，就轉為 `CLOSED`。

---

## 二、R04 對抗性發現

### R04-B01 · Critical：撤銷狀態可被整體回滾

**狀態**：OPEN · Release Blocker  
**來源**：`scripts/adapters/plugin-data-adapter.mjs`

`loadRevocationJournal()` 的新邏輯只有在呼叫端傳入 `minJournalEntries > 0` 或仍保有有效 Checkpoint 時，才能發現日誌遺失。

預設 `isRevoked()` 並沒有提供可信的歷史高水位。

因此，在攻擊者能修改 `PLUGIN_DATA` 中兩份持久化檔案的威脅模型下：
1. 已存在有效撤銷紀錄。
2. 撤銷日誌及其 Checkpoint 同時遺失。
3. 讀取端未提供 `minJournalEntries`。
4. 載入函式接受空白撤銷歷史。
5. 原本應被撤銷的 ID 可能重新被判定為未撤銷。

這是程式分支可直接推導的 Fail-Open，不需要偽造 Ed25519 簽章。

**修復要求**： 將已提交的撤銷高水位錨定至不能和日誌、Checkpoint 一起回滾的可信來源。單純在同一可寫目錄增加第三份檔案，不構成獨立反回滾保證。

**推翻條件**：若能證明所有生產讀取端必定由獨立可信來源取得不可回退的高水位，且雙檔遺失的負向測試確實被拒絕，此項可重新驗證。

---

### R04-B02 · Critical：Trust Registry 仍可回退至創世版本

**狀態**：OPEN · Release Blocker  
**來源**：`loadTrustRegistry()` in `scripts/adapters/plugin-data-adapter.mjs`

R04 的新增檢查：
```javascript
if (
  typeof options.minRegistryVersion === 'number' &&
  fallback.registryVersion < options.minRegistryVersion
)
```

只有在最低版本已知且被傳入時才有效。

若磁碟上的版本 2 以上註冊表被刪除，而載入端未提供 `minRegistryVersion`，目前仍會接受 `EMBEDDED_ROOT_REGISTRY` 版本 1。

這形成與 B01 類似的問題：根金鑰仍然可信，不代表持久化治理狀態仍然新鮮。

此外，遞迴驗證 `priorRegistry` 可以證明其簽章合法，卻不能單憑該驗證證明它是目前版本的合法直接前驅。

**修復要求**：至少需要區分密碼學有效性、版本單調性與授權鏈連續性（例如 `priorRegistry.registryVersion === registry.registryVersion - 1`），不能將三者合併成單一 `valid: true`。

---

### R04-B03 · High：檔案路徑防護仍可繞過

**狀態**：OPEN · Release Blocker  
**來源**：`appendRevocationEntry()` in `scripts/adapters/plugin-data-adapter.mjs`

已用本機 Node.js v22.16.0 的隔離測試目錄，分別重現兩種檔案系統行為。

檔案系統反例實測：
| 測試 | 實際觀察 |
| --- | --- |
| 懸空 symlink | `existsSync()` 回傳 `false`，但 `lstatSync()` 可辨識 symlink |
| 經懸空 symlink 寫入 | 工作區目標檔案被建立 |
| hard link | `isSymbolicLink()` 回傳 `false`，`nlink` 為 2 |
| 經 hard link 附加內容 | 工作區的同一實體檔案被修改 |

現行程式只有在 `fs.existsSync(targetPath)` 為真時才執行 `lstatSync()`，因此懸空 symlink 會略過防護。Hard link 則根本不屬於 symlink，解析 `realpath` 也無法辨認它與另一個路徑共享同一 inode。

此外，檔案檢查在取得鎖以前執行，檢查與實際開啟之間仍存在 TOCTOU 窗口。

**修復方向**：應採用支援平台上的原子開檔防跟隨語意、檔案描述元驗證，並處理 hard link 的實體檔案身分（例如檢查 `nlink > 1` 或確認 inode 未出現在 target workspace）及平台差異。

---

### R04-B04 · High：CASE 可在必要信任資料不足時通過

**狀態**：OPEN · Release Blocker  
**來源**：`skills/3lens/scripts/finalize-scan.mjs`、`skills/3lens/scripts/compact-guard.mjs`

在 `finalizeScan()`：
```javascript
if (
  env.toolManifestDigest ||
  preCompactionState?.toolManifestDigest
) {
  expectedContext.toolManifestDigest =
    preCompactionState?.toolManifestDigest ||
    effectiveToolProvenance?.toolIntegrityDigest ||
    null;
}
```

若封套的 `toolManifestDigest` 為空，而且沒有 `preCompactionState`，就不會建立期望值，R04 新增的 digest 強制比較也不會觸發。

其他缺口包括 CLI 未傳遞強制簽章選項，以及缺少由可信執行環境提供的正向 compaction 證明。沒有旗標、Manifest 標記或事前狀態時，`compactGate` 可被視為不適用。

因此，現在的 CASE 更接近「在提供充分可信上下文時可以檢查一致性」，尚不能宣稱能自主防止跨 `/compact` 的狀態替換。

**修復要求**：必須讓必要的 Run ID、Nonce、Manifest Digest、Repo Fingerprint 及事前狀態來源不完整時直接 `UNCHECKABLE`，且不得依賴同一可修改的 `scratch` 資料同時充當證據與驗證基準。

---

### R04-B05 · High：首次建立日誌的讀取仍未加鎖

**狀態**：OPEN · Release Blocker  
**來源**：`loadRevocationJournal()` 加鎖路徑

```javascript
if (options.skipLock === true || !fs.existsSync(journalPath)) {
  return doLoadRevocationJournal(options);
}
```

日誌不存在時直接跳過鎖，與首次建立日誌的寫入端沒有共同互斥保護。

這保留了初始化瞬間讀取不完整快照的競爭窗口。現階段是由控制流程確認的同步缺口，尚未重現實際錯誤裁決，因此不把它寫成已成功利用的攻擊。

**修復要求**：讓正式讀取端不因檔案尚未存在而跳過取得同一把鎖，並補上首次建立期間的跨行程負向測試。

---

### R04-B06 · High：實證報告與權威語料庫出處不一致

**狀態**：OPEN · Release Blocker  
**來源**：`evals/v2-corpus/layer2-external-validity-corpus.json`、`reports/multi-tier-effort-ablation-report-2026-11.md`

R04 語料庫已將 14 個案例全部分類為 `SYNTHETIC_REGRESSION` 或 `SYNTHETIC_CLEAN_CONTROL`。

但目前實證報告的第 1.1 節及第 4.1 節仍保留 `UPSTREAM_VERIFIED_OSS`、外部 OSS Clean Controls 等敘述，與已凍結語料庫的分類不一致。

而 RFC 0005 的 Workstream 2 要求具備真實外部漏洞與官方修補出處。現有合成案例可以作為回歸測試，卻不能自動等同於外部有效性驗證。

同時，低、中兩檔單一測試案例的 Pilot，不足以證明 RFC 所描述的跨模型層級、召回率、誤報率及不確定性校準目標均已完成。

這是發布證據的範圍問題，不能用增加一般單元測試數量取代。

---

## 三、已獨立確認的正向證據

以下成果可保留，不需要因為 R04 被拒絕而全部撤銷。

| 查核項目 | 獨立核查結果 |
| --- | --- |
| PR Commit 身分 | HEAD、Base 與 R03→R04 關係吻合 |
| 13 項 TCB 腳本清冊 | 13/13 路徑一致，沒有缺漏或多餘項 |
| Adapter 雙份程式碼 | `scripts/adapters` 與 `skills/3lens/scripts/adapters` 的內容及 Git Blob SHA 相同 |
| Layer 2 指定 Commit | 14/14 `targetFile` 確實可在 `eddd0c3` 讀取 |
| CASE Manifest Digest 空值防護 | 當 `expectedContext.toolManifestDigest` 已提供時，空值確實會遭到拒絕 |
| RETIRED 金鑰歷史驗章 | 程式已納入非撤銷的 `RETIRED` 公鑰；測試亦涵蓋一般輪替情境 |

另外，`validate-v2-corpus.mjs` 目前只檢查 Commit SHA 格式、當前工作樹中的檔案存在性，以及 `frozenAt` 不晚於目前時間。它沒有自動比對檔案是否屬於指定 Commit，也沒有驗證 `frozenAt` 與 Commit 時間相符。

本輪已額外逐一查核 14 個 Commit 路徑，確認它們存在；但這不等於目前的自動驗證器已具備相同保證。

---

## 四、發布門禁裁定

**Gate 2：v1.12.0 Promotion — BLOCKED**

| 評估維度 | 結果 |
| --- | --- |
| 原始碼身分 | PASS |
| TCB Manifest 覆蓋 | PASS（限清冊覆蓋） |
| 持久化反回滾 | FAIL |
| 檔案系統隔離 | FAIL |
| CASE Fail-Closed | FAIL |
| 並發原子性保證 | NOT ESTABLISHED |
| 外部有效性及發布證據 | FAIL |
| 完整 CI 再驗證 | PENDING |

本輪透過 GitHub Actions 查詢時，Semgrep、Ubuntu 與 macOS CI 工作顯示成功，Windows CI 仍為執行中。因此不能將整體遠端 CI 宣稱為已完成的獨立驗證。

NIST SP 800-218 SSDF 1.1 要求以可驗證方式管理安全設計、實作與發布完整性；它不是只要測試全綠就能推定安全的認證制度。

### 合併前必要修復順序

1. 建立真正獨立的持久化單調狀態錨點，阻止雙檔刪除與註冊表版本回退。
2. 修正檔案開啟及路徑防護，補足 symlink、hard link、TOCTOU 負向測試。
3. 將 CASE 必要上下文、可信事前狀態與強制驗證設定納入 CLI 合約。
4. 將日誌首次建立和既有日誌讀取納入一致的互斥機制。
5. 統一語料庫與實證報告的出處分類，補足 RFC 0005 Exit Gate 所需的真實評估證據。

---

## 五、審查獨立性與不確定清單

本次已直接讀取固定 Commit 的 GitHub 原始碼，確認清冊及 14 個 Commit 檔案，並在隔離的本機目錄執行兩種檔案系統反例。未修改 GitHub 儲存庫、未提交 PR Review、未合併或發布，也未執行完整專案測試套件。Git Clone 因執行環境無法解析 `github.com` 而失敗，故未宣稱已完成全程式端對端重現。

**不確定清單**：
- 未查證： 完整專案測試的獨立重跑結果、Windows CI 最終結果，以及 `frozenAt` 與 R03 Commit 原始 Git 時間是否完全一致。
- 預設： 依 RFC 宣稱的反回滾與防污染保證，將攻擊者可修改 `PLUGIN_DATA` 或建立檔案連結列入威脅模型；若權限邊界明確排除，須重新評定相關嚴重度。
- 推測： CASE 的缺失上下文問題在實際 Antigravity `/compact` 流程中的可利用性，仍需真實生命週期測試確認。

本輪裁定綁定 `f5093885`。只有在新的修復 Commit 提供相應負向測試、獨立閉環證據及重新審查後，才能重新考慮 `APPROVED`，不能以本次 CI 通過率抵銷未閉合的 Critical 發現。
