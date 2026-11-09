# Three-Lens Milestone 5.4 Phase 2
## Round 03 獨立第三方 AppSec 對抗性覆審報告

**審查日期**：2026-11-07  
**審查員**：Independent Third-Party AppSec Auditor (ChatGPT Pro · High Reasoning Effort)  
**審查裁定**：`REJECTED`（PR #52 仍存在阻擋合併之核心安全缺陷，維持禁止合併）  
**審查目標**：GitHub PR #52 (`feat/m54-phase-2-governance`)  
**審查 Head SHA**：`eddd0c38875c356fd20530b2e19cd12734d50155`  
**比對 Base SHA**：`143446bb932787cd64577135975fe1bdb73b52fe` (`v1.11.0`)  
**比對 R02 SHA**：`a4d49e160c98f3fd9f5135a6551689ce95311c06`  
**審查模式**：Read-only、冷啟動、對抗性原始碼審查 (High Reasoning Depth)  

---

## 審查裁定概述

正式裁定：`REJECTED`。不同意將 PR #52 合併至 `main`，亦不同意據此核准 v1.12.0 發佈。

R03 確實修復了多項 R02 指出的缺陷（F09、F10 已關閉），但仍存在影響安全權威判定的阻擋項：
1. 撤銷日誌與 Checkpoint 尚未形成不可協同回滾的信任錨點 (R03-B01)。
2. 信任註冊表仍有版本下限與歷史金鑰驗證問題 (R03-B02)。
3. 最終日誌檔案 symlink 仍可能導致 Workspace 污染 (R03-B03)。
4. 讀寫快照與並發一致性未完全鎖定 (R03-B04)。
5. 新的 CASE 權威模組 `compact-guard.mjs` 未納入 TCB `tool-integrity-manifest.json` 完整性驗證 (R03-B05)。
6. CASE 的真實生命週期防線仍可被未傳入參數跳過 (R03-B06)。
7. 內部合成測試案例已改善出處標示，但 Base Commit 不含新建立檔案，且尚不能充當已驗證的外部效度語料庫 (R03-B07)。

---

## 一、F01～F10 修復覆審矩陣

| Finding | R03 裁定 | 核心理由 |
| :--- | :--- | :--- |
| **F01** Critical | PARTIAL · OPEN | 七欄位簽章已補強，但 Checkpoint 可與日誌一起回滾；讀寫快照亦不一致 |
| **F02** Critical | PARTIAL · OPEN | 創世金鑰限制已補強，但版本回退、先驗註冊表驗證及歷史金鑰仍有缺口 |
| **F03** High | PARTIAL · OPEN | 目錄實體路徑已檢查，惟最終日誌檔案 symlink 仍可轉向 workspace |
| **F04** High | PARTIAL · OPEN | 寫入鎖有所改善，但讀取端沒有同步，且日誌與 Checkpoint 未共同提交 |
| **F05** High | PARTIAL · OPEN | 摘要與簽章驗證已補強，但無強制簽章設定時仍接受未簽署封套；工具摘要可被省略 |
| **F06** High | PARTIAL · OPEN | Finalizer 已能呼叫 CASE 驗證，但實際 CLI 進入點未可靠傳遞 compaction 生命週期狀態 |
| **F07** High | PARTIAL · OPEN | 合成案例標示改善，但 commit 與檔案對應仍不一致，外部效度要求未達成 |
| **F08** Medium | PARTIAL · OPEN | Clean controls 的合成身分已誠實揭露，但不能取代 RFC 要求的外部生產元件 |
| **F09** Medium | **CLOSED** · SCOPED | 單次 Pilot 限制與工具呼叫差異已明確揭露 |
| **F10** Medium | **CLOSED** | RFC Exit Gate 維持 `PENDING_REVIEW`，未提前宣告正式通過 |

---

## 二、R03 安全阻擋項細節 (R03-B01 ～ R03-B07)

### R03-B01 · Critical：撤銷日誌缺乏不可協同回滾的錨點
`appendRevocationEntry()` 先以 `fs.appendFileSync()` 新增日誌紀錄，再利用暫存檔與 `fs.renameSync()` 更新 Checkpoint。若攻擊者同時替換或回滾日誌與 Checkpoint，讀取端無法偵測。此外若兩者皆遺失，`loadRevocationJournal()` 將其視為空日誌放行。
- **結案要求**：將最新已接受日誌頭錨定至攻擊者無法與日誌同步回滾的可信位置，並要求缺失或回退時 Fail-Closed。

### R03-B02 · Critical：信任註冊表仍存在信任來源與回退缺口
1. `minRegistryVersion` 回退繞過：`loadTrustRegistry()` 在磁碟沒有註冊表時直接回傳 `EMBEDDED_ROOT_REGISTRY`，未先執行 `validateTrustRegistry(fallback, options)`，造成版本下限被繞過。
2. `priorRegistry` 信任前提：`validateTrustRegistry()` 使用 `options.priorRegistry.keys`，但未在函式內驗證 `priorRegistry` 自身之合法性。
3. 金鑰退休後歷史驗證：`loadRevocationJournal()` 僅載入 `ACTIVE_PINNED_ROOT` 或 `ACTIVE` 金鑰，歷史已退休金鑰簽署的合法日誌可能驗證失敗。
4. 創世鍵值完整檢查：版本 1 尚未對金鑰物件之 `publicKeyPem`、`status` 進行創世固定值比對。
- **結案要求**：驗證回退版本下限、限定可信先驗註冊表來源、保留可驗證歷史金鑰、完整檢查創世鍵值。

### R03-B03 · High：最終檔案 symlink 仍可能導致 Workspace Pollution
`resolvePluginDataDir()` 檢查目錄本身在 workspace 外，但若 `.irv-revocation-journal.jsonl` 本身是 symlink 指向 workspace 內檔案，`fs.appendFileSync()` 仍會沿著 symlink 寫入 workspace。
- **結案要求**：對最終檔案執行不追隨 symlink 的安全開檔或實體位置確認，並將 `options.workspacePaths` 納入二次檢查。

### R03-B04 · High：並發一致性與讀取鎖未封閉
寫入者持有 `journalPath` 鎖，但 `loadRevocationJournal()` 讀取端未同步取鎖，可能在日誌已附加但 Checkpoint 尚未更新的微秒間讀到不一致狀態。
- **結案要求**：採用一致性讀取快照或同一鎖協定，並定義崩潰後的提交恢復語意。

### R03-B05 · High：CASE 權威模組未納入 TCB 完整性驗證
`finalize-scan.mjs` 已將 `compact-guard.mjs` 匯入正式決策流程，但 `REQUIRED_CRITICAL_SCRIPTS` 與 `tool-integrity-manifest.json` 均未列入 `skills/3lens/scripts/compact-guard.mjs`。
- **結案要求**：將 `compact-guard.mjs`（及持久化轉接器）加入 TCB 清冊，重建完整性 Manifest，並增設防篡改測試。

### R03-B06 · High：CASE 真實生命週期防線未全面連線
正式 CLI 進入點呼叫 `finalizeScan({...})` 時未可靠傳遞 `isCompactedSession` 或 `preCompactionState`；`validateCompactedStateEnvelope()` 的 `requireSignature` 亦非無條件強制。
- **結案要求**：讓真實壓縮事件以不可自行降級的方式進入 Finalizer，在該模式下強制要求驗章與完整工具摘要。

### R03-B07 · High：合成語料出處版本與外部效度不一致
1. Clean Control 的 Base SHA `143446b…` 在該 commit 實際不存在（為本 PR 新增檔案）。
2. 全數內部合成案例不能取代 RFC 0005 Workstream 2 所承諾之外部生產環境組件驗證。
3. 凍結時間戳 `2026-11-07T18:25:00Z` 晚於 commit 時間戳（時區標示錯誤）。
- **結案要求**：校正出處 commit、內容指紋及凍結時間，並將合成語料與外部效度分開驗收。

---

## 三、發佈授權裁示

| 決策項目 | 裁示 |
| :--- | :--- |
| **修復方向** | 有實質進步 |
| **原 R02 Findings 全數關閉** | 否（2 項關閉、8 項 Partial/Open） |
| **TCB 完整性保證** | 不足 |
| **持久化反回滾保證** | 不足 |
| **CASE 生命週期強制驗證** | 不足 |
| **Layer 2 外部效度** | 未成立 |
| **PR #52 合併授權** | **`DENIED`** |
| **v1.12.0 釋出授權** | **`DENIED`** |
| **下一階段** | **Round 04 Remediation Required** |
