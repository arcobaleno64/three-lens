# Three-Lens Milestone 5.4 Phase 2 獨立第三方安全審查報告 (R01)

**審查日期**：2026-11-07  
**審查員**：Independent Third-Party AppSec Auditor (ChatGPT Pro)  
**審查裁定**：`REJECTED`（PR #52 暫不符合合併 `main` 的安全放行條件）  
**審查目標**：GitHub PR #52 (`feat/m54-phase-2-governance`)  
**審查 Head SHA**：`46c6c2f9b7bb7ad7d7acbee0cd5ab2c5b3015c83`  
**審查模式**：Read-only、冷啟動、對抗性程式碼審查  

---

## 一、審查基準與裁定概述

PR #52 在多項關鍵資安與信任機制上存在設計漏洞，可能導致未授權的偽造資料被誤判為可信狀態。經獨立審查，全數列出 10 項 Findings（2 Critical, 5 High, 3 Medium），PR #52 必須維持**禁止合併**狀態，直至所有阻擋項（Blockers）完成修復並重新覆審。

---

## 二、核心安全 Findings 清冊

### `M54-P2-F01`：撤銷日誌雜湊鏈缺乏可信驗證錨點 (Critical · Merge Blocker)
- **受影響檔案**：`scripts/adapters/plugin-data-adapter.mjs` (L296–414)
- **根本成因**：
  1. `loadRevocationJournal()` 僅驗證相鄰條目的 `entryIndex` 與 `prevEntryDigest` 雜湊鏈。
  2. `appendRevocationEntry()` 的 Ed25519 簽章為選用功能。
  3. 讀取端完全沒有實作簽章驗證與根金鑰校驗。
  4. 找不到日誌檔案時直接回傳有效的空日誌。
  5. 缺乏外部可信的日誌頭雜湊或持久化高水位計數器。
- **衝擊**：具備儲存目錄寫入權限者可直接刪除或重寫日誌，破壞「Tamper-Evident」保證。
- **修復要求**：強制要求並驗證授權簽章，將日誌頭摘要與單調版本綁定於根錨點；日誌遺失、截斷或回滾必須依已建立之歷史狀態拒絕驗證。

### `M54-P2-F02`：持久化 Registry 缺乏根信任授權驗證 (Critical · Merge Blocker)
- **受影響檔案**：`scripts/adapters/plugin-data-adapter.mjs` (L169–288)
- **根本成因**：`validateTrustRegistry()` 僅檢查結構與自簽指紋（`sha256(activePublicKeyPem) == activeKeyFingerprint`），未驗證該 Registry 是否曾獲 `EMBEDDED_ROOT_REGISTRY` 授權，未強制比對前一版的單調遞增，亦無授權簽章。
- **衝擊**：攻擊者可在 `PLUGIN_DATA` 中植入自製金鑰與指紋，構造偽造 Registry。
- **修復要求**：將嵌入式 Ed25519 根錨點用於強制驗證授權鏈；Registry 更新須包含由根錨點簽署之授權證明與防回滾機制。

### `M54-P2-F03`：路徑防污染缺乏真實路徑解析與工作目錄覆蓋 (High)
- **受影響檔案**：`scripts/adapters/plugin-data-adapter.mjs` (L125–135)
- **根本成因**：`path.resolve()` 未處理符號連結（symlink）與 Windows Junction 實體路徑別名；且指定 `options.repoRoot` 時未一併防禦 `process.cwd()`。
- **修復要求**：引入 `fs.realpathSync()` 進行實體路徑比對，並同時強制防禦 `repoRoot` 與 `process.cwd()`。

### `M54-P2-F04`：缺乏跨行程檔案互斥鎖 (High)
- **受影響檔案**：`scripts/adapters/plugin-data-adapter.mjs` (L270–288, L380–414)
- **根本成因**：`saveTrustRegistry()` 與 `appendRevocationEntry()` 無行程互斥鎖，並行審計時可能發生日誌索引衝突或 Registry 覆寫遺失。
- **修復要求**：加入跨行程檔案鎖（lockfile 機制）或重試回滾保護。

### `M54-P2-F05`：CASE 狀態未強制簽章且未驗證 persistedState 完整性 (High)
- **受影響檔案**：`skills/3lens/scripts/compact-guard.mjs` (L190–260)
- **根本成因**：簽章為可選；若未簽署，攻擊者可替換 `persistedState`（如偽造 BallotBox 票數）並重算 `stateDigest` 繞過檢查。`assertCompactSafe()` 未比對壓縮前後之 `persistedState` 內容。
- **修復要求**：強制要求有效簽章或在 `assertCompactSafe()` 中實作深層狀態不可變對比。

### `M54-P2-F06`：CASE Guard 未正式接線至 `finalize-scan.mjs` (High)
- **受影響檔案**：`skills/3lens/scripts/finalize-scan.mjs`
- **根本成因**：RFC 0005 宣告 finalizer 會強制檢查 CASE 封套，但 `finalize-scan.mjs` 目前尚未引入 `compact-guard.mjs`。
- **修復要求**：於 `finalizeScan()` 正式接入 CASE 封套驗證，驗證失敗時嚴格輸出 `UNCHECKABLE`。

### `M54-P2-F07`：外部效度語料庫存在 CVE 錯配與出處斷鏈 (High · HS-05 違規)
- **受影響檔案**：`evals/v2-corpus/layer2-external-validity-corpus.json`
- **根本成因**：
  1. `CVE-2023-38001`：宣告為 SQLi，實際 NVD 紀錄為 IBM Aspera Orchestrator CSRF。
  2. `CVE-2024-39912`：宣告為 Voucher TOCTOU，實際為 PHP WebAuthn 使用者名稱枚舉。
  3. `CVE-2023-49005`：宣告為 AWS Key，非此弱點。
  4. 部分 Commit SHA 無法在上游官方儲存庫解析。
- **修復要求**：將非真實對應案例重分類為內部測試基準（`SYNTHETIC_REGRESSION`），真實 Layer 2 案例必須全數精確對齊 NVD / 上游公開可驗證之 CVE 與 Commit。

### `M54-P2-F08`：負控制組缺乏真實外部專案特異度 (Medium)
- **受影響檔案**：`evals/v2-corpus/layer2-external-validity-corpus.json`
- **根本成因**：3 個 Clean Controls 皆引自專案自有 `evals/safe/`，未引進未修改的真實開源成熟專案模組。
- **修復要求**：引入真實開源成熟專案之乾淨模組。

### `M54-P2-F09`：推理層級節省數據外推過度與環境 toolDirty (Medium)
- **受影響檔案**：`reports/multi-tier-effort-ablation-report-2026-11.md`
- **根本成因**：僅測單一案例 `SEM-03`，且 Medium 執行時環境被標記為 `toolDirty: true`。
- **修復要求**：明確標記為 Pilot / Preliminary 觀察，釐清 `toolDirty` 標記成因。

### `M54-P2-F10`：過早宣稱 Phase 2 退出條件全數達成 (Medium)
- **受影響檔案**：`docs/rfcs/0005-milestone-5-4-phase-2-execution-roadmap.md`, `reports/...`
- **根本成因**：在 F01~F07 未修復、完整矩陣未實跑前，文件宣稱 Phase 2 Exit Gate 達成。
- **修復要求**：將狀態修正為 `IN_REMEDIATION`，退出門禁維持 `PENDING_REVIEW`。
