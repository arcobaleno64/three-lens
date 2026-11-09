# Three-Lens Milestone 5.4 Phase 2 獨立第三方安全覆審報告 (Round 02)

**審查日期**：2026-11-07  
**審查員**：Independent Third-Party AppSec Auditor (ChatGPT Pro · High Reasoning Effort)  
**審查裁定**：`REJECTED`（PR #52 仍存在阻擋合併之核心安全缺陷，維持禁止合併）  
**審查目標**：GitHub PR #52 (`feat/m54-phase-2-governance`)  
**審查 Head SHA**：`a4d49e160c98f3fd9f5135a6551689ce95311c06`  
**比對 Base SHA**：`143446bb932787cd64577135975fe1bdb73b52fe` (`v1.11.0`)  
**審查模式**：Read-only、冷啟動、對抗性程式碼審查 (High Reasoning Depth)  

---

## 審查裁定概述

正式裁定：`REJECTED`。PR #52 在指定 Commit `a4d49e160c98f3fd9f5135a6551689ce95311c06` 仍存在阻擋合併的安全缺陷。

實際程式碼中仍有可辨識的信任驗證繞過路徑：
1. **Registry 信任根繞過 (F02 · Critical)**：`validateTrustRegistry()` 在缺乏 `priorRegistry` 時從當前 Registry 自身 `keys` 尋找驗章公鑰，形成循環自簽認證；且 Version 1 未約束 `keys` 清單必須與內嵌創世根完全一致，攻擊者可注入未授權的 `ACTIVE` 金鑰。
2. **撤銷日誌簽章與防回滾邊界 (F01 · Critical)**：簽章僅涵蓋 `targetId:entryIndex:prevEntryDigest`，未納入 `revocationType`、`reason`、`signedBy` 等關鍵欄位；Checkpoint 與 Journal 位於同目錄無獨立防回滾錨點，且解析錯誤時被空 `catch {}` 忽略。
3. **CASE 簽章驗章空轉 (F05 · High)**：當 `requireSignature=true` 但未提供 `verifierPublicKey` 時，程式僅檢查簽章字串存在即放行，未執行真正的密碼學驗章。
4. **CASE 接線條件式跳過 (F06 · High)**：`finalizeScan()` 僅在主動傳入封套時驗證，且 `compactGate = !compactGuardResult || compactGuardResult.valid === true` 允許無封套呼叫直接通過，未與掃描會話真實生命週期綁定。
5. **外部效度語料庫與出處斷鏈 (F07/F08 · High/Medium)**：部分 CVE 漏洞機制與實體程式碼不符（node-tar CVE-2021-32803 是 symlink/目錄快取繞過，非純 ../ 拼接；axios CVE-2020-28168 是 Proxy redirect SSRF，非跨來源 header 洩漏）；短 commit SHA 在官方上游無法檢索；Clean controls 屬自製包裝函式非上游原始碼。
6. **治理狀態 (F10 · Medium)**：已將 RFC 0005 與報告修正為 `IN_REMEDIATION` / `PENDING_REVIEW`，本項 **CLOSED**。

---

## F01～F10 覆審狀態總表

| Finding | 原嚴重度 | R02 狀態 | 核心成因與修復要求 |
| :--- | :--- | :--- | :--- |
| **`M54-P2-F01`** | Critical | **OPEN** | 簽章須覆蓋整筆規範化紀錄；Checkpoint 損壞/遺失不得靜默退回；需獨立錨點 |
| **`M54-P2-F02`** | Critical | **OPEN** | v1 keys 須嚴格等於創世金鑰；v>1 驗章公鑰必須源自已驗證之信任根/先驗版本，禁止自簽取鑰 |
| **`M54-P2-F03`** | High | **PARTIAL** | 補齊不存在的中間目錄解析、建立後二次真實路徑確認與大小寫別名防禦 |
| **`M54-P2-F04`** | High | **PARTIAL** | 補齊持有者存活確認（PID probe）與多行程並發競爭測試 |
| **`M54-P2-F05`** | High | **OPEN** | `requireSignature=true` 時強制要求 `verifierPublicKey`，缺一不可 |
| **`M54-P2-F06`** | High | **OPEN** | 將 CASE 要求綁定至掃描會話生命週期，且由 finalizer 傳入可信狀態比對 |
| **`M54-P2-F07`** | High | **OPEN** | 漏洞語意與 CVE 正確對齊；真實 OSS 案例出處提供完整可解析之 40-char commit SHA |
| **`M54-P2-F08`** | Medium | **OPEN** | 負控制組誠實分類為內部基準或引入完全未修改之上游檔案 |
| **`M54-P2-F09`** | Medium | **PARTIAL** | 已限定為單一 Pilot 觀察；需進一步對齊環境等價性與工具調用差異 |
| **`M54-P2-F10`** | Medium | **CLOSED** | RFC 0005 與報告已正確認定為 `IN_REMEDIATION`，退出門禁為 `PENDING_REVIEW` |
