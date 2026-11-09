# Milestone 5.5 Independent Architecture & AppSec Review R07

**Date**: `2026-11-10T02:29:00Z`  
**Reviewer**: ChatGPT Pro (Independent Reviewer via MCP Bridge)  
**Target Package**: `@arcobaleno64/three-lens`  
**Target Commit**: `c16bd0eaddc1d38eb269f793f0457a52daac8650` (HEAD of `feat/v1.13.0-dev`)  
**Parent Commits**: `b2e8c566ca352b955457a9e5048f682ca67bf3c5`, `d3a029f433b7fa7c7a3dcf5f6ac5c36e7de791f6`  
**Verdict**: **NOT APPROVED / REJECTED (MILESTONE ACCEPTANCE REJECTED)**  

---

## 1. Summary of Determinations

| Finding | Severity | Core Defect |
| :--- | :--- | :--- |
| **R07-F01** | **HIGH (Blocker)** | Finding Cryptographic Payload Binding: Payload only signed `id:ruleId:severity:disposition:signedBy`. Modifying `location`, `title`, or `ballots` didn't invalidate signature. |
| **R07-F02** | **MEDIUM** | Trusted Root Override Boundary: `options.trustedRootPublicKeyPem` allowed untrusted callers to supply their own root key. |
| **R07-F03** | **HIGH (Blocker)** | ACP v1 Protocol Conformance: `...update` could overwrite `content`; `progress` is not standard ACP v1 session update; `session/new` lifecycle. |
| **R07-F04** | **HIGH (Blocker)** | Turn Token Validation Gap: Missing `turnId` or future `turnId` bypassed generation checks. |
| **R07-F05** | **HIGH (Blocker)** | Realpath Lexical Fallback Symlink Escape: Non-existent parent fell back to lexical path without verifying symlinks on existing ancestors. |
| **R07-F06** | **HIGH (Blocker)** | Dangling Symlink Write Escape: `fs.existsSync` returns false for dangling symlinks, skipping `lstatSync`, allowing writes through dangling symlinks to external locations. |
| **R07-F07** | **HIGH (Blocker)** | Safe Purge Identity Binding OR Logic: Used `isHarnessOwned` with `||` logic instead of mandatory AND verification of marker and remote. |

---

## 2. Review Transcript Receipt

```markdown
審查基準： c16bd0eaddc1d38eb269f793f0457a52daac8650
目標分支： feat/v1.13.0-dev
審查模式： Cold-Start / Adversarial / Evidence-Bound / Read-Only
審查日期： 2026-11-10（臺灣時間）

裁定：NOT APPROVED / REJECTED

主要缺失：
1. R07-F01 (HIGH): authorityProof 簽章內容僅涵蓋 id:ruleId:severity:disposition:signedBy，未涵蓋 title, location, ballots 雜湊，導致合法簽章可移植至經竄改的 Finding。
2. R07-F02 (MEDIUM): options.trustedRootPublicKeyPem 容許呼叫端任意指定信任金鑰。
3. R07-F03 (HIGH): session/update 格式需嚴格符合 ACP v1 規範，不可由 ...update 任意覆寫正規化欄位。
4. R07-F04 (HIGH): Turn Token 檢查在未傳入 turnId 或傳入未來世代 turnId 時存在放行缺口。
5. R07-F05 (HIGH): Harness 實體路徑回退邏輯在目錄尚未建立時直接使用 path.resolve，容許經由現存父層 symlink 逸出。
6. R07-F06 (HIGH): adm-zip 提取中，fs.existsSync 對 dangling symlink 回傳 false，導致 lstat 被略過，隨後於沙盒外建立檔案。
7. R07-F07 (HIGH): safePurgeHarnessTarget 所有權判斷採用 OR 邏輯，未強制同時驗證 Marker 與 Git Config。
```
