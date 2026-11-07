# Milestone 5.4 Phase 2 Round 07 Independent Review Report

- **Date**: 2026-11-07
- **Target Pull Request**: [#52 (arcobaleno64/three-lens)](https://github.com/arcobaleno64/three-lens/pull/52)
- **Branch**: `feat/m54-phase-2-governance`
- **Reviewed Head Commit**: `80eeec495f1ce19509d27009720b753b09210221`
- **Auditor Persona**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (Cold-Start Default-Deny via ChatGPT Pro with High Reasoning Effort)
- **Auditor Final Verdict**: `REJECTED` (2 P1 Critical Blockers, 4 P2 High Blockers)
- **CI Status**: PASS across all runners (Ubuntu, macOS, Windows), CodeQL, Semgrep on Run `42382105453` and `42382100687`.

---

## 1. Executive Summary & Verdict

The independent auditor performed a rigorous, cold-start review of commit `80eeec495f1ce19509d27009720b753b09210221` on PR #52.
While verifying that all GitHub Actions CI workflows passed and shallow clone issues were resolved (R05-B06 APPROVED), the auditor identified 2 P1 Critical and 4 P2 High architectural blockers that require deterministic remediation under Default-Deny:

1. **F-01 (P1 · Critical)**: Genesis Replay Combination Attack via Full History Deletion (`history/` directory deletion allows bare Genesis v1 replay).
2. **F-02 (P1 · Critical)**: CASE `toolManifestDigest` Authority Confusion in `finalizeScan.mjs` (unauthenticated `preCompactionState` can override `effectiveToolProvenance`).
3. **F-03 (P2 · High)**: Multi-File Transaction Rollback lacks Crash Recovery & Test did not enter transaction body.
4. **F-04 (P2 · High)**: Cross-Lock TOCTOU between Journal Lock and Registry Lock (separate lock files instead of unified governance lock).
5. **F-05 (P2 · High)**: Layer 2 External Validity Corpus Commit Binding Discrepancy (L2-08 fixture content diverged from declared commit SHA without blob verification).
6. **F-06 (P1 · Critical)**: Unauthenticated Pre-Compaction State can obtain `VERIFIED` without cryptographic signature; `signedBy` omitted from CASE signature payload.
7. **F-07 (P2 · High)**: Silent catch block on `--compact-envelope` parsing failure allows fail-open downgrade.

---

## 2. Full Independent Review Transcript

```markdown
本輪採取嚴格的 Default-Deny 裁定：CI 全綠、單元測試全數通過，以及修補說明完整，都不能單獨構成安全核准的依據。

審查的核心是驗證攻擊者能否透過多檔案回滾、歷史信任狀態替換、簽章降級、金鑰生命週期混淆及交易中斷，重新取得系統已撤銷或未授予的權限。

本次只針對指定的 commit `80eeec495f1ce19509d27009720b753b09210221` 裁定，不把其他 commit 的修補成果混入本輪證據。

## 一、審查基準確認

| 項目 | 查核結果 |
| --- | --- |
| Repository | `arcobaleno64/three-lens` |
| PR | #52 |
| Branch | `feat/m54-phase-2-governance` |
| PR Head SHA | `80eeec495f1ce19509d27009720b753b09210221` |
| 指定審查 SHA | 完全一致 |
| PR 狀態 | OPEN |
| Changed Files | 27 |
| Mergeable | GitHub 回報 TRUE |

## 二、已確認的殘留攻擊面

### F-01：Genesis Replay 仍存在完整歷史錨點刪除繞過
P1 · Critical
位置：`scripts/adapters/plugin-data-adapter.mjs`

修補確實增加了同版本歷史 HWM 比對、跨版本最高 HWM 比對，以及 Journal 與 Checkpoint 遺失偵測。
但歷史紀錄、Journal、Checkpoint 與 Trust Registry 全部位於同一個可寫入的 `PLUGIN_DATA` 儲存區。
目前的防護依賴 `history/` 尚存。當攻擊者能修改持久化治理檔案時，若同時刪除 `history/`，再放回合法的 Genesis v1，程式就失去辨識先前撤銷狀態的歷史依據。
原因在於：
1. `loadTrustRegistry()` 只有在 `history/` 存在時才掃描歷史紀錄。
2. `highestHistHwmIndex` 初始值為 `-1`。
3. 歷史目錄不存在時，不會觸發歷史 HWM 回滾檢查。
4. 若 Journal 與 Checkpoint 也不存在，Genesis v1 仍可能通過後續驗證。

### F-02：CASE 的 Tool Manifest Digest 仍可被未可信的 Pre-Compaction State 覆蓋
P1 · Critical
位置：`skills/3lens/scripts/finalize-scan.mjs:2981–2990`

目前程式：
```javascript
toolManifestDigest:
  compactOptions?.expectedToolManifestDigest ||
  preCompactionState?.toolManifestDigest ||
  effectiveToolProvenance?.toolIntegrityDigest ||
  null
```
這個優先順序存在權威混淆。假設 `preCompactionState.toolManifestDigest = "forged"`，`effectiveToolProvenance.toolIntegrityDigest = "trusted"`，實際採用的預期值會是 `forged`，而不是 `trusted`。
正確方向應是：
- 可信工具來源決定預期 Digest。
- Pre-Compaction State 只能提供待驗證值，不能決定可信基準。
- 兩者不一致時必須回報 UNCHECKABLE。

### F-03：多檔案交易回滾沒有達到宣稱的原子性
P2 · High
位置：`scripts/adapters/plugin-data-adapter.mjs:1854–1935`

第一，Rollback 是 Best-Effort，不是原子交易。Catch 區塊使用一般 `fs.writeFileSync()` 恢復檔案，並且把復原過程的例外直接吞掉 (`catch (_) {}`)。缺少 WAL / Crash Recovery。
第二，現有回滾測試在載入 Registry 時就拋出錯誤（測試先把 Registry 檔案替換成目錄），失敗發生在 Journal Append 之前，沒有真正進入交易區段。

### F-04：Journal Lock 與 Registry Lock 沒有形成共同交易鎖
P2 · High
位置：`plugin-data-adapter.mjs:1313–1319`, `1754–1769`, `1900–1903`

`saveTrustRegistry()` 鎖定 Registry 路徑，而 `appendRevocationEntry()` 鎖定 Journal 路徑，卻在交易中直接寫入 Registry。這形成兩個不同的互斥範圍，存在跨行程 TOCTOU 競爭風險。

### F-05：Layer 2 固定版語料庫的 Commit 綁定不成立
P2 · High
目前 PR 的修補版 fixture（`evals/oss-corpus/post-fix/01-minimist-prototype-pollution.js`）過濾了 `constructor` 與 `prototype`，但語料庫 L2-08 宣告的歷史 commitSha 為 `eddd0c38875c356fd20530b2e19cd12734d50155`，該 commit 當時並未包含這些過濾。Validator 僅使用 `git cat-file -e` 檢查檔案存在，未驗證內容與 Blob SHA。

### F-06：未驗證的 Pre-Compaction State 可以直接取得 VERIFIED
P1 · Critical
位置：`skills/3lens/scripts/finalize-scan.mjs:5274–5282` & `compact-guard.mjs`

CLI 從 `scratch/pre-compaction-state.json` 讀取未簽章狀態，未要求簽章時即可得到 `VERIFIED`。此外，`createCompactedStateEnvelope()` 的 `signedBy` 並未納入簽章內容。

### F-07：指定 CASE 檔案解析失敗可能被靜默忽略
P2 · High
位置：`finalize-scan.mjs:5263–5272`

`try { compactedAuditEnvelope = JSON.parse(fs.readFileSync(compactEnvelopePathArg, 'utf8')); } catch {}` 在解析失敗時直接保留 `null`，使明確指定 `--compact-envelope` 的調用靜默降級為一般掃描。
```
