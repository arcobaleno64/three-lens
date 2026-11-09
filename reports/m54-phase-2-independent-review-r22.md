# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 22

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `d769b5d41ae45142e255121ccff377b15e369614`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
# Three-Lens PR #52：Round 22 獨立安全審查

REJECTED · 禁止合併

審查基準： `d769b5d41ae45142e255121ccff377b15e369614`

審查日期： 2026 年 11 月 9 日（臺灣時間）

核心裁定：R21-B01 的正常撤銷路徑已獲修補，但尚未達成 Default-Deny 要求的完整收斂。

已透過 GitHub 連線讀取指定 commit 的原始碼、測試及 CI 紀錄。本輪找到一項足以阻擋合併的新缺陷：

R22-B01：Journal 撤銷狀態讀取失敗時，程式將「無法確認撤銷」解讀為「沒有撤銷」，形成 Fail-Open 授權檢查。

這不需要破解 Ed25519。問題發生在密碼學驗證之前的信任狀態取得階段。

## 一、審查基準與已確認事項

| 項目             | 獨立核對結果                                                                           |
| -------------- | -------------------------------------------------------------------------------- |
| Repository     | `arcobaleno64/three-lens`                                                        |
| PR             | [#52](https://github.com/arcobaleno64/three-lens/pull/52?utm_source=chatgpt.com) |
| Base           | `main`                                                                           |
| Head           | `feat/m54-phase-2-governance`                                                    |
| 指定 SHA         | `d769b5d41ae45142e255121ccff377b15e369614`                                       |
| PR 狀態          | OPEN、Mergeable                                                                   |
| GitHub Actions | 兩個 Workflow Runs 均 Success                                                       |
| 審查方式           | Cold-Start、Adversarial、Read-Only                                                 |

已檢查的重要程式碼包括：

- `getJournalRevokedKeyMap()`
- `validateTrustRegistry()`
- `createAuthorizedRegistryUpdate()`
- `doLoadTrustRegistry()` 與 `saveTrustRegistry()`
- `loadRevocationJournal()` 與 `appendRevocationEntry()`

原始碼版本以指定 SHA 鎖定，不以目前分支的後續變更取代本輪證據。

## 二、新增阻擋項：R22-B01

P1 · OPEN · Revocation-State Read Failure Causes Fail-Open Authorization

### 直接程式碼證據

檔案：[plugin-data-adapter.mjs，第 1425–1452 行](https://github.com/arcobaleno64/three-lens/blob/d769b5d41ae45142e255121ccff377b15e369614/scripts/adapters/plugin-data-adapter.mjs?utm_source=chatgpt.com#L1425-L1452)

關鍵程式碼：

```
const revokedMap = new Map();

if (!fs.existsSync(journalPath)) return revokedMap;

try {
  const content = fs.readFileSync(journalPath, 'utf8');
  // ...
} catch (_) {}

return revokedMap;
```

這段程式碼有三個確定的行為：

1. Journal 不存在時，直接回傳空的 `Map`。
2. `readFileSync()` 發生讀取錯誤時，吞掉例外並回傳空的 `Map`。
3. 個別 Journal 條目無法解析時，略過該條目，繼續處理其他資料。

因此，空的 `Map` 同時代表「已確認沒有 KEY_REVOCATION」與「無法成功檢查 KEY_REVOCATION」。

這兩種狀態在安全語義上完全不同。

### 影響範圍

| 呼叫位置                                          | 實際風險                                         |
| --------------------------------------------- | -------------------------------------------- |
| `createAuthorizedRegistryUpdate()` L2210–2230 | Journal 讀取失敗後，撤銷檢查不會拒絕已撤銷簽署者                 |
| `validateTrustRegistry()` L1743、L2055–2085    | 無法取得撤銷狀態時，仍可能繼續驗證 Registry 授權簽章              |
| `saveTrustRegistry()` L3640–3655              | 寫入前的撤銷檢查使用同一個可能為空的 Map                       |
| `doLoadTrustRegistry()` L2740–2755            | 依賴 `validateTrustRegistry()`，不具備獨立且完整的撤銷狀態驗證 |

這證明 R21-B01 的新檢查存在共同的失敗模式。多個入口呼叫同一個會靜默失敗的輔助函式，並不等於建立了多道獨立防線。

必須區分：此處已由原始碼直接確認 Fail-Open 的邏輯缺陷；完整磁碟持久化及後續特權利用是否還會遭其他見證機制阻止，仍需端對端故障注入確認。不能把尚未重播的利用結果寫成已實證成功。

## 三、R22-B01 攻擊鏈與因果分析

以下攻擊以 Round 21 已採用的場景為基礎：A 原本是 ACTIVE delegated key，Root 已透過 Journal 撤銷 A，但 Registry 仍保留 A 的 ACTIVE 狀態。

攻擊路徑：Journal 讀取失敗

Journal 已撤銷 A
↓
KEY_REVOCATION(A) 已提交
↓
Journal 讀取發生 EIO / EACCES
↓
readFileSync() 拋出例外
↓
例外被吞掉，回傳空 Map
↓
關鍵 Fail-Open 缺口
↓
A 的 authorizationProof 未因撤銷遭拒
↓
仍須符合其他 Registry 與簽章檢查
↓
可能接受含 rogue key B 的 Registry
↓
端對端利用效果待故障注入驗證

關鍵之處在於，`assertMonotonicWitnessFreshness()` 主要驗證 Registry 版本、內容承諾與 HWM 單調性；其 Journal prefix 強制讀取檢查位於 HWM 超越既有見證索引的條件分支。

因此，在候選 Registry 保留既有 HWM 索引且版本遞增時，單調見證檢查不能直接視為 Journal 撤銷狀態讀取成功的證明。

參考：[Witness 驗證 L3370–3505](https://github.com/arcobaleno64/three-lens/blob/d769b5d41ae45142e255121ccff377b15e369614/scripts/adapters/plugin-data-adapter.mjs?utm_source=chatgpt.com#L3370-L3505)。

上述推導足以要求新的負向測試。其前提是攻擊者持有已撤銷的 A 私鑰，且能使 Journal 讀取失敗，同時不破壞其他必要的 Registry／見證讀寫。這些條件尚未經完整動態重播。

## 四、R21 修補覆審結果

| 項目                                | Round 22 裁定     | 原因                                       |
| --------------------------------- | --------------- | ---------------------------------------- |
| R21-B01：建立 Registry 時拒絕 revoked A | PARTIALLY HOLDS | 正常讀取下有拒絕檢查；讀取錯誤時失效                       |
| R21-B01：保存 Registry 時拒絕 revoked A | PARTIALLY HOLDS | 使用同一個可靜默失敗的撤銷查詢                          |
| R21-B01：載入非法 Registry             | PARTIALLY HOLDS | 存在額外見證防線，但撤銷狀態取得並非完整 Fail-Closed         |
| R21-B01：歷史 Registry 相容性           | HOLDS（限定範圍）     | `isHistorical` 與 HWM 條件已實作；未證明所有歷史替換均不可行 |
| R21-B02：COMMITTED WAL 乾淨程序重啟      | HOLDS（限定範圍）     | 新增測試經 CI 成功執行                            |

R21-B01 不宜標記為 `CLOSED`，應維持 `FIXED_PENDING_VERIFY`，並由 R22-B01 追蹤尚未完成的故障邊界。

### R21-B02 的限制

已讀取 [測試 L5987–6170](https://github.com/arcobaleno64/three-lens/blob/d769b5d41ae45142e255121ccff377b15e369614/tests/test-plugin-data-adapter.mjs?utm_source=chatgpt.com#L5987-L6170)。

測試確實建立 COMMITTED WAL 狀態、啟動新 Node.js 程序，確認 witness 推進、Journal 撤銷辨識與 WAL 清除。

但這是人工建立持久化狀態後的新程序恢復測試，不是實際在 COMMITTED 寫入時終止原程序或模擬斷電。能證明指定恢復路徑，不代表所有 crash window 或磁碟耐久性情境皆已驗證。

## 五、CI 與 TCB 完整性核驗

# 8/8
GitHub Checks Success

# 101/101
Adapter Tests PASS

# 121/121
SARIF Tests PASS

另已從 Ubuntu CI Job 日誌確認 Release Evidence Check 為 29/29 檔案通過。

來源：[GitHub Actions CI Run #42545967662](https://github.com/arcobaleno64/three-lens/actions/runs/42545967662?utm_source=chatgpt.com)。

本輪亦獨立對取得的固定 SHA 檔案內容重新計算 SHA-256：

| 物件                                                      | SHA-256 驗證          |
| ------------------------------------------------------- | ------------------- |
| `scripts/adapters/plugin-data-adapter.mjs`              | 符合 `020de29a…61775` |
| `skills/3lens/scripts/adapters/plugin-data-adapter.mjs` | 符合 `020de29a…61775` |
| `skills/3lens/tool-integrity-manifest.json`             | 符合 `0578c44d…20166` |
| `evals/evidence-matrix.json`                            | 已確認包含上述兩項正確摘要       |

兩份 adapter 的 Git blob SHA 亦完全一致。本輪沒有發現使用者宣告的 TCB 摘要不一致問題。

## 六、修復條件與驗收門檻

建議只針對新增阻擋項修補，不重新設計已正常運作的 Ed25519、WAL 或 Witness 架構。

1. 修正撤銷查詢的失敗語義。 Journal 不存在、無法讀取或含無效條目時，不得回傳代表安全狀態的空 `Map`；應回傳明確錯誤或拋出例外。真正全新、未建立 Journal 的情境需另外辨識。

2. 確保 Registry 授權驗證具有一致的可信撤銷狀態。 避免因驗證相依關係重新引入 Registry／Journal 遞迴鎖定；使用受治理鎖保護且可驗證的資料快照。

3. 新增 EIO、EACCES、Journal 缺失及 malformed JSON 故障注入。 對 `createAuthorizedRegistryUpdate()`、`validateTrustRegistry()`、`saveTrustRegistry()` 與 `loadTrustRegistry()` 分別確認拒絕結果。

4. 進行端對端 A → v3 → B 負向重播。 在保留原有 HWM 與雙見證的條件下，使撤銷狀態查詢失敗，確認 B 無法取得任何有效治理權威，包括 Registry 授權與 Journal 追加。

5. 以新程序再次驗證修復結果。 確認修復不破壞撤銷前歷史 Registry 的合法驗證、正常 COMMITTED WAL 恢復與見證單調性。

關閉 R22-B01 所需的關鍵觀察，是所有受影響授權入口在 Journal 讀取失敗時均拒絕使用撤銷狀態不明的金鑰，而且沒有可利用的替代授權路徑。

## 七、Round 22 正式裁定

## REJECTED

Blocking P1

禁止合併 PR #52。

決定性阻擋項：`R22-B01`

`getJournalRevokedKeyMap()` 對 Journal 讀取失敗採取 Fail-Open 處理，使撤銷權威無法在所有錯誤路徑維持 Default-Deny。

CI 與檔案完整性驗證均通過，但不足以消除已發現的授權邏輯缺陷。

裁定僅適用於 commit d769b5d41ae45142e255121ccff377b15e369614。未對 GitHub 提交 Review、修改檔案或執行合併。

### 不確定清單

- 未查證： 未獨立執行完整 Node.js 原始測試套件；未完成 Journal EIO/EACCES 下的完整端對端攻擊重播。
- 預設： 攻擊者掌握已撤銷 A 的私鑰，並具備在受限情境下干擾 Journal 讀取的能力，不掌握 Root 私鑰。
- 推測： 若現有其他安全控制在所有 Journal 讀取失敗情境下，仍能阻止 Registry 授權被接受，R22-B01 的實際利用影響可下修；但輔助函式的 Fail-Open 行為本身仍須修正。

下一步（2 分鐘內）： 在 PR #52 的修復追蹤紀錄中新增 `R22-B01 · P1 · OPEN`，附上 [L1425–1452 原始碼](https://github.com/arcobaleno64/three-lens/blob/d769b5d41ae45142e255121ccff377b15e369614/scripts/adapters/plugin-data-adapter.mjs?utm_source=chatgpt.com#L1425-L1452)，並維持 PR OPEN、不合併。
```
