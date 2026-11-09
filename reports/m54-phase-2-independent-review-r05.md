# Three-Lens PR #52：Round 05 獨立 AppSec 對抗性覆審

REJECTED｜發布阻擋審查日期： 2026-11-07（臺灣時間）
審查模式： 唯讀、冷啟動、對抗性原始碼審查
審查基準： NIST SSDF SP 800-218、Default-Deny Invariant、Zero Workspace Pollution

| 項目 | 核對結果 |
| --- | --- |
| Repository | `arcobaleno64/three-lens` |
| PR | [#52](https://github.com/arcobaleno64/three-lens/pull/52) |
| Base | `143446bb932787cd64577135975fe1bdb73b52fe` |
| R04 | `f5093885d6fca1070a146a029d54b6601427b217` |
| R05 Head | `fb17447d18bb2223b971c7f6c058542d8ef0d756` |
| R04 → R05 | 1 個 Commit、11 個變更檔案 |
| Base → R05 | 11 個 Commits、20 個變更檔案 |

核心裁定：R04-B01 尚未真正閉合。 撤銷高水位雖然新增到信任註冊表，卻沒有受到密碼學完整性保護。具備相關儲存檔案寫入能力的攻擊者，仍可移除高水位，再刪除撤銷日誌及 checkpoint，使既有撤銷歷史被視為空白。

這直接違反本 PR 宣稱的撤銷不可回滾安全性質。即使其他測試全部通過，也不足以核准合併或發布 `v1.12.0`。

以下逐項區分已由原始碼證實的問題、需要反例驗證的風險，以及尚未完成的驗證工作。

## 一、Round 05 安全缺失登錄

以下缺失依指定 Commit 的實際原始碼判定。反例區分「已確認的邏輯缺口」與「尚待動態重現的競爭條件」，不將推導冒充實測。

| Finding ID | 嚴重度 | 缺失 | 裁定 |
| --- | --- | --- | --- |
| R05-B01 | Critical | 撤銷高水位未納入簽章，可被移除後清除撤銷歷史 | OPEN |
| R05-B02 | Critical | 註冊表回退與授權鏈連續性依賴選用參數 | OPEN |
| R05-B03 | High | 撤銷追加的多檔提交不具原子性，註冊表寫入失敗可能被吞掉 | OPEN |
| R05-B04 | High | 檔案鎖無法消除外部攻擊者造成的 Symlink TOCTOU | OPEN |
| R05-B05 | High | CASE 預設可接受未簽章封套，缺少可信前態時可重新計算摘要 | OPEN |
| R05-B06 | High（治理） | Synthetic Corpus 尚不符合 RFC 原訂外部效度驗收條件 | OPEN |

### R05-B01：撤銷高水位缺乏不可竄改保護

受影響檔案： `scripts/adapters/plugin-data-adapter.mjs`

關鍵位置：
- L397–416：`computeRegistryAuthorizationPayload`
- L530–548：可選的 `revocationHighWaterMark`
- L959–981：日誌遺失判斷

`computeRegistryAuthorizationPayload()` 未將 `revocationHighWaterMark` 納入簽章資料，因此修改或刪除此欄位不會破壞註冊表原有的授權簽章。

`validateTrustRegistry()` 只在該欄位存在時檢查格式，未要求曾建立過高水位的註冊表持續保有高水位。

在缺少外部可信錨點的情況下，攻擊者可採取下列步驟：
1. 建立有效撤銷紀錄。
2. 從信任註冊表刪除 `revocationHighWaterMark`。
3. 刪除撤銷日誌與 checkpoint。
4. 重新呼叫預設的 `isRevoked()`。

原本已撤銷的 ID 可能被誤判為未撤銷。

要求修補：將 `revocationHighWaterMark` 納入簽章授權有效負載 (`computeRegistryAuthorizationPayload`)，或使用專屬授權子簽章；在更新高水位時必須以有效密鑰重新簽署註冊表。若高水位曾經存在，後續載入必須強制要求存在且版本單調不降。

### R05-B02：版本單調性與祖先鏈驗證尚非預設強制

受影響檔案： `scripts/adapters/plugin-data-adapter.mjs`

- `validateTrustRegistry` 的連續版本驗證需要 `options.priorRegistry`；沒有前版時，只有 `requirePriorRegistry === true` 才強制拒絕。
- `loadTrustRegistry` 預設並未提供可信前版，也未要求持久化註冊表必須存在。
- 反例 A：版本跳躍（直接載入 v3 跳過 v2）。
- 反例 B：註冊表遺失回退至內嵌 v1，撤銷狀態遺失。
- `cryptographicValidity` 在某些提前返回路徑回報 `true`，即使當次尚未執行簽章驗證。應區分「已驗證有效」與「尚未驗證」。

要求修補：將持久化版本與授權鏈的可信基準納入強制驗證，明確區分首次初始化與既有安裝，不可讓呼叫者遺漏選用參數就解除反回滾要求。

### R05-B03：註冊表高水位提交失敗可能仍回報成功

受影響檔案： `scripts/adapters/plugin-data-adapter.mjs`

- `appendRevocationEntry` L1277–1281: `catch (regErr)` 只重拋包含 `_VIOLATION` 的錯誤，忽略其他錯誤（例如 `EACCES`、`ENOSPC`）。
- 寫入日誌、更新 Checkpoint、更新註冊表高水位的非原子多步提交中，高水位寫入失敗必須明確 fail-closed。若高水位無法持久化，必須拒絕該次撤銷追加並回滾或宣告失敗。

要求修補：高水位提交失敗必須明確 fail-closed；建立可恢復的提交狀態，並透過故障注入驗證每個寫入階段遭中斷後都不會遺失撤銷權威。

### R05-B04：檔案鎖無法消除外部攻擊者造成的 Symlink TOCTOU

受影響檔案： `scripts/adapters/plugin-data-adapter.mjs`

- 檔案鎖是協作式的。具備相關目錄寫入權限的外部程序不必遵守該 `.lock`。
- 開檔流程應使用不跟隨符號連結的開檔方式（例如 POSIX `O_NOFOLLOW` / `fs.constants.O_NOFOLLOW`，Node.js `fs.openSync` 支援 flags 如 `'ax+'` 或 descriptor 驗證）與檔案描述元身分驗證，對 Windows reparse point 另行設計等效控制。不得以取得 `.lock` 作為排除所有外部 TOCTOU 的證明。

要求修補：使用不跟隨 Symlink 的開檔方式與檔案描述元身分驗證，對 Windows reparse point 另行設計等效控制。

### R05-B05：CASE 缺少必要的可信完整性基準

受影響檔案：
- `skills/3lens/scripts/compact-guard.mjs`
- `skills/3lens/scripts/finalize-scan.mjs`

- `requireSignature` 預設非強制。若封套未包含簽章，且 `preCompactionState` 缺席時，驗證只剩封套內部摘要一致性，並不能證明內容相對壓縮前未變。
- 要求修補：在權威驗證模式要求可信簽章或可信前態；未能建立壓縮前狀態與封套的來源連續性時，維持 `UNCHECKABLE`，不得宣告 `VERIFIED`。

### R05-B06：外部效度驗收規格與實際資料集不一致

- 實際資料集為 11 個 `SYNTHETIC_REGRESSION` 與 3 個 `SYNTHETIC_CLEAN_CONTROL`，尚無 `UPSTREAM_VERIFIED_OSS`。
- 要求修補：對 RFC 0005 外部效度門檻完成實證或正式修訂驗收規格，並把新增安全測試 (`test:plugin-data`, `test:compact`, `validate:v2-corpus`) 納入 CI (`.github/workflows/ci.yml`)。

## 二、Round 04 六項缺失覆審結果

| R04 Finding | R05 判定 | 原因 |
| --- | --- | --- |
| R04-B01 | PARTIALLY HOLDS | 原雙檔刪除測試成立，但高水位可被取消 |
| R04-B02 | PARTIALLY HOLDS | 明確提供前版時有效，預設載入仍有漏洞 |
| R04-B03 | PARTIALLY HOLDS | 懸空 Symlink、Hard Link 靜態檢查改善，競爭窗口未封閉 |
| R04-B04 | PARTIALLY HOLDS | 必要摘要與 CLI 接線已具備，權威完整性不足 |
| R04-B05 | CLOSED（限定範圍） | 首次建立日誌時，預設讀取確實取得相同鎖 |
| R04-B06 | CLOSED（技術出處） | 14/14 Git Tree Blob、Commit 與時間已核對 |

## 三、CI 與測試證據

- `npm test`: CI Success
- `npm run check:release`: CI Success
- `npm run check:docs`: CI Success
- 缺失：新安全測試未納入 PR CI 工作流程（`test:plugin-data`, `test:compact`, `validate:v2-corpus`）。

## 四、正式審查裁示與放行條件

Round 05 Decision：REJECTED
禁止合併至 `main` 或發布 `v1.12.0`。
