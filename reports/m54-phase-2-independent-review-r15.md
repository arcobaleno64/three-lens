# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 15

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `3042f0807dda02ce2a7c7e66121d7f953c0bb8a9`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 15 獨立安全審查
Default-Deny · 禁止預先核准

審查日期： 2026-11-08（臺灣時間）
審查基準： 3042f0807dda02ce2a7c7e66121d7f953c0bb8a9
審查模式： Cold-Start / Adversarial / Evidence-Bound
權限範圍： 唯讀，不修改儲存庫、不提交 PR Review、不執行合併。

已透過 GitHub 核對：

PR #52 目前為 OPEN，merged=false，mergeable=true。

PR 指向 main，Head SHA 與指定審查版本完全一致。

指定 Commit 的提交說明及差異包含 R14-B01～B09 的修補。

GitHub Actions 的 Pull Request CI 與 Semgrep 已確認為 SUCCESS。

證據：PR #52 · 固定審查 Commit

這些結果確認了審查對象及部分自動化檢查狀態，尚不構成任何 Critical Finding 的安全結案證明。

第一部分：已確認的主要阻擋缺陷
R15-B01 · Critical：同索引、不同雜湊的防回滾檢查未在正式讀取路徑生效
BLOCKING · 原始碼直接證實

受影響檔案： scripts/adapters/plugin-data-adapter.mjs

在第 2470 行附近的 assertMonotonicWitnessFreshness()，新的分岔防護要求同時取得：

JavaScript
candidateHwmHeadIndex
candidateHwmHeadDigest

但 doLoadTrustRegistry() 第 2160～2170 行仍呼叫：

JavaScript
assertMonotonicWitnessFreshness(
  dir, parsed.registryVersion, currentHwmIdx, options
);
updateMonotonicWitness(
  dir, parsed.registryVersion, currentHwmIdx
);

其中第四個參數 options 被函式當成選項物件，而不是實際候選 headDigest。因此，當版本及索引不變，但候選 HWM Digest 改變時，這個讀取路徑不會執行預期的分岔比較。

doLoadRevocationJournal() 也有相同模式。更重要的是，讀取成功後的見證更新同樣未提供 Digest。

影響： R14-B07 宣稱的「相同索引、不同 Digest 必然拒絕」不成立。這不是單純漏寫測試，而是正式資料流沒有把必要欄位傳到安全檢查函式。

在攻擊者能修改治理檔案，且具備可簽署替代歷史狀態的金鑰之條件下，此缺口可能使分岔狀態通過新鮮度檢查。是否能完整重新取得特權，仍須結合 Registry、History、Journal 的簽章路徑驗證。

推翻條件： 找出指定 Commit 中另一條必經、以可信見證 Digest 比對候選 Digest 的正式讀取路徑，並重播同索引分岔攻擊證明必然被拒絕。

原始碼：正式載入路徑 · 見證比較函式

R15-B02 · Critical：COMMITTED WAL 復原仍存在「先清除標記、後更新見證」窗口

受影響函式： _recoverAbortedRevocationTransactionInner()

R14-B05 修正了 appendRevocationEntry() 正常提交的順序：

純文字
COMMITTED WAL
    ↓
updateMonotonicWitness()
    ↓
刪除 WAL

但同一份程式的 COMMITTED 復原分支，在驗證 Journal Tail 後，直接執行：

JavaScript
fs.unlinkSync(txnPath);
return {
  recovered: false,
  committed: true,
  txnId: txnData.txnId
};

該分支沒有先呼叫 updateMonotonicWitness()。

攻擊窗口如下：

交易的 Registry、Checkpoint、Journal 已寫入，WAL 已標為 COMMITTED。

在更新外部單調見證之前，程序中斷。

新程序呼叫 recoverAbortedRevocationTransaction()，驗證後刪除 WAL。

若此時再次中斷，最新已提交狀態可能仍未記入持久化見證。

攻擊者在這個窗口還原較舊且仍有合法簽章的治理狀態，存在通過舊見證檢查的風險。

這與 R14-B05 原本要消除的失效模式相同，只是入口從正常提交轉移到復原程序。

裁定： R14-B05 不得結案；COMMITTED 復原必須在刪除最後一份可恢復交易證據前，確保持久化見證涵蓋已提交的新狀態。

推翻條件： 證明 COMMITTED WAL 復原必經另一項先完成 fsync 的見證更新，而且不存在獨立呼叫復原函式後就返回的路徑。目前公開的復原函式不符合這個條件。

原始碼：COMMITTED WAL 復原 · 正常提交路徑

R15-B03 · Critical：相同 Registry Version 的歷史權威分岔仍可重新取得授權

這是比單純 HWM Digest 遺漏更根本的問題。

computeRegistryAuthorizationPayload()（第 1165～1186 行）確實涵蓋 Registry 的金鑰陣列、金鑰狀態及授權身分。但持久化見證只記錄最高 registryVersion，沒有綁定該版本的 Registry 內容雜湊。

validateTrustRegistry() 驗證版本 2 的授權簽章時，使用版本 1 中處於 ACTIVE 的簽署者。它沒有可信的不可回溯時間證據，證明該簽章必定是在金鑰退休之前產生。

這產生以下具體的條件式攻擊：

同版本權威替換攻擊鏈

合法狀態為 Registry v2，原始 Root A 已退休，Root B 為 ACTIVE；見證記錄最高版本 2。
攻擊者取得已退休 Root A 的私鑰，保留合法的 v1 歷史狀態。
以 Root A 重新簽署另一份 Registry v2，將攻擊者控制的 Key C 設為 ACTIVE。

同步替換磁碟 Registry 與 history/trust-registry.v2.json，維持版本 2；在尚無 Journal HWM 的情境下，見證索引也維持 -1。

驗證器仍可從 v1 的 Root A 推導出有效的 v2 授權簽章，而版本型見證無法區分原始 v2 與偽造 v2。

安全後果： 在上述威脅前提下，攻擊者不需要破解 Ed25519，也不需要取得現役 Root B 的私鑰，就可能以事後取得的退休私鑰重新製造一條同版本、不同授權內容的歷史分支。

這是由原始碼驗證規則推導的攻擊鏈，尚未完成直接執行原始 Adapter 的端到端重播，不能冒稱為已實際成功入侵。但目前也沒有看到足以否定這條攻擊鏈的可信 Registry 內容錨點。

修復要求： 持久化見證不能只釘住最高 Registry Version，還必須釘住該版本的完整權威內容承諾，例如 Canonical Registry Digest，並對相同版本但不同 Digest 採 Default-Deny。還必須明確定義外部見證本身的不可回滾信任假設。

推翻條件： 證明已存在一個不受攻擊者改寫、且正式載入必定驗證的 Registry v2 唯一內容承諾，可以拒絕 Root A 事後重新簽署的替代版本。

原始碼：Registry 授權 Payload · 歷史簽署者驗證 · 見證資料模型

R15-B04 · High：見證格式驗證不完整，公開寫入介面仍存在

getMonotonicWitness() 對見證檔案的驗證，主要檢查 JSON 是否可解析，以及解析結果是否為物件。

例如，以下內容仍可通過這個初步檢查：

JSON
{}

由於 maxSeenRegistryVersion、maxSeenHwmHeadIndex、maxSeenHwmHeadDigest 都不是強制欄位，結構不完整的見證可能被當成有效資料處理。

另外，移除 resetMonotonicWitnessForTest() 不等於消除所有公開修改入口：

safeOpenStorageFile() 仍公開匯出，且支援具有 O_TRUNC 效果的寫入模式。

safeWriteFileSync() 也公開匯出，接受呼叫端指定的目標路徑及內容。

外部見證位於使用者主目錄下，尚未證明具備不受相同權限攻擊者改寫的保護。

這不代表任何遠端使用者都能修改見證。實際風險取決於攻擊者的檔案系統權限。但在 R14-B02 原本採用的「惡意模組呼叫端」威脅模型下，移除單一函式名稱無法建立安全邊界。

證據：儲存寫入介面 · 見證解析

R15-B05 · Medium：檔案鎖的 TOCTOU 與權限聲明仍未完全成立

withFileLock() 釋放時採用：

純文字
fstatSync(lockFd)
  → lstatSync(lockFile)
  → 再次 lstatSync(lockFile)
  → unlinkSync(lockFile)

最後一次檢查與 unlinkSync() 仍是兩個獨立操作。因此，不能宣稱對具有目錄修改權限的並行攻擊者，已經從原理上消除所有 TOCTOU 競爭。

另外，鎖檔建立使用：

JavaScript
fs.openSync(lockFile, 'wx+')

沒有明確指定 0o600。

獨立 Node.js v22.16.0 實測，在 umask=022 時建立的檔案權限是 0644，不是聲明中的 0600。這不必然導致權限提升，但足以推翻「固定採用 0o600 DAC」的敘述。

證據：withFileLock

第二部分：R14-B01～B09 完整覆審矩陣

原阻擋項

	

Round 15 判定

	

結案意見




R14-B01 · ALS 生命週期

	

HOLDS（限縮範圍）

	

active=false 修正已存在；非同步回呼防護已加入




R14-B02 · 見證重設入口

	

REOPENED

	

指定重設 API 已移除，但公開寫入介面仍可修改見證




R14-B03 · WAL 快照驗證

	

PARTIALLY HOLDS

	

快照語意綁定已加入；目前 Registry 缺少簽署者時，仍可能進入內建根金鑰回退路徑




R14-B04 · 退休金鑰權限

	

REOPENED

	

歷史 Registry 同版本替換及 HWM 歷史承襲仍有攻擊空間




R14-B05 · WAL 見證順序

	

REOPENED

	

正常提交已改善，COMMITTED 復原未完成相同保證




R14-B06 · 見證 Fail-Closed

	

REOPENED

	

JSON 語法損毀會拒絕，結構不完整未必拒絕




R14-B07 · Digest 分岔

	

REOPENED

	

正式載入路徑缺少候選 Digest 傳遞




R14-B08 · WAL 尾部驗簽

	

PARTIALLY HOLDS

	

尾部 Ed25519 驗簽已加入，但不能等同完整提交狀態驗證




R14-B09 · 鎖檔 TOCTOU

	

NOT ESTABLISHED

	

描述符綁定有改善，原子性及固定 0o600 權限聲明不足

HOLDS 代表所檢查的局部修復條件成立，不等於相關整體安全保證已獨立完成驗收。

第三部分：獨立驗證與測試證據

GitHub Actions

6/6
3 個 CI 平臺、Semgrep、2 個 CodeQL Job 成功

Plugin Data 測試

71/71
已查閱 Ubuntu CI 原始日誌確認

Release Invariants

62 / 40
62 項規格與 40 項不變量，CI 顯示 PASS

獨立完整攻擊重播

未完成
已完成靜態分析及限縮的密碼學語意測試

本輪已核對 GitHub CI Job 執行結果及原始日誌；另外確認原始碼與套件內 Adapter 的 Git Blob SHA 一致：

3e5d41d8a96ddbe35362c52e89cf059f5d727315

獨立 Ed25519 語意實驗結果：

純文字
Original signature valid: true
Alternate signature valid: true
Same registry version:   true
Same registry digest:    false
Original witness pass:   true
Alternate witness pass:  true

此實驗直接使用程式中的 Registry 授權 Payload 邏輯建立最小化模型，但不是整份原始 Adapter 的端到端執行。本地環境無法解析 GitHub 網域，因此未能完整複製儲存庫並重新執行全部測試。

可重現證據：

R15 獨立密碼學語意測試

R15 Findings JSON Ledger

Round 15 最終裁定
REJECTED
MERGE BLOCKED

MERGE_AUTHORIZED = FALSE

適用於 Commit 3042f0807dda02ce2a7c7e66121d7f953c0bb8a9，不自動延伸至後續提交。

本裁定基於三項 Critical 阻擋缺陷：候選 Digest 未參與正式讀取驗證、WAL 復原仍有未持久化見證的清理窗口，以及相同 Registry Version 的歷史權威替換風險。

下一輪必須優先完成的驗收條件

所有 Registry、Journal、WAL 讀取與復原路徑，均應使用一致的候選版本、HWM Index 與 Digest 驗證。

對 Registry 的相同版本、不同內容分岔建立可信承諾，並測試退休根金鑰事後遭竊的情境。

對所有 WAL 完成路徑建立 Crash-Point Matrix，證明任何中斷都無法遺失最新見證。

強制驗證見證檔案的完整 Schema，明確界定外部見證的權限與防回滾保證。

以完整 Adapter 進行獨立攻擊重播，不能只依靠新增單元測試的 PASS 數量結案。

不確定清單

未查證： 全部 121 項測試未在獨立本地環境重新執行，完整跨檔案攻擊尚未完成端到端重播。

預設假設： 攻擊者能修改 PLUGIN_DATA 治理檔案、取得已退休簽署者私鑰，但不能直接修改受保護的外部見證；若此假設不符合實際部署，風險及可利用性必須重新評估。

推測部分： 真實競爭時序與斷電攻擊的成功率未測得；本輪不宣稱已實際重現特權提升。

確定事項： 指定程式碼存在足以拒絕現有完整安全保證的控制流程與驗證資料缺口。

下一步（2 分鐘內）： 將 Round 15 Findings Ledger 納入 PR #52 的修復追蹤，維持 REJECTED，暫不合併 main。
```
