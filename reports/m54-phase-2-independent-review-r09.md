# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 09

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `7437340e0572f578d3f3df2c3ef117acea8e930b`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
本輪採取 Cold-Start、Evidence-Bound、Default-Deny 審查，不把前八輪的裁定、修復說明、測試通過或 CI 綠燈視為本輪的既定事實。

審查基準鎖定：

Repository：arcobaleno64/three-lens

PR：#52

指定 Head：7437340e0572f578d3f3df2c3ef117acea8e930b

R08 修復 Commit：9579d1a7afdf339c2498fbdee07a0f5c05ebb89d

核心範圍：R08-B01～R08-B08，並檢查修復是否引入新的權限提升、回滾或競爭條件。

初步查核發現一項證據一致性問題： GitHub PR API 回傳的狀態為 open、merged=false，但同時存在 merge_commit_sha。這與委託書所述「已合併」不一致，不能直接採信其中任何一方。

另外，目前取得的指定 Head 工作流程紀錄確認 Semgrep 與 Pull Request CI 兩項成功；CodeQL Run 42397725411 尚未在這次查核中獨立確認。

以下以實際程式碼與攻擊路徑為準，不以測試數量代替安全證明。

一、審查基準與 CI 核實

指定三項 CI 均成功 PR 尚未合併至 main

項目

	

實際查核結果




指定 Head SHA

	

一致




PR 狀態

	

OPEN




PR merged

	

FALSE




Main 與 Head

	

Ahead 18、Behind 0




Semgrep 42397730211

	

SUCCESS




Pull Request CI 42397730216

	

SUCCESS




CodeQL 42397725411

	

SUCCESS，兩個分析工作均成功

這裡需要區分兩件事：分支已經同步最新 main，不等於 PR 已經合併進 main。目前 GitHub 的 merged_at 仍為 null。

二、已確認的阻擋缺陷
REJECT 條件已成立

以下不是尚待驗證的猜測，而是直接從指定 Head 的程式碼控制流程可以確認的問題。

R08-B02：WAL 損壞狀態仍有 Fail-Open 路徑

位置：scripts/adapters/plugin-data-adapter.mjs:448–540

缺陷 1：未知狀態不會拒絕載入。

目前程式只有：

JavaScript
if (txnData.status === 'PREPARED') {
    // 執行復原
}

return { recovered: false };

這代表 CORRUPTED、未知狀態，甚至其他非 PREPARED 狀態，都會直接回傳 recovered: false。

而 loadTrustRegistry() 在呼叫復原函式後，會繼續執行 doLoadTrustRegistry()。

因此：

前一次復原失敗，WAL 被標記為 CORRUPTED。

程序重新啟動。

再次讀取 WAL。

因為狀態不是 PREPARED，復原函式回傳 recovered: false。

註冊表繼續載入。

這直接違反損壞狀態必須持續 Fail-Closed 的要求。

缺陷 2：WAL 必要欄位沒有完整驗證。

目前只強制要求：

txnId

status

但 journalPath、checkpointPath、regPath 都是條件式驗證。攻擊者提供只有 txnId 和 status: PREPARED 的 JSON，即可跳過所有復原操作，最後刪除 WAL 並回傳成功。

這也使 R08-B01 所宣稱的完整路徑遏制失去部分意義。

R08-B01：路徑檢查仍有 TOCTOU 窗口

位置：同一檔案 448–540。

程式雖然在操作前呼叫：

JavaScript
assertSafeStorageTarget(expectedRegPath, options);

但隨後仍使用：

JavaScript
fs.writeFileSync(expectedRegPath, ...);
fs.truncateSync(expectedJournalPath, ...);

這兩種操作仍然透過路徑重新開啟檔案。

assertSafeStorageTarget() 的 lstatSync() 檢查與實際寫入之間沒有持續綁定同一個檔案描述符。

攻擊者若能在這個窗口替換目標檔案為 symbolic link，檢查通過後的路徑操作仍可能導向其他檔案。

專案其實已有 safeOpenStorageFile()，但 WAL 復原沒有一致使用它。

因此，這項修復只能證明一般情況下的路徑檢查，不能證明競爭條件下的安全性。

R08-B07：Reclaim Lock 本身仍可被競爭回收

位置：plugin-data-adapter.mjs:322–427。

目前第二階段鎖使用：

JavaScript
const reclaimLockFile = `${lockFile}.reclaim`;

但當其他程序發現 reclaim lock 超過 3 秒時，會直接：

JavaScript
fs.unlinkSync(reclaimLockFile);

沒有再次驗證：

原持有者 PID 是否存活。

原持有者的 lock ID。

reclaim lock 是否已經被另一程序替換。

自己是否仍然持有該 reclaim lock。

而且 finally 區塊也直接刪除 reclaim lock 路徑，沒有驗證檔案所有權。

攻擊情境：

程序 A 取得 reclaim lock。

A 暫停超過 3 秒。

程序 B 將 A 的 reclaim lock 刪除。

程序 C 取得新的 reclaim lock。

A 恢復執行，B、C、A 可能同時進入回收邏輯。

因此，兩階段鎖並未建立不可被其他競爭者破壞的互斥條件。
```
