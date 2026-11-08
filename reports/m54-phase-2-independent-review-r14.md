# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 14

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `5b790c4e7be61c599572b8770adf4f22f7e47f98`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 14 獨立安全審查
REJECTED · 禁止合併

審查日期：2026-11-08（臺灣時間）｜審查模式：Cold-Start / Adversarial / Default-Deny

本輪已從指定 Commit 的實際程式碼確認重大安全缺口。R13-B04 的治理鎖能力逸出問題尚未真正解決，且 R13-B02 的持久化防回滾見證仍可透過公開 API 清除。

這不是因為缺少測試就預設拒絕，而是存在可以具體指出程式路徑、觸發條件與安全後果的缺陷。

審查指定 Commit

5b790c4e7be6

GitHub PR

#52 · feat/m54-phase-2-governance

GitHub 狀態

OPEN / Mergeable

審查權限

唯讀；未修改、未核准 PR

已確認的阻擋缺陷
R14-B01 · Critical：AsyncLocalStorage 仍可在實體鎖釋放後保留授權上下文

來源：scripts/adapters/plugin-data-adapter.mjs

第 59–63 行：isGovernanceLockHeld() 以 AsyncLocalStorage 的 store.active 與路徑比對判斷是否持鎖。

第 517–546 行：withFileLock() 在同步回呼結束後，立即執行 finally 釋放實體鎖。

第 573–580 行：withGovernanceLock() 以 AsyncLocalStorage.run() 建立 active: true 的上下文，卻沒有在鎖釋放前撤銷授權。

根本問題：AsyncLocalStorage.run() 返回不代表衍生的非同步工作已失去上下文。

已使用 Node.js v22.16.0 進行獨立最小化語意測試。測試安排 queueMicrotask() 在鎖定回呼內建立工作，並於回呼返回後觀察：

純文字
phase:           after_withLock_return
lockHeld:        false
asyncStoreActive:true
canSkipLock:     true

這證實授權上下文的存活時間可能超過實體鎖的生命週期。

當排程的非同步工作繼承該上下文，再以 skipLock: true 呼叫治理 API 時，現有 isGovernanceLockHeld() 判斷具備被繞過的條件。

裁定：R13-B04 不予結案，列為 REOPENED。

此測試證實 Node.js 授權上下文的逸出機制及程式碼中的對應控制缺口；尚未宣稱已完成針對整個儲存庫的端到端競爭攻擊重現。

R14-B02 · Critical：防回滾見證存在呼叫端可自行授權的刪除入口

來源：相同檔案，第 2258–2270 行。

JavaScript
export function resetMonotonicWitnessForTest(
  dir, testOptions = {}
) {
  if (testOptions.allowInWorkspace !== true) {
    throw new Error('[PERMISSION_DENIED]');
  }
  // ...
  fs.unlinkSync(localWitnessFile);
  fs.unlinkSync(systemWitnessFile);
}

這個防護檢查並未驗證呼叫者是否為測試框架、是否處於授權的測試執行階段，甚至沒有不可由呼叫端指定的權限來源。

allowInWorkspace 只是一般參數。呼叫端可以自行提供 true。

因此，對於能匯入並執行該模組 API 的攻擊者，兩份持久化見證具有明確的刪除路徑。搭配程序重啟與歷史狀態還原，會直接破壞設計所宣稱的跨程序防回滾保證。

裁定：R13-B02 不予結案，列為 REOPENED。

上述兩項均足以獨立阻止本 PR 通過密碼學治理層級的安全驗收。

R14-B03 · Critical：WAL 復原可能使用偽造的前像版本資訊，執行未授權回滾

檢查 recoverAbortedRevocationTransaction() 後，發現更直接的交易一致性缺口。

第 668–675 行允許 WAL 使用內建創世根金鑰驗簽，沒有先確認該金鑰在目前信任狀態是否已退休。

第 776–794 行驗證 WAL 內快照的 SHA-256，但並未驗證快照內容的 Registry 版本及 HWM 是否等於 WAL 聲稱的初始狀態。

接著，第 817–890 行對目前磁碟 Registry 進行防回滾檢查，最後於第 902–940 行根據 WAL 快照還原資料。

這形成以下條件式攻擊路徑：

攻擊者取得已退休創世根金鑰的私鑰，可簽署新的 PREPARED WAL。

WAL 宣稱的 initialRegistryVersion 與 initialHwmHeadIndex 設為目前有效版本，卻嵌入較舊的 Registry 與 Checkpoint 快照。

攻擊者對舊快照計算正確 SHA-256，並使用退休私鑰對 WAL 簽署。

復原程序驗證目前狀態及 WAL 簽章，但沒有將還原目標的語意狀態與經驗證的初始狀態綁定，因而可能執行舊狀態還原。

這裡的 SHA-256 沒有被破解。問題在於攻擊者可以對自己選擇的錯誤快照提供正確雜湊。

重大影響： 即使持久化見證仍記錄較新的版本，復原程序也可能先對磁碟執行破壞性回滾，後續載入才發現版本倒退而拒絕。若見證同時失效，則存在舊版信任狀態被重新接受的條件。

這是程式碼控制流程推導出的可行攻擊條件，尚未完成完整端到端重播；不能宣稱已實證重新取得特權，但足以否定「WAL 回滾前已完成嚴格目標狀態驗證」的安全聲明。

裁定：R13-B01 與 R13-B08 的交界安全保證不成立，列為新的 Critical 阻擋項。

R14-B04 · Critical：已退休根金鑰仍可透過 HWM 簽章授權新的撤銷狀態

這是本輪最重要的金鑰生命週期缺陷之一。

computeRegistryAuthorizationPayload()（第 1066–1087 行）簽署的欄位不包含 revocationHighWaterMark。

然而，validateTrustRegistry()（第 1242–1260 行）允許 HWM 簽署者的狀態為：

JavaScript
[
  'ACTIVE_PINNED_ROOT',
  'ACTIVE',
  'RETIRED',
  'REVOKED'
]

doLoadRevocationJournal()（第 2658–2687 行）也將 RETIRED 金鑰加入歷史驗簽信任集合，且沒有對新紀錄執行簽署時期的授權判斷。

因此，若攻擊者持有已退休根金鑰的私鑰，且能修改相關治理狀態檔案，就可能：

保留既有有效 Registry authorizationProof。

使用退休私鑰簽署新的 Journal 紀錄與較高 HWM。

同步更新 Registry、History 與 Checkpoint，符合檔案一致性要求。

讓驗證程序接受新的 HWM，即使簽署者已失去新增撤銷的權限。

已以 Node.js Ed25519 建立獨立密碼學語意測試：

純文字
authorizationPayloadUnchanged: true
oldRegistryProofStillValid:    true
retiredRootHwmSignatureValid:  true
codeAcceptsRetiredHwmSigner:  true

這證實現有授權 Payload 的涵蓋範圍與退休金鑰驗證規則可以同時滿足，卻沒有證明新撤銷操作獲得有效授權。

裁定：R13-B08 的防護只覆蓋部分 Registry 更新 API，沒有涵蓋所有能改變權威狀態的驗證入口，故不予結案。

需要修正的是「歷史簽章可以驗證」與「現在仍有權簽署」的授權分界，而不是全面禁止退休金鑰的歷史驗簽。

其他新增缺陷與覆審結果

Finding

	

風險

	

判定與證據




R14-B05

	

Critical

	

WAL 先刪除，後更新見證（第 3069–3076 行）。斷電窗口可能讓已提交的撤銷狀態失去外部新鮮度紀錄。




R14-B06

	

High

	

Witness 讀寫失敗被忽略（第 2192–2207、2238–2255 行）。無法保證持久化失敗時 fail-closed。




R14-B07

	

High

	

Witness 只比較版本與 headIndex，不比較 digest。同版本、同索引的不同有效簽署分支可能無法辨識。




R14-B08

	

High

	

COMMITTED WAL 只驗證 Journal Tail 雜湊。既有測試甚至使用無效的 Journal 簽章，仍預期復原成功並刪除 WAL。




R14-B09

	

Medium

	

鎖檔使用兩次 inode 比對後執行 unlinkSync()，最後檢查與刪除之間仍有條件式 TOCTOU 風險，尚未動態重現。

R14-B08 的直接證據在 測試檔第 2807–2897 行。

Round 13 八項修復的最終處置

原 Finding

	

Round 14 裁定




R13-B01：Registry Schema / WAL

	

REOPENED




R13-B02：持久化單調見證

	

REOPENED




R13-B03：Journal 缺失 Fail-Closed

	

PARTIALLY HOLDS




R13-B04：治理鎖能力逸出

	

REOPENED




R13-B05：COMMITTED / PREPARED WAL

	

REOPENED




R13-B06：多代金鑰輪替

	

PARTIALLY HOLDS




R13-B07：POSIX fsync / 鎖釋放

	

PARTIALLY HOLDS




R13-B08：退休金鑰授權

	

REOPENED

其中 PARTIALLY HOLDS 表示指定範圍的防護邏輯已有改善，不代表符合結案條件。

CI 與獨立性限制

已透過 GitHub 核對指定 SHA 的三項 Workflow：

Pull Request CI：SUCCESS

Semgrep：SUCCESS

CodeQL：SUCCESS

兩項獨立 Node.js 語意實驗已執行，包含 AsyncLocalStorage 授權存續與退休根金鑰的 HWM 簽章涵蓋範圍。AsyncLocalStorage 的觀察結果亦符合 Node.js 官方文件。
Node.js v26.13.0 Documentation

限制： 無法在本地取得整份 GitHub 原始碼，因此沒有獨立重跑 npm test、check:release，也沒有完成整套端到端攻擊重播。這些限制已在報告中明確區分，不以推論冒充實測。

完整 Round 14 審查報告

Round 14 Security Review

Markdown · 9 項 Finding · 原始碼行號 · 修復條件 · 負向驗收要求

下載獨立安全審查報告

最終 Release Gate

MERGE_AUTHORIZED = FALSE

指定 SHA 的程式碼具備充分理由維持 REJECTED。即使所有既有 CI 都成功，仍不能取代對授權生命週期、密碼學綁定及中斷復原的獨立驗證。

不確定清單： 完整目標程式的攻擊重播尚未完成；部分競爭與斷電攻擊依威脅條件推導；實際部署的檔案系統權限及額外防護未經驗證。

下一步（2 分鐘內）：將 R14-B04「退休根金鑰仍可授權新 HWM」 登記為 PR #52 的 Critical 阻擋項，保持禁止合併狀態。
```
