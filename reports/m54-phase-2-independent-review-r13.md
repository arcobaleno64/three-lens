# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 13

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `3de451e6a635105ef239dac2702d0a786049e891`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 13 獨立安全審查
REJECTED · 不准合併

審查日期： 2026-11-08（臺灣時間）
審查基準： 3de451e6a635105ef239dac2702d0a786049e891
審查對象： arcobaleno64/three-lens PR #52
審查模式： Default-Deny、Read-Only、Adversarial Security Review

已從 GitHub 取得指定 commit 的程式碼及測試內容，確認修補確實存在，但至少有兩個核心安全主張仍不成立：

R12-B02：獨立單調新鮮度見證尚未建立強制性、跨程序生命週期的信任保證。 目前主要依賴記憶體 Map，外部見證是選用參數。程序重啟後，歷史合法快照仍可能被當成最新狀態。

R12-B04：模組私有 Symbol 仍可透過公開的 withGovernanceLock() 回呼取得有效授權能力。 私有變數未匯出不等於授權能力沒有外洩。程式將帶有私有 Token 的 lockedOpts 傳給外部回呼，形成治理鎖繞過路徑。

上述兩項均涉及使用者要求的核心安全不變量，因此足以阻擋 APPROVED。以下繼續檢查其餘修復項目、識別其他可證明的缺口，並區分程式碼證據與尚未執行的攻擊測試。

一、Round 13 缺失裁定總表

Critical

3

High

4

Medium

1
8 項 OPEN，包含 1 項新發現。嚴重度為本輪審查評估，不代表全部已經完成端對端攻擊重現。

Round 13

	

對應前輪

	

嚴重度

	

裁定




R13-B01

	

R12-B01

	

Critical

	

REOPEN




R13-B02

	

R12-B02

	

Critical

	

REOPEN




R13-B03

	

R12-B02

	

High

	

REOPEN




R13-B04

	

R12-B04

	

Critical

	

REOPEN




R13-B05

	

R12-B03、B05

	

High

	

REOPEN




R13-B06

	

R12-B06

	

High

	

REOPEN




R13-B07

	

R12-B07

	

Medium

	

REOPEN




R13-B08

	

新發現／R12-B06

	

High

	

NEW OPEN

二、關鍵技術發現
R13-B01：Registry 結構不完整仍可能觸發 WAL 回滾

Critical | 原始碼直接確認

_recoverAbortedRevocationTransactionInner() 的防回滾 Schema 檢查，實際上僅強制檢查 registryVersion 的型別及最低版本，另對部分 HWM 欄位進行條件式檢查。

例如：

JSON
{
  "registryVersion": 1
}

這個物件沒有完整 Registry Schema，但不會被新增的 R12-B01 條件直接拒絕。

在攻擊者掌握先前合法簽署的 PREPARED WAL，且 WAL 初始版本及 HWM 條件相符時，復原流程仍可能進入 Journal 截斷與舊快照還原。

更重要的是，這些磁碟變更發生在後續完整 Registry 驗證之前。即使新鮮度見證稍後拒絕載入，也不能撤銷已執行的截斷。

原始碼：plugin-data-adapter.mjs L764–894

解除條件： 在任何 WAL 回滾寫入之前，完成 Registry 的密碼學驗證、Schema 驗證及獨立新鮮度檢查，並加入 { "registryVersion": 1 } 的負向測試。

R13-B02／B03：新鮮度見證不獨立，Journal 還存在 fail-open 路徑

Critical + High | 原始碼直接確認

目前見證維護在 _DIR_MONOTONIC_WITNESS = new Map()，預設初始值為 Registry 版本 1、HWM -1。

externalMonotonicWitness 並非必要參數，也沒有強制讀取、更新與持久化外部可信峰值的實作。resetMonotonicWitness() 更是公開匯出的操作。

因此，當程序重新啟動、攻擊者還原整套早期合法狀態，而且呼叫端未提供可信外部見證時，這套機制無法證明磁碟狀態的新鮮度。

另有更直接的問題：

doLoadRevocationJournal() 以 failClosed: false 載入 Registry。如果 Registry 因新鮮度檢查失敗而無效，且 Checkpoint、Journal 均不存在，函式仍可提前回傳：

JavaScript
{
  valid: true,
  entries: [],
  error: null,
  count: 0
}

這裡沒有強制套用後面的 Witness Freshness 斷言。

須精確區分：isRevoked() 本身另有 Registry 無效即視為 revoked 的防線，因此不能直接宣稱 isRevoked() 已被繞過。但 loadRevocationJournal() 的有效性宣告已不可靠。

原始碼：Witness L2026–2083、Journal L2319–2364

解除條件： 使用攻擊者無法同步回滾的可信持久化見證，並要求所有有效 Journal 回傳路徑均符合新鮮度條件，包括空檔案及檔案缺失情境。

R13-B04：私有 Symbol 仍可逸出治理鎖

Critical | 原始碼及隔離 JavaScript 語意測試支持

在 withGovernanceLock()：

JavaScript
return callback({
  ...opts,
  skipLock: true,
  [INTERNAL_GOVERNANCE_TOKEN]: true
});

問題不是 Symbol.for()，而是公開回呼收到含有私有 Symbol 屬性的物件。

以下操作即可保存該能力：

JavaScript
let escaped;

withGovernanceLock(opts, lockedOpts => {
  escaped = { ...lockedOpts };
});

// 治理鎖已釋放，但 escaped 仍持有有效 Token
loadTrustRegistry(escaped);

後續 loadTrustRegistry() 的 canSkipLock 條件會成立，得以略過重新取得檔案鎖。

我另外執行隔離的 Node.js 語意檢查，確認物件展開會保留 Symbol 屬性，且原始物件移除 Token 後，逸出副本仍保有有效值。這不是對完整儲存庫執行的整合 PoC，但已支持此控制流程缺陷。

原始碼：治理鎖 L532–582

解除條件： 不得將攜帶內部授權能力的 options 傳給外部任意回呼。應改由模組內部控制巢狀呼叫的鎖所有權，並新增 Token 逸出測試。

R13-B05：WAL 後像驗證仍不完整

High | 原始碼直接確認

COMMITTED WAL 復原確認 Registry 與 Checkpoint 的 HWM 相符後，沒有確認 Journal 實際內容，就可能刪除 WAL。

PREPARED WAL 的正向提交判斷也僅要求：

JavaScript
fs.statSync(expectedJournalPath).size >
  txnData.initialJournalSize

Journal 增長不代表新增內容與簽署的 HWM 對應。

這意味著存在 Registry、Checkpoint 匹配，但 Journal 遺失或內容無效時，仍清除 WAL 的控制流程。其後的 Journal 載入可能拒絕資料，但交易證據已被提前清除。

原始碼：WAL 後像驗證 L698–829

解除條件： 提交確認必須驗證 Journal 的實際交易紀錄、索引及內容雜湊，而非檔案存在和大小；任何不一致不得刪除 WAL。

R13-B06／B08：多代輪替驗證及退休根金鑰授權存在缺口

High | 原始碼直接確認

多代輪替驗證有遞迴前提問題。對 v3 使用 v2 作為 priorRegistry 時，程式可能進一步以 priorRegistry: null 驗證 v2；但 v2 本身要求已驗證的前代狀態，因此合法的 v1 → v2 → v3 授權鏈可能失敗。

R12-B06 測試只涵蓋 v1 → v2，無法推翻這項缺陷。

另一項新發現是，當 Registry 的 authorizationProof.authorizedBy 等於創世根金鑰 ID，驗證器會直接使用預設根公鑰。前代金鑰狀態只明確排斥 REVOKED，未排斥 RETIRED。

因此，已退休但未撤銷的創世根私鑰仍可能用於授權新的 Registry 版本。這與新增撤銷紀錄只能由 ACTIVE 或 ACTIVE_PINNED_ROOT 金鑰簽署的規則不一致。

原始碼：金鑰授權與更新 L1371–1503

解除條件： 分離歷史簽章驗證權與新交易授權權限；以完整 v1 → v2 → v3 鏈及已退休根金鑰再簽署案例證明兩者的處理正確。

R13-B07：持久化及鎖釋放保證仍不足

Medium | 原始碼直接確認，實際競爭利用未重現

POSIX 目錄 fsync 目前只對 EIO 顯式拋出，其他非 Windows 錯誤仍可能被忽略，不能視為完整 fail-closed。

鎖釋放則在最後一次 lstatSync() 後再呼叫 unlinkSync()。這兩項並非不可分割操作；如果攻擊者能在期間替換鎖檔案路徑，仍有 TOCTOU 窗口。

原始碼：持久化 L260–289、鎖釋放 L495–521

解除條件： 針對 POSIX 寫入失敗建立故障注入測試，並實證鎖檔案競爭處理，或明確縮限攻擊者的檔案系統權限假設。

三、CI 與審查證據分級

證據

	

本輪結果

	

證明範圍




PR Head SHA、22 commits

	

已查證

	

版本與比較基準




Windows／macOS／Ubuntu CI

	

PASS

	

GitHub 工作流程完成




Semgrep

	

PASS

	

掃描工作成功




CodeQL

	

PASS

	

指定 Run 的 Jobs 成功




R12 專屬負向測試

	

已檢閱原始碼

	

覆蓋部分阻擋條件




本輪新增攻擊情境

	

尚未完整執行

	

原始碼推導，待整合驗證




SHA-256 雙層完整性

	

尚未獨立重算

	

不能單憑提交數值宣告通過

其中 CodeQL 已核對指定 Run 的 Jobs，但未獨立建立該 Run 與指定 Head SHA 的完整關聯證明。

本輪沒有修改、提交或合併任何 GitHub 檔案，也沒有在本機成功取得完整儲存庫，因此不能宣稱已重新執行 121/121、61/61 等完整測試，亦不能宣稱全部攻擊已實際重現。

四、正式驗收門禁

PR #52 合併授權

DENIED

本輪證據足以否定現有修復完整性，但不足以核准任何新的權威聲明。

不得將以下狀態視為等價：

CI_GREEN ≠ SECURITY_VERIFIED ≠ RELEASE_AUTHORIZED

下一輪應至少完成新鮮度見證的冷啟動回滾測試、治理 Token 逸出測試、多代輪替及退休金鑰測試，以及 Journal 完整後像驗證。所有測試需鎖定新的 commit SHA，且必須保留失敗與成功的原始證據。

五、可供下一輪使用的缺失紀錄

下載 Round 13 缺失紀錄（JSON）

包含 8 項 Finding、嚴重度、原始碼定位、反例條件、解除標準及本輪驗證限制。檔案已完成 JSON 格式驗證。
不確定清單

未查證： 完整程式碼在隔離環境下的端對端 PoC、雙層 SHA-256 重新計算，以及 CodeQL Run 與目標 SHA 的獨立關聯。

預設前提： 攻擊者可修改 PLUGIN_DATA 的部分檔案或重播先前取得的合法 WAL；治理鎖逸出另假設可呼叫公開 JavaScript API。

推測： 特定競爭時序能否在 Windows、macOS、Linux 真實部署環境穩定重現，尚待故障注入驗證。

下一步（2 分鐘內）： 在 PR #52 的審查追蹤紀錄中，優先登錄 R13-B04 為 Critical / OPEN，並將上述指定 SHA 維持在不可合併狀態。
```
