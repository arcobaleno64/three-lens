# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 12

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `80e900d2a504a0990a296360ba5206021c2ad0bb`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens Milestone 5.4 Phase 2：Round 12 獨立安全審查
REJECTED · 不准合併

審查日期： 2026-11-08（臺灣時間）
審查模式： Default-Deny / Adversarial / Read-Only
審查對象： GitHub PR #52
固定審查 SHA： 80e900d2a504a0990a296360ba5206021c2ad0bb

裁定：REJECTED。 已取得指定提交的實際原始碼，確認部分 Round 11 修補確實存在，但尚不能認定五項阻擋項均已結案。特別是 WAL 提交狀態的後像驗證、治理鎖權限邊界與歷史狀態驗證，仍存在足以阻止合併的問題。

一、審查基準核對

項目

	

獨立查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

#52




Target / Branch

	

main / feat/m54-phase-2-governance




PR 狀態

	

OPEN，尚未合併




Mergeable

	

TRUE




指定 Head SHA

	

完全吻合




PR 提交數

	

21




異動檔案數

	

32




GitHub Actions

	

Pull Request CI、Semgrep 均回報 success




程式碼審查範圍

	

固定於指定 SHA，不跟隨後續分支異動

上述資訊已透過 GitHub 連線核對。Mergeable TRUE 與 CI success 不構成安全核准。

本輪亦確認指定提交確實修改了 plugin-data-adapter.mjs、相關測試、TCB Integrity Manifest 與 Evidence Matrix，因此不是只依據提交者提供的文字說明進行審查。

二、Round 12 阻擋發現

Finding

	

等級

	

獨立審查結果




R12-B01

	

Critical

	

可解析但不符合 Schema 的 Registry 能略過防回滾檢查




R12-B02

	

Critical

	

全部本地信任狀態同步回滾時，缺少獨立可信的新鮮度證明




R12-B03

	

High

	

COMMITTED WAL 只條件式檢查 headIndex，未驗證完整後像




R12-B04

	

High

	

Governance Token 可重建，Recovery 也可繞過治理鎖直接呼叫




R12-B05

	

High

	

PREPARED WAL 尚未證明完整提交就可能被判定為 COMMITTED




R12-B06

	

High

	

非創世根簽章者的合法 WAL 可能無法復原，多代金鑰輪替亦受影響




R12-B07

	

Medium

	

unlinkSync 競爭窗口及目錄 fsync 失敗處理不完整

R12-B01：合法舊 WAL 仍可能造成撤銷紀錄回滾

原始碼位置：plugin-data-adapter.mjs L728–805

當磁碟上的 Registry 是合法 JSON，但內容為 {} 時，JSON.parse() 成功，程式卻未確認 registryVersion、HWM 是否具備必要欄位。

後續 typeof curRegVer === 'number' 等條件因此不成立，防回滾比較被略過。若攻擊者重播真正由授權金鑰簽署的舊 PREPARED WAL，且既有 Journal 的舊前綴未變，SHA-256 前綴驗證仍可能通過，程式便會執行截斷及舊快照復原。

這是直接由原始碼證實的控制流程缺口。最終是否成功消除新撤銷，仍需以真實 WAL 在隔離環境完成端到端重播。

推翻條件： 合法舊 WAL 搭配 {} Registry 時，復原程序必須在任何資料變更前拒絕，且保留較新的撤銷紀錄。

R12-B02：簽章不能證明歷史狀態是最新的

若攻擊者能同步回復整個 PLUGIN_DATA 內的 Registry、Journal、Checkpoint 與 History，舊狀態可以仍然具有完全合法的 Ed25519 簽章。

固定創世根能驗證資料來源，卻不能單憑簽章區分「目前最新的合法狀態」與「以前曾經合法的狀態」。

因此，若威脅模型確實要求抵抗完整本地儲存狀態回滾，必須提供獨立於該可回滾儲存區的新鮮度或單調性證據。

推翻條件： 提供受保護的外部單調見證，並證明完整舊快照重播時，讀取程序會拒絕該狀態。

R12-B03：COMMITTED WAL 後像驗證不符合修復宣告

原始碼位置：L680–705

已確認 COMMITTED WAL 現在會進行 Ed25519 驗章，這項修復有效。

但後像驗證並未比較 committedHwmHeadDigest，也沒有在此分支完成 Journal、History 及 Registry 授權鏈的完整驗證。甚至在缺少 committedHwmHeadIndex 時，索引比較會直接跳過。

推翻條件： 使用有效簽章的 COMMITTED WAL，配合相同索引但不同 Digest 的磁碟狀態，必須被拒絕，且不得清除 WAL。

R12-B04：治理鎖的不可偽造性不成立

原始碼位置：L37

JavaScript
export const INTERNAL_GOVERNANCE_TOKEN =
  Symbol.for('three_lens.governance.internal_lock_token');

使用 Symbol.for() 並不能建立只有模組內部才能取得的秘密 Token，而且這個值還被直接匯出。

獨立 Node.js 最小測試確認，外部呼叫者可以重建完全相同的 Symbol，使 canSkipLock 成立。此外，公開的 recoverAbortedRevocationTransaction() 本身沒有要求取得治理鎖。

推翻條件： 外部 API 呼叫者無法偽造鎖所有權，也無法在未持鎖狀態執行會修改磁碟的 Recovery。

R12-B05～B07：其餘未結案問題

PREPARED WAL 的正向提交識別只比對 Registry 與 Checkpoint 的 HWM，沒有確認 expectedTargetRegistryVersion 及完整 Journal、History 後像。非 embedded signer 的 WAL 復原又因缺乏已驗證的 priorRegistry，可能拒絕合法輪替後的金鑰。

另外，重複 lstatSync 並不能讓最後的 unlinkSync(path) 變成原子操作；POSIX 目錄 fsync 出錯時也被忽略。這些都與「完整交易恢復」、「不可偽造鎖」及「斷電持久化」的宣告不一致。

三、Round 11 阻擋項結案狀態

Round 11

	

Round 12 裁定




R11-B01

	

部分修復，未結案




R11-B02

	

部分修復，未結案




R11-B03

	

防回滾不變量仍不成立




R11-B04

	

部分修復，未結案




R11-B05

	

鎖保護不變量仍不成立

本輪沒有任何一項達到可獨立核准為 CLOSED 的證據標準。這不否定既有修補的實際改善，而是表示目前證據還不能支持整體安全放行。

四、獨立驗證界線

已完成 GitHub 原始碼與測試內容檢視、指定 SHA 核對、CI job 狀態核對，以及 Node.js Symbol 與 Journal 前綴條件的最小驗證。

未完成的部分包括：在原始儲存庫重新執行完整測試、獨立重算全部 TCB SHA-256、真實多進程競爭測試、斷電故障注入，以及完整舊 WAL 回滾攻擊重播。這些不得寫成已經驗證通過或失敗。

五、正式審查報告

完整報告包含各項 Findings 的原始碼位置、攻擊前提、影響、證據等級、結案必要條件與驗證限制。

Round 12 Independent Security Review

Markdown 格式，固定 SHA、7 項發現、修復驗收條件

下載報告

本輪審查是獨立、唯讀的拒絕裁定。沒有修改 PR、提交程式碼，也沒有向 GitHub 發佈審查意見。

不確定清單

未查證：完整測試重跑及 TCB 雙層 SHA-256 獨立重算。

預設：攻擊者具備題述的治理檔案讀寫與舊狀態替換能力。

推測：部分回滾與 TOCTOU 攻擊的實際端到端可利用性，仍待隔離重播。

下一步（兩分鐘內）： 將 R12-B01 登錄為 Critical 阻擋項，要求新增「合法舊 WAL + 可解析但無效 Registry + 已提交新撤銷」的負向測試，確保修復前不合併 PR #52。
```
