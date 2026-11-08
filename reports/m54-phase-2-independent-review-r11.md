# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 11

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `bca6cefd0c710b1935c302663b38cd2d71414938`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens Milestone 5.4 Phase 2：Round 11 獨立安全審查

審查日期：2026-11-08（臺灣時間）｜審查模式：Default-Deny / Adversarial / Read-Only

一、審查基準確認

已透過 GitHub 連線取得 PR #52 的實際資料，確認以下基準：

項目

	

獨立核對結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Target / Branch

	

main / feat/m54-phase-2-governance




PR 狀態

	

OPEN，尚未合併




Mergeable

	

TRUE




指定 Head SHA

	

bca6cefd0c710b1935c302663b38cd2d71414938




實際 Head SHA

	

與指定 SHA 完全一致




PR 提交數

	

20




PR 異動檔案數

	

31




程式碼審查範圍

	

固定於指定 SHA

另已確認：

生產路徑 scripts/adapters/plugin-data-adapter.mjs 與 skills/3lens/scripts/adapters/plugin-data-adapter.mjs 的 Git Blob SHA 一致，兩份檔案內容相同。

指定 SHA 確實包含 Round 10 審查報告及後續修復。

GitHub 回報的 Pull Request CI 與 Semgrep 工作流程已完成，結果為 success。

上述只證明審查基準與部分 CI 紀錄成立，不代表密碼學安全性、交易原子性或五項阻擋缺陷已經結案。

二、Round 11 核心阻擋發現
目前裁定：REJECTED

本輪已在指定 SHA 的原始碼中確認足以阻止核准的信任邊界缺陷。以下區分「已由程式碼證實的行為」與「依攻擊前提推導的利用鏈」，不將尚未執行的攻擊測試冒充為已重現結果。

R11-B01：WAL 簽章信任根可由未驗證的 Registry 注入

Critical｜R10-B01 未結案｜原始碼證實，完整攻擊鏈待動態重播

位置：plugin-data-adapter.mjs L593–629

復原時，如果 signedBy 不是固定信任根，程式會嘗試從磁碟 Registry 取出公鑰：

JavaScript
const onDiskReg = JSON.parse(
  fs.readFileSync(expectedRegPath, 'utf8')
);
const regKey = onDiskReg.keys?.find(
  k => k.keyId === txnData.signedBy
);
if (regKey && (
  regKey.status === 'ACTIVE' ||
  regKey.status === 'ACTIVE_PINNED_ROOT'
)) {
  signerPublicKeyPem = regKey.publicKeyPem;
}

致命問題：這段程式沒有先驗證 onDiskReg 的來源、簽章、祖先鏈與信任根授權。

而 loadTrustRegistry() 在正式驗證 Registry 之前，會先呼叫 WAL Recovery，形成信任依賴反轉：

未驗證的磁碟 Registry

提供 WAL 驗章公鑰

授權修改 Journal / Registry / History

之後才驗證復原後的 Registry

因此，攻擊者若具有治理儲存目錄的寫入能力，便存在以下可由程式碼推導的攻擊路徑：

保存較早期、真正合法的 Registry / History 快照。

將磁碟 Registry 暫時替換成包含攻擊者公鑰、標示 ACTIVE 的偽造內容。

使用攻擊者自己的 Ed25519 私鑰簽署 PREPARED WAL，指向舊快照。

觸發 Recovery，使程式採信尚未驗證的攻擊者公鑰，復原舊治理狀態。

這不是 Ed25519 演算法遭破解，而是驗章所使用的公鑰本身未經可信來源授權。

crypto.verify() 回傳成功，最多證明資料與所選公鑰相符，不能證明該公鑰具備治理權限。

更嚴重的是，復原後的 Registry 可以是真正合法的舊版。若先前的撤銷紀錄及其本地防回滾錨點一同被移除，後續驗證不一定能識別歷史降級。

裁定：R10-B01 = REOPENED。

推翻此發現需要證明：WAL Recovery 使用的每一把公鑰，都已在任何磁碟復原動作之前，由獨立可信錨點完成授權鏈驗證。指定 SHA 的程式碼不具備此保證。

R11-B02：COMMITTED WAL 完全繞過簽章與交易完成證明

High｜R10-B04 未結案｜原始碼及現有測試直接證實

位置：plugin-data-adapter.mjs L532–549

現行流程：

JavaScript
if (txnData.status === 'COMMITTED') {
  try {
    assertSafeStorageTarget(txnPath, options);
    fs.unlinkSync(txnPath);
  } catch (_) {}

  return {
    recovered: false,
    committed: true,
    txnId: txnData.txnId
  };
}

此分支出現在 signedBy 授權檢查和 crypto.verify() 之前。

結果是，只要 WAL JSON 含有 txnId 與 status: "COMMITTED"，程式就會直接承認交易已提交。

而且現有的 R10-B04 測試 L1931–1943，刻意寫入了一份沒有簽章、沒有 signedBy、沒有交易內容雜湊的 COMMITTED WAL，並要求 Recovery 接受它。

這項測試證明了程式目前的行為，卻也直接證明提交狀態缺少來源認證。

另外，在寫入交易時：

PREPARED 的簽章涵蓋 status: "PREPARED"。

COMMITTED 更新了 status，並增加 committedAt。

更新後並未重新簽章。

Recovery 亦未驗證 Journal、Checkpoint、Registry 與 History 是否構成完整的提交狀態。

因此，R10-B04 的修補僅防止正常情況下殘留 COMMITTED WAL 引發誤回滾，尚未證明 COMMITTED 狀態本身不可偽造，或與真正完成的交易具有密碼學綁定。

裁定：R10-B04 = REOPENED。

推翻此發現需要提供已驗證的 COMMITTED 簽章與完整交易後像驗證，並證明偽造 COMMITTED 標記無法跳過必要的復原或拒絕程序。

R11-B03：防回滾檢查可被損壞的 Registry 繞過

Critical｜R10-B01 延伸缺陷｜確定性控制流程缺口

位置：plugin-data-adapter.mjs L651–667

防回滾程式先解析磁碟 Registry：

JavaScript
try {
  const currentReg = JSON.parse(
    fs.readFileSync(expectedRegPath, 'utf8')
  );
  // registryVersion / HWM monotonicity checks
} catch (parseErr) {
  if (
    parseErr.message &&
    parseErr.message.includes(
      'TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED'
    )
  ) {
    throw parseErr;
  }
}

這個 catch 僅重新拋出明確的 rollback 錯誤。

如果 JSON.parse() 因 Registry 損壞而失敗，程式會略過單調性檢查，直接繼續執行 WAL Recovery。

這提供另一條不需要偽造簽章的攻擊路徑。

攻擊時序：重播真正合法的舊 WAL

系統曾產生有效的、由主管金鑰簽署的 PREPARED WAL，攻擊者取得其歷史副本。

交易完成，後續新增撤銷紀錄，現行 HWM 已前進。
具備本地治理檔案寫入能力的攻擊者，重新放回舊 WAL，並使現行 Registry 無法解析。

JSON.parse() 失敗被忽略，原本應拒絕的單調性檢查未完成。

Recovery 依舊 WAL 執行 Journal 截斷、Checkpoint / Registry / History 舊快照復原。

當舊快照本身具有完整且合法的簽章與一致性，復原後的狀態可能再次通過一般載入驗證。

這揭露了單調性機制的根本限制：它以可由同一攻擊者修改的磁碟內容作為比較基準，且在基準失效時沒有強制拒絕。

此外，目前只比較 HWM 的 headIndex 是否較大，未將同一 headIndex 下的 headDigest 不一致視為明確的歷史分歧；initialJournalSha256 雖已簽入 WAL，Recovery 也沒有驗證即將保留的 Journal 前綴是否符合這個摘要。

裁定：R10-B01 的防回滾修復不成立。

推翻此發現需要證明：在 Registry 無法解析、缺失或遭歷史替換的情況下，任何舊 WAL 都不能使已提交的撤銷狀態倒退。現行程式碼沒有提供這項證明。

R11-B04：合法交易中斷被錯誤判定為回滾攻擊

High｜交易可用性與恢復完整性缺陷

位置：plugin-data-adapter.mjs L2523–2543

目前寫入順序為：

建立已簽章的 PREPARED WAL
寫入 Journal 和 Checkpoint
更新 Registry HWM 和 History
更新 WAL 為 COMMITTED
清除 WAL 並回傳成功

若程序在第 3 步完成後、第 4 步之前崩潰，磁碟 Registry 的 HWM 已經大於 WAL 記錄的 initialHwmHeadIndex。

Recovery 因此拋出：

[TRANSACTION_WAL_ROLLBACK_ATTEMPT_DETECTED]

這是正常交易的中斷狀態，不是外部重播攻擊。

裁定：目前可以拒絕不確定的復原，但尚不能宣告具備完整的自動崩潰恢復能力。

需要以交易 ID 與簽署的預期後像區分本交易部分提交，以及真正的歷史回滾。

R11-B05：路徑競爭與持久化保證仍有缺口

High｜R10-B02、R10-B03 未完全結案

位置：safeWriteFileSync L257–271、withFileLock L349–485

已確認 ftruncateSync(fd)、fsyncSync(fd)、PID 型別守衛和 inode/device 檢查有實質改善。

但仍有兩個沒有關閉的保證：

第一，檢查檔案身分並不等於原子刪除檔案。 目前主鎖釋放及 Reclaim Lock 仍在檢查後使用 fs.unlinkSync(path)。若攻擊者能在檢查與刪除之間替換目錄項目，仍有誤刪或破壞互斥性的可能。新測試並未真正製造這種並發交錯。

第二，fsync 暫存檔不代表 rename 後的目錄項目已持久化。 safeWriteFileSync() 沒有在 rename 後同步父目錄。Linux fsync(2) 文件明確區分這兩種持久化保證。
Linux manual page
+1

對 Windows、macOS 和 Linux，也不能僅靠三平台測試綠燈，就推論其檔案系統的斷電及路徑競爭語意完全相同。

三、Round 10 五項阻擋項最終覆審表

原阻擋項

	

Round 11 狀態

	

裁定理由




R10-B01 WAL 來源認證

	

REOPENED

	

未驗證公鑰注入、舊 WAL 回滾與損壞 Registry 跳過檢查




R10-B02 Rollback TOCTOU

	

OPEN

	

描述符操作已改善，路徑替換與目錄刷盤保證未完整建立




R10-B03 Reclaim Lock

	

OPEN

	

PID 守衛改善，檢查與 unlink 非原子




R10-B04 COMMITTED WAL

	

REOPENED

	

無簽章 COMMITTED 被直接接受




R10-B05 isRevoked 原子性

	

PARTIALLY HOLDS

	

正常路徑已持鎖，但 skipLock: true 可繞過，尚缺真實競爭測試

R10-B05 需要特別區分：在所有呼叫端遵守治理鎖的前提下，這次修補的方向成立。尚未證明的是 skipLock 不會被未持鎖者使用，以及非合作式本機檔案操作不會破壞該快照。不能把這兩種安全邊界混為一談。

四、CI 與證據可信度裁定

經 GitHub Actions 原始紀錄交叉查核：

驗證項目

	

查核結果




npm test

	

121/121 PASS




Plugin Data Adapter

	

50/50 PASS




Compact Guard

	

22/22 PASS




Release Gate

	

62 specifications、40 security invariants PASS




Ubuntu / Windows / macOS

	

全部成功




CodeQL / Semgrep

	

全部成功

三個工作流程均對應 bca6cefd，因此 CI 綠燈的宣告可以接受。

但本輪未確認攻擊者可在各作業系統上穩定觸發完整特權回復。已確立的是程式碼中的信任邊界和檢查順序確有缺陷，在使用者指定的敵對本機寫入威脅模型下，不足以構成安全證明。

雙層 SHA-256 數值也已在指定提交的 Manifest 與 Evidence Matrix 找到一致宣告；本輪沒有獨立重新計算兩層 SHA-256。即使重新計算全部正確，仍僅能證明檔案一致性，不能替代可信的外部版本錨定與防回滾證明。

五、正式結案裁定
REJECTED
Release Gate 阻擋

審查対象： bca6cefd0c710b1935c302663b38cd2d71414938

**理由：**至少存在兩條獨立的高影響 WAL 信任與回滾控制缺口；COMMITTED 狀態亦缺乏來源認證。這些問題足以阻止權威性 APPROVED 宣告。

**不得據此核准：**將 PR #52 合入 main，或將其治理能力標示為完成獨立安全驗收。

本裁定僅適用於指定 SHA。新提交必須重新驗證受影響的證據鏈；本次沒有執行合併、留言或任何儲存庫修改。

完整審查報告已整理為 Markdown，包含所有原始碼行號、攻擊前提、修復優先序及結案條件：

Round 11 獨立安全審查報告（Markdown）

不確定清單

**未查證：**完整攻擊 PoC 尚未在指定提交的實際 Runtime 與三平台檔案系統執行。

**預設前提：**攻擊者具有 PLUGIN_DATA 治理檔案寫入能力，但沒有受信任主管私鑰；實際部署的檔案 ACL 尚未核實。

**推測：**特定檔案替換與競爭時序能穩定使已撤銷 ID 再次得到 revoked: false；需要整合重播才能提升為已實測結論。

**兩分鐘內的下一步：**先新增一個負向測試：以真正簽署過的舊 PREPARED WAL 搭配損壞的現行 Registry，驗證 Recovery 必須拒絕歷史回滾，且不得刪除既有撤銷紀錄。
```
