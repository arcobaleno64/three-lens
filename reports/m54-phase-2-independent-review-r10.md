# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 10

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `8f1379c5c7ceea5768853b05445217ee1288bbfb`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens Milestone 5.4 Phase 2：Round 10 獨立安全審查

初步裁定：REJECTED 仍有阻擋項

Round 10 目前不符合 APPROVED 條件。 GitHub 上的實際 PR 狀態與提交紀錄，已經出現兩項需要先釐清的問題，而且最新一輪 Codex Review 留下了一項可重現的交易完整性缺陷。

一、審查基準核對

截至 2026-11-08，本次查核取得的 GitHub 資料如下：

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




PR

	

#52




Branch

	

feat/m54-phase-2-governance




Target

	

main




PR 狀態

	

Open，尚未合併




Mergeable

	

TRUE




實際 Head SHA

	

8f1379c16e0f41dfe5557e38f5896e6194c6749b




指定審查 SHA

	

8f1379c5c7ceea5768853b05445217ee1288bbfb




Changed Files

	

30

有兩個基準問題：

你提供的 SHA 與 GitHub PR 實際 Head SHA 不一致。不能將兩者視為同一個提交。

你提供的「已完成合併」與 GitHub 回傳的 merged=false、state=open 不一致。

因此，本次以 GitHub 實際 PR Head 為程式碼審查基準，不把使用者提供的狀態敘述當成已驗證事實。

二、已發現的重大問題

GitHub 最新一筆針對實際 Head 8f1379c16e0f41dfe5557e38f5896e6194c6749b 的 Codex Review，指出：

WAL 移除失敗時，交易仍回報成功，卻可能在下一次讀取時撤銷已確認的權限撤銷紀錄。

這直接涉及你指定的攻擊面：

交易中斷。

WAL 狀態與實際持久化狀態不一致。

已確認的安全狀態遭到回滾。

復原程序將未完成的交易誤判為應該回復舊狀態。

這不是單純的程式碼品質問題，而是安全狀態持久性問題。

三、Round 09 三項阻擋修復的獨立覆審
R09-B01：WAL 損壞與必要欄位驗證

部分通過 整體仍阻擋

位置：plugin-data-adapter.mjs:467–570

已確認的改善：

JSON 無法解析時直接拒絕復原。

CORRUPTED、UNKNOWN 等非 PREPARED 狀態一律拒絕。

journalPath、checkpointPath、regPath 必須是有效字串。

initialJournalSize 必須是數值。

不再以 recovered: false 靜默放行。

這部分確實修復了 Round 09 指出的兩個問題。

但是，發現一項更嚴重的缺陷。

Critical · R10-B01 WAL 快照沒有密碼學來源驗證，仍可偽造復原交易。

目前復原程序只驗證：

WAL 狀態。

路徑是否符合預期。

必要欄位是否存在。

檔案是否符合儲存安全檢查。

卻沒有驗證 WAL 本身是否由可信交易建立。

尤其是以下資料都可以由攻擊者自行提供：

initialJournalSize

initialJournalExisted

initialCheckpointRawBase64

initialRegistryRawBase64

initialHistRawBase64

沒有交易簽章、MAC 或其他可信來源證明，確認這些快照確實是交易開始前的狀態。

實際攻擊路徑：

假設系統已經成功撤銷一個 NONCE：

原始 Registry v1 已經具有有效的 revocationHighWaterMark。

Journal 已經保存具有效 Ed25519 簽章的撤銷紀錄。

History v1 也已經保存含有 HWM 的 Registry。

攻擊者建立一份偽造的 .revocation-txn.json，使用合法的治理檔案路徑。

將 initialJournalSize 設為 0，initialJournalExisted 設為 false。

將 Registry 與 History 快照設為原本合法的 Genesis v1 狀態，不含 HWM。

將 initialCheckpointExisted 設為 false。

保持 status: PREPARED。

接著呼叫 isRevoked()。

目前的復原流程會：

刪除 Journal。

刪除 Checkpoint。

將 Registry 恢復成合法但過期的 Genesis v1。

將 History v1 一併恢復成不含 HWM 的版本。

刪除 WAL。

繼續載入 Registry。

這裡特別值得注意：攻擊者不是偽造 Ed25519 簽章，而是重播一份過去真正合法的狀態。

History 的檢查也無法阻止這個攻擊，因為攻擊者連同唯一的 v1 歷史紀錄一起恢復了。

最後，isRevoked() 可能將原本已撤銷的 NONCE 判定為：

JavaScript
{
  revoked: false,
  reason: null,
  entry: null
}

這個攻擊不需要 supervisor private key。

裁定：R09-B01 不通過。

這是本輪最嚴重的問題。現有欄位驗證只能證明 WAL 格式符合預期，不能證明 WAL 所聲稱的歷史快照真實。

參考：

WAL 復原實作

Registry 與 History 防回滾檢查

既有獨立審查提出的 WAL 快照驗證問題

R09-B02：路徑 TOCTOU 與描述符綁定

主要改善成立 尚未完全閉環

位置：

safeOpenStorageFile()：188–250

safeWriteFileSync()：257–271

recoverAbortedRevocationTransaction()：467 起

appendRevocationEntry()：2165 起

已確認的正面改善：

防護項目

	

結果




O_NOFOLLOW

	

已導入




lstat 與 fstat 比對

	

已導入




inode/device 校驗

	

已導入




Journal ftruncateSync

	

使用檔案描述符




Journal fsyncSync

	

已導入




Checkpoint 原子寫入

	

已導入




Registry 原子寫入

	

已導入




History 原子寫入

	

已導入




刪除前安全檢查

	

已導入

正常 WAL 復原路徑的改進是成立的。

但我發現兩個殘留問題。

R10-B02-A：交易失敗後的 rollback 仍使用路徑重新開啟。

在 appendRevocationEntry() 的 catch 區塊，仍然使用：

JavaScript
fs.truncateSync(journalPath, initialJournalSize);
fs.writeFileSync(checkpointPath, initialCheckpointRaw);
fs.writeFileSync(regPath, initialRegistryRaw);
fs.writeFileSync(histPath, initialHistRaw);

這些操作沒有使用前述描述符綁定機制。

攻擊者若能在交易失敗與 rollback 之間替換目標路徑，就可能使復原操作作用於非預期檔案。

尤其 Journal 的 truncateSync() 仍是透過路徑重新開啟。

這代表：

WAL Crash Recovery 已改善，但 Transaction Rollback 並未全面繼承相同的安全保證。

R10-B02-B：原子 rename 尚未建立完整的目錄描述符保證。

safeWriteFileSync() 使用：

JavaScript
fs.renameSync(tmpPath, targetPath);

雖然暫存檔已經過描述符檢查，但最後 rename 仍使用路徑。

目前沒有看到將父目錄的 inode/device 身分持續綁定至 rename 操作的完整證明。

此外，暫存檔執行 fsync 後，沒有看到 rename 後對父目錄執行目錄同步，因此斷電情境下的目錄項目持久性也尚未建立完整證明。

裁定：R09-B02 部分通過，但不能宣告 TOCTOU 全面消除。

參考：

安全檔案操作

安全原子寫入

交易 rollback

R09-B03：Reclaim Lock 互斥與所有權

改善成立 競爭條件仍未閉環

位置：plugin-data-adapter.mjs:322–430

已確認：

新增隨機 reclaimLockId。

reclaim lock 過期後檢查持有者 PID。

PID 存活時拒絕回收。

finally 區塊檢查 reclaimLockId。

這些改善合理，但尚不足以證明互斥性。

R10-B03-A：PID 型別驗證不足。

目前條件：

JavaScript
if (recParsed.pid && !isPidAlive(recParsed.pid)) {
  // reclaim
}

而 isPidAlive() 對非數值 PID 直接回傳 false。

因此：

JSON
{
  "pid": "12345",
  "timestamp": 123456789,
  "reclaimLockId": "example"
}

會被視為 PID 已死亡，而不是 PID 狀態無法驗證。

這與「只有確認持有者死亡才可回收」不同。

正確的 Default-Deny 邏輯應該是：

PID 格式有效且存活：拒絕回收。

PID 格式有效且確認不存在：才考慮回收。

PID 格式無效、資料損壞或狀態不明：拒絕回收。

R10-B03-B：Ownership Check 與 unlink 仍存在 TOCTOU。

目前 finally：

JavaScript
const content = fs.readFileSync(reclaimLockFile, 'utf8');
const parsed = JSON.parse(content);

if (parsed.reclaimLockId === reclaimLockId) {
  fs.unlinkSync(reclaimLockFile);
}

這仍然是：

讀取檔案。

驗證 ID。

重新透過路徑刪除。

驗證與刪除不是同一個原子操作。

其他程序可以在兩個系統呼叫之間替換檔案。

因此，隨機 ID 只能減少誤刪機率，不能構成檔案身分與刪除操作的原子性證明。

此外，主要 lock 的回收邏輯還有一個問題：

JavaScript
let canRecover = true;

如果主要 lock 的 JSON 無法解析，例外被忽略後，canRecover 仍然是 true。

也就是說，主要 lock 的持有者身分不明時，仍可能被回收。

裁定：R09-B03 部分通過，互斥性及所有權驗證仍未完整成立。

參考：

- withFileLock 實作

四、Round 10 新發現的交易完整性缺陷
R10-B04：WAL 刪除失敗仍回報成功
High · 阻擋

位置：plugin-data-adapter.mjs:2374–2384

目前程式：

JavaScript
// Successfully committed: remove WAL marker
try {
  if (fs.existsSync(txnPath)) fs.unlinkSync(txnPath);
} catch (_) {}

return {
  success: true,
  entryIndex,
  entryDigest,
  path: normalizePath(journalPath)
};

這裡存在明確的交易狀態矛盾。

攻擊／故障情境：

建立 PREPARED WAL。

成功寫入 Journal。

成功寫入 Checkpoint。

成功更新 Registry 與 History。

刪除 WAL 時遭遇 EACCES。

例外被忽略。

API 回傳 success: true。

下一次 loadTrustRegistry() 發現 PREPARED WAL。

執行復原，將所有資料恢復到交易前狀態。

原本已經回報成功的撤銷紀錄消失。

這代表呼叫端收到成功訊號，卻沒有取得持久化的撤銷結果。

這項缺陷已有最新 Codex Review 的獨立重現紀錄，且目前程式碼仍保留相同邏輯。

參考：最新 WAL 刪除失敗問題

修復方向：

WAL 清除必須納入交易提交條件。

或新增明確的 COMMITTED 狀態，讓復原程序能區分已提交與未提交交易。

必須定義 WAL 清除失敗時的呼叫端結果。

必須補上注入 EACCES 的負向測試。

不能只把 catch 改成重新拋出例外，因為此時 Registry、Journal、Checkpoint 可能已經完成部分或全部發布，仍需要正確的交易狀態機。

R10-B05：isRevoked() 的狀態快照並非原子操作
High · 阻擋

位置：plugin-data-adapter.mjs:2433–2498

目前流程：

JavaScript
const regLoad = loadTrustRegistry(...);

// 檢查 Registry 的 revokedKeyIds

const journalLoad = loadRevocationJournal(...);

// 檢查 Journal

兩個函式各自取得、釋放 governance lock。

isRevoked() 本身沒有將整個狀態檢查包在同一個互斥區段。

可能發生：

程序 A 讀取 Registry，取得尚未撤銷某 Key 的舊狀態。

程序 B 取得 governance lock。

程序 B 寫入經授權的新 Registry，將該 Key 加入 revokedKeyIds。

程序 B 釋放 lock。

程序 A 讀取 Journal。

Journal 仍然有效，HWM 也沒有變動。

程序 A 使用先前取得的舊 Registry，回傳 revoked: false。

這不是簽章偽造，而是不同時間點的合法狀態被組合成一個不一致的安全判斷。

建議：

isRevoked() 應在單一 governance lock 內完成：

WAL Recovery。

Registry 載入與驗證。

Journal 載入與簽章驗證。

HWM、Checkpoint 一致性檢查。

最終撤銷判斷。

內部呼叫應使用既有 lock，不可再次取得同一把非重入鎖。

參考：isRevoked 實作

五、自動化測試覆蓋率覆審

我直接檢查了目前 Head 的 tests/test-plugin-data-adapter.mjs。

Round 09 新增測試位於 1678–1737 行。

測試項目

	

實際覆蓋

	

裁定




B01：CORRUPTED 狀態

	

有

	

PASS




B01：UNKNOWN 狀態

	

有

	

PASS




B01：缺少必要欄位

	

有

	

PASS




B01：偽造 PREPARED WAL

	

無

	

FAIL




B01：舊快照回滾攻擊

	

無

	

FAIL




B02：描述符綁定

	

無專屬測試

	

FAIL




B02：inode 替換競爭

	

無

	

FAIL




B02：rollback 路徑競爭

	

無

	

FAIL




B03：存活 PID 拒絕回收

	

有

	

PASS




B03：無效 PID 拒絕回收

	

無

	

FAIL




B03：reclaim lock 替換競爭

	

無

	

FAIL




B03：finally 誤刪其他持有者

	

無

	

FAIL




B04：WAL unlink 失敗

	

無

	

FAIL




B05：isRevoked 並發快照

	

無

	

FAIL

特別指出：

45/45 測試通過，不代表 45 項安全性主張已經獲得驗證。

目前測試偏重一般成功路徑及特定輸入條件，對於多程序競爭、歷史狀態重播與交易提交失敗的覆蓋不足。

測試檔案：test-plugin-data-adapter.mjs

六、CI 與交付完整性

我另外查核了你提供的三組 GitHub Actions Run ID。

Run ID

	

工作項目

	

結果




42402527715

	

Ubuntu / Windows / macOS

	

SUCCESS




42402527731

	

Semgrep

	

SUCCESS




42402523664

	

CodeQL Actions / JavaScript-Typescript

	

SUCCESS

另外確認：

主程式與 bundled adapter 的 Git blob SHA 相同。

兩份 adapter 的內容逐位元組一致。

tool-integrity-manifest.json 已列入主 adapter 的完整性檢查。

PR 最新 Head 已有 Codex Review，但仍存在未解決的安全審查意見。

有一項證據限制：GitHub 的 per-commit status 與 workflow-run 查詢沒有回傳這三組 Run ID 與指定 Head SHA 的直接關聯紀錄。因此，我能確認這些 Run 的工作結果成功，但不能據此單獨證明每個 Run 都是針對指定 SHA 執行。

七、最終審查裁定

Round 10 Final Verdict

REJECTED
REJECTED

本輪不授予 PR #52 安全驗收通過資格。

阻擋理由：

Critical： 可偽造 PREPARED WAL，重播合法舊快照，移除已建立的撤銷狀態。

High： 交易 rollback 仍有路徑型 TOCTOU 操作。

High： Reclaim Lock 的 PID 驗證與所有權刪除仍存在競爭窗口。

High： WAL 刪除失敗仍回報交易成功，後續復原可能撤銷已確認的操作。

High： isRevoked() 沒有取得一致且原子的治理狀態快照。

這次的核心問題不是 Ed25519 本身，也不是 CI 或測試執行環境。

而是整個治理系統仍然存在一個根本性的信任問題：

系統可以驗證歷史狀態曾經合法，卻無法充分證明目前要求復原的歷史狀態，就是當初真正建立的交易前狀態。

這使得簽章正確、Hash 正確、路徑正確，仍然可能得到錯誤的安全結論。

目前尚不能宣告以下不變量成立：

Authenticated History
≠
Authenticated Recovery
Authenticated History

=Authenticated Recovery
Transaction Success
≠
Durable Commit
Transaction Success

=Durable Commit
Lock Ownership Check
≠
Atomic Lock Release
Lock Ownership Check

=Atomic Lock Release
下一輪進入條件

建議修復順序：

優先級

	

工作項目

	

必要驗收條件




P0

	

WAL 快照來源認證

	

偽造、重播、跨交易替換全部拒絕




P0

	

交易提交狀態機

	

WAL 清除失敗不得回報成功




P1

	

Rollback 描述符安全

	

所有復原及失敗回滾操作一致受保護




P1

	

Reclaim Lock 原子性

	

PID、檔案身分與釋放行為一致




P1

	

isRevoked 原子快照

	

並發撤銷期間不得使用過期 Registry

最重要的設計要求： WAL 必須有不可由一般 PLUGIN_DATA 寫入者偽造的交易來源驗證，而且要綁定交易 ID、前後狀態摘要、檔案集合及提交階段。單純對 WAL 做 SHA-256 不足以解決問題，因為攻擊者可以連同摘要一起重算。

不確定清單：

未查證：未在本環境重新執行完整 45 項測試及實際競爭測試。

使用預設：攻擊者能修改 PLUGIN_DATA 中的 WAL 與相關持久化檔案，但不能取得內嵌信任根的私鑰。

純推測：無；WAL 重播問題及交易提交問題均有目前程式碼控制流程支持。

兩分鐘內的下一步：先將 R10-B01 的偽造 WAL 快照回滾攻擊列為第一個修復任務，不要先處理測試數量或 CI 綠燈。
```
