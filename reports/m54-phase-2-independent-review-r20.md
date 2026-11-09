# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 20

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `917eaf2b6641c616cc03d7030e1962d1e1744ec3`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens Milestone 5.4 Phase 2：Round 20 獨立安全審查
審查進行中，尚未核准

審查基準： 917eaf2b6641c616cc03d7030e1962d1e1744ec3

審查模式： Cold-Start、Adversarial、Read-Only、Evidence-Bound、Default-Deny。

一、審查基準確認

已直接查核 GitHub 上的 PR #52 與指定 Commit。

項目

	

實際查核結果




Repository

	

arcobaleno64/three-lens




PR

	

#52




PR 狀態

	

OPEN




Target

	

main




Head SHA

	

完全吻合




Mergeable

	

TRUE




Changed files

	

43




Commits

	

33




指定 Commit

	

存在

來源：PR #52、指定 Commit。

另外，指定 Commit 的最後一次變更只有調整 R19-B03 測試中的 histV1Path 與 walPath 路徑解析方式。這代表本輪不能只檢查最後一次 Commit，必須檢查整個 Head Commit 的實際檔案狀態。

二、CI 初步查核

GitHub Actions 查詢已取得兩項成功完成的 Workflow：

Semgrep：SUCCESS

Pull Request CI：SUCCESS

但指定 Commit 的 Combined Status 查詢沒有返回任何 Status Entries。

因此，目前只能確認上述兩個 Workflow 成功，尚不能獨立確認你提供的 8/8 Check Runs 清單。即使全部確認成功，也不會取代程式碼安全性審查。

三、發現的重大阻擋項

P1 · 尚未收斂 R20-B01：單調見證未驗證既有 Journal Prefix

位置：

scripts/adapters/plugin-data-adapter.mjs

assertMonotonicWitnessFreshness()

doLoadRevocationJournal()

指定版本程式碼

這是本輪最嚴重的問題。

問題不在於簽章驗證失效，而在於已驗證的簽章鏈可以被另一條合法簽章鏈取代。

目前實際程式碼有以下行為：

doLoadRevocationJournal() 會驗證 Journal 每筆紀錄的 Ed25519 簽章、索引及前後雜湊連結。

assertMonotonicWitnessFreshness() 會拒絕 HWM 回退，也會拒絕相同 HWM 索引卻出現不同 Digest。

但是，當 HWM 索引嚴格增加時，程式允許 Registry Digest 改變，只要求 Non-HWM Identity Digest 不變。

沒有驗證新 Journal 在舊見證索引位置的 Digest，是否仍等於 witness.maxSeenHwmHeadDigest。

因此，攻擊者若同時取得治理檔案寫入權限及一把仍有效的 delegated signing key，可以：

替換原本已提交的 Journal 前綴。

以有效 delegated key 重新簽署替代紀錄。

建立完整的新雜湊鏈。

更新 Checkpoint、Registry HWM 與同版本 History。

將 HWM 推進至比既有見證更大的索引。

目前的驗證邏輯可能接受這條新鏈，卻遺失原先已提交的撤銷紀錄。

安全影響： 已撤銷的 nonce 或其他目標可能重新被判定為未撤銷。這直接破壞 Append-only、Tamper-evident 與 Anti-Rollback 三項核心安全性質。

這不是單純的測試覆蓋率問題，而是授權狀態的完整性問題。

必要修復：在接受 HWM 推進之前，必須驗證候選 Journal 的既有前綴至少完整保留至 witness.maxSeenHwmHeadIndex，且該位置的 Digest 與已持久化見證完全一致。不能只比較新舊 HWM 的索引大小。

四、R19 四項阻擋的逐項覆審

原阻擋項

	

程式碼覆審

	

測試證據

	

Round 20




R19-B01

	

撤銷清單與 ACTIVE 狀態矛盾已拒絕；HWM 簽署者亦有撤銷檢查

	

測試覆蓋不足

	

部分收斂




R19-B02

	

Non-HWM Identity Commitment 已實作

	

95 項測試中的對應案例通過

	

收斂




R19-B03

	

COMMITTED、PREPARED 均加入 History 同步

	

新增測試只直接驗證 PREPARED

	

部分收斂




R19-B04

	

signedBy、簽章及歷史有效視窗修正

	

精確錯誤匹配

	

收斂

R19-B01 的測試證據問題

R19-B01 測試名稱宣稱涵蓋 validation、save、load 與 journal windows。

但檢視 tests/test-plugin-data-adapter.mjs 第 4947 至 5062 行，實際測試直接執行的是：

validateTrustRegistry()

saveTrustRegistry()

沒有直接執行 loadTrustRegistry()，也沒有建立包含該矛盾狀態的 Journal 測試。

因此，不能把測試名稱當作完整覆蓋證據。

另外，HWM 驗證有一個值得注意的保守限制：若 HWM 簽署者已經存在於 priorReg.revokedKeyIds，目前會直接拒絕，即使 HWM 完全等於歷史紀錄。這是 fail-closed 行為，不是授權繞過，但可能要求先以現行有效金鑰推進 HWM，才能繼續更新 Registry。

R19-B02 的收斂範圍

這次修復確實建立了獨立的 Non-HWM Identity Commitment。

涵蓋：

authorizationProof 的簽署者、時間、演算法及前版資訊。

Registry 簽章。

pinnedSince。

rotationPolicy。

keyType。

validFrom、validUntil。

並且在 witness、history 與載入流程中執行比對。

但這只保證 Registry 非 HWM 身分不變，不能取代 Journal 前綴連續性驗證。前述 R20-B01 正好利用兩者之間的缺口。

R19-B03 的收斂範圍

兩個 Recovery 分支都已經加入 History 同步：

COMMITTED：驗證 Registry、Non-HWM Identity 及歷史狀態後同步 History，再更新 witness。

PREPARED：驗證完整 Journal 鏈與 post-image 後同步 History，再更新 witness。

新增測試確實重現了 Registry 已更新、History 尚未更新的中斷狀態，且驗證恢復後可以重新載入 Registry 與 Journal。

但該測試直接建立的是 PREPARED WAL。COMMITTED 分支雖有其他恢復測試，這個特定 History 同步情境尚未獲得對等的專項測試。

R19-B04 的收斂範圍

這項修正成立。

我確認測試使用：

已退役的 authA 簽署偽造 Journal entry。

authB 簽署新的 Checkpoint、HWM 及 WAL。

對 loadRevocationJournal() 與 recoverAbortedRevocationTransaction() 分別要求精確匹配 RETIRED_KEY_AUTHORIZATION_REJECTED。

這能排除因 WAL 簽署者錯誤而提前失敗的假陽性。

五、其他獨立發現

除了前述 P1 前綴問題，還有三項需要修正的問題。

R20-B02：Journal KEY_REVOCATION 未撤銷簽署權限
High · 阻擋

位置：

appendRevocationEntry()：約 L4045–4115

resolveJournalTrustedKeyWindows()：約 L640–715

_isRevokedInner()：約 L4330–4380

目前有兩套不同的撤銷語意：

查詢端：

isRevoked(keyId) 會遍歷 Journal，只要找到 targetId === keyId，就回報已撤銷。

簽署端：

appendRevocationEntry() 只檢查：

registry.revokedKeyIds。

Registry 中的 keys[].status。

私鑰與公鑰是否匹配。

它載入 Journal 後，沒有檢查先前是否已有 KEY_REVOCATION 紀錄撤銷目前的 signedBy。

resolveJournalTrustedKeyWindows() 也只使用 Registry 與歷史 Registry 的撤銷狀態，沒有建立 Journal 層級的簽署權限終止界線。

因此，以下情境仍然成立：

Root 簽署 KEY_REVOCATION，撤銷 delegated key sub。

isRevoked('sub') 回傳 true。

Registry 中 sub 仍是 ACTIVE，且未列入 revokedKeyIds。

sub 再使用自己的私鑰簽署新的撤銷紀錄。

Journal 載入流程仍可能接受這筆紀錄。

這代表 Journal 所宣告的金鑰撤銷，不一定會真正終止該金鑰的簽署能力。

修復要求：

建立統一的 Registry 與 Journal 金鑰撤銷語意。

驗證 Journal 時，依時間順序建立 signer authorization window。

金鑰撤銷事件生效後，禁止該金鑰簽署後續紀錄。

新增「ACTIVE 金鑰被 Journal 撤銷後，仍嘗試追加紀錄」的負向測試。

R20-B03：COMMITTED 交易在 Witness 寫入失敗時仍可能被回滾
Medium · 阻擋

位置：

updateMonotonicWitness()：約 L3120–3305

appendRevocationEntry()：約 L4160–4290

PREPARED Recovery：約 L1185–1225

目前 updateMonotonicWitness() 的順序：

更新 _DIR_MONOTONIC_WITNESS 記憶體狀態。

寫入 local witness。

寫入 system witness。

問題在於，假設第一個 witness 寫入成功，第二個失敗：

Local witness 已經前進。

System witness 尚未前進。

updateMonotonicWitness() 拋出錯誤。

接著 appendRevocationEntry() 的外層 catch 會執行交易回滾：

還原 Journal。

還原 Checkpoint。

還原 Registry。

還原 History。

刪除 WAL。

但是，它沒有還原已經前進的 witness。

這會產生：

𝑊
local
>
𝑅
disk
W
local
	​

>R
disk
	​


後續讀取可能因單調見證超前而永久拒絕舊狀態。

更重要的是，這次回滾發生在 WAL 已經標記為 COMMITTED 之後。

這與 COMMITTED 應代表不可回滾的交易狀態互相矛盾。

PREPARED Recovery 也有類似問題：更新 witness 發生一般錯誤時，外層 catch 可能繼續進入回滾流程。

修復要求：

明確定義 COMMITTED 的不可逆提交點。

一旦 COMMITTED WAL 已持久化，不應因 witness 次要錨點寫入失敗而回滾交易。

保留 WAL，讓 Recovery 重試完成雙錨點同步。

對兩個 witness 先後寫入失敗進行故障注入測試。

R20-B04：Storage Write 未檢查實際寫入位元組數
Medium · 阻擋

位置：

safeWriteFileSync()：約 L300–340

appendRevocationEntry()：約 L4160–4185

目前兩個重要路徑都採取單次寫入：

JavaScript
fs.writeSync(fd, content, null, 'utf8');

以及：

JavaScript
fs.writeSync(fd, line, null, 'utf8');

兩者都沒有檢查實際回傳的 bytesWritten。

safeWriteFileSync() 接著就會：

fsync。

關閉檔案。

Rename 覆蓋正式檔案。

如果發生 short write，截斷的暫存檔仍可能被發布。

Journal append 的問題更直接：即使 Journal 只寫入部分紀錄，後續仍可能繼續發布 Checkpoint、Registry HWM 與 Witness。

這會造成已提交的錨點指向一份不完整的 Journal。

修復要求：

使用 write-all loop。

直到所有位元組寫完才允許發布。

short write 必須觸發交易失敗。

Journal 不完整時不得提交 Checkpoint、Registry HWM 或 Witness。

六、完整性與 CI 證據
可取得的 CI 工作均成功

項目

	

實際查核結果




Linux CI

	

SUCCESS




Windows CI

	

SUCCESS




macOS CI

	

SUCCESS




Semgrep

	

SUCCESS




plugin-data tests

	

95/95 PASS




Release evidence

	

29 files PASS




Release invariants

	

PASS




Documentation integrity

	

PASS

Ubuntu Actions 日誌直接顯示：

純文字
# tests 95
# pass 95
# fail 0

三個作業系統的 CI 工作均成功。

另外確認：

兩份 plugin-data-adapter.mjs 的 Git Blob SHA 相同：

5d2b66c39a5078522e8d0cabd48ba40d523b8a91

這確認兩份檔案逐位元組一致。

tool-integrity-manifest.json 包含使用者提供的 Adapter SHA-256。

evals/evidence-matrix.json 包含 Adapter 與 Manifest 的預期 SHA-256。

.github/workflows/pull-request-ci.yml 已使用 fetch-depth: 0，因此先前關於 shallow checkout 無法取得歷史 Commit 的問題，不適用於目前版本。

需要保留一項限制：Combined Status API 沒有返回 Status Entries，因此我不能獨立確認使用者列出的全部 8 個 Check Runs。這不代表 CI 失敗，只代表該項總數尚未獲得獨立確認。

七、正式裁定
REJECTED
Round 20：拒絕合併

PR #52：不得合入 main。

理由：

R20-B01：Journal Prefix Continuity 缺失，已提交撤銷紀錄可能被替換。

R20-B02：Journal KEY_REVOCATION 未真正終止被撤銷金鑰的簽署能力。

R20-B03：Witness 部分寫入失敗可能造成 COMMITTED 交易回滾與永久鎖死。

R20-B04：Short Write 可能將不完整的治理檔案當成成功結果發布。

R19-B01～B04 的局部修復有實質進展，但不能推導出整體安全不變量成立。

最重要的判斷：

目前 Three-Lens 已經具備相當完整的簽章驗證、Registry 身分承諾、歷史快照與 WAL 恢復機制。

但仍然存在一個根本問題：

Valid Signature
≠
Authorized Historical State
Valid Signature

=Authorized Historical State

一條密碼學上完全合法的新簽章鏈，不代表它有權取代已經被獨立見證的歷史狀態。

這是 Round 20 不予核准的核心原因。

本輪採唯讀方式，沒有修改 Repository、提交程式碼或發布 GitHub Review。

不確定清單

未查證：8/8 Check Runs 的完整獨立清單。

未執行：本機 Clean-Room 攻擊重播；判定依指定 Commit 原始碼及 GitHub Actions 證據。

純推測：無。

下一步： 維持 PR #52 OPEN，先將 R20-B01 設為最高優先修復項，加入「舊 HWM 前綴被替換但新鏈簽章全部有效」的負向測試，再進行 Round 21 覆審。
```
