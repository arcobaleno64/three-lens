# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 21

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `36d0e9ba1cfc7a7d2b8ece5002f73fda8156081a`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 21 獨立安全審查
Default-Deny · 尚未授權合併
一、審查基準與權威邊界

透過 GitHub 連線核對，本輪審查標的如下：

項目

	

核對結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Base

	

main




Head Branch

	

feat/m54-phase-2-governance




固定 Commit

	

36d0e9ba1cfc7a7d2b8ece5002f73fda8156081a




PR 狀態

	

OPEN、Mergeable




GitHub Actions

	

兩個 Workflow Runs 均為 Success




審查模式

	

Cold-Start / Adversarial / Read-Only

判定原則： Mergeable = TRUE 與 CI Success 不構成密碼學安全性證明。任何一項權威邊界未獲正面驗證，即不得裁定 APPROVED。

本輪不修改程式碼、不更新 GitHub Review 狀態、不執行 PR Merge，亦不以先前審查報告替代本輪原始碼證據。

二、重大新發現：R21-B01
P1 · 未授權權威重新授予

已由實際原始碼確認：Journal 的 KEY_REVOCATION 能禁止被撤銷金鑰追加 Journal，卻沒有同步禁止該金鑰簽署新版 Trust Registry。

這是 R20-B02 修補範圍之外的跨權威通道缺口。

直接程式碼證據

路徑

	

實際行為




appendRevocationEntry() L4153–4162

	

會檢查 Journal 的 KEY_REVOCATION，拒絕已撤銷簽署者




createAuthorizedRegistryUpdate() L2140–2160

	

僅檢查 Registry 的 revokedKeyIds 與 keys[].status




validateTrustRegistry() L1980–2108

	

使用先前 Registry 的金鑰狀態驗證新版 authorizationProof，沒有查詢 Journal 撤銷事件




saveTrustRegistry() L3532–3735

	

驗證 Registry 與單調見證後即可持久化新版 Registry，沒有要求新簽署者通過 Journal 撤銷檢查

攻擊路徑

以 R20-B02 測試已建立的狀態為起點：

Registry v2 中，金鑰 A 為 ACTIVE，且攻擊者掌握 A 的合法私鑰。

Root 在 Journal index 1 寫入 KEY_REVOCATION(targetId=A)，但 Registry v2 仍將 A 標為 ACTIVE。

攻擊者使用 A 簽署 Registry v3 的 authorizationProof，加入自己控制的新金鑰 B，並保留既有 HWM。

createAuthorizedRegistryUpdate() 與 validateTrustRegistry() 的既有判斷不會因 Journal 已撤銷 A 而拒絕該授權。

B 因新版 Registry 成為可被信任的 ACTIVE 金鑰，取得新的治理簽署能力。

這不需要破壞 Ed25519，也不需要重寫既有 Journal prefix。問題是已撤銷金鑰的權威仍可沿另一條授權路徑延續。

此攻擊路徑屬於程式碼層級的高信心推導，尚未透過完整 Node.js 執行環境重播；真正的端對端驗收應建立 Registry v3 後，確認 B 是否能成功追加新的 Journal 條目。

本項足以阻擋 APPROVED。 若實測發現存在已核驗、會拒絕這條路徑的其他授權檢查，本項可重新評估；目前指定版本的上述路徑沒有這項檢查。

三、R20-B01～B04 修補驗收結果

Finding

	

裁定

	

證據與剩餘限制




R20-B01 · Journal Prefix Continuity

	

HOLDS

	

L3463–3500、L3984–4003 已加入 witnessed prefix digest 比對，對應替代歷史測試通過




R20-B02 · KEY_REVOCATION

	

PARTIALLY HOLDS

	

Journal 讀寫防線有效，但 Trust Registry 更新路徑仍允許已撤銷簽署者授權，衍生 R21-B01




R20-B03 · COMMITTED WAL

	

待完整驗證

	

L4330–4336 已避免 COMMITTED 後回滾；但現有測試未注入真實 secondary witness 寫入失敗




R20-B04 · Short Write

	

HOLDS

	

writeAllSync() 已供兩個寫入路徑共用；直接故障注入測試主要覆蓋 safeWriteFileSync()

R20-B01 與 B04 的修補可在上述限定範圍內接受。

R20-B03 目前確認有正確方向的程式碼防護，但驗收證據尚不足以證明所有磁碟失敗時序均能恢復。尤其 txnData.status 在記憶體中先切換為 COMMITTED，再將新 WAL 寫入磁碟，應補充該寫入失敗與程序中斷之後的重啟驗證。

參考：R20-B03 測試 L5669–5798。

四、CI 與供應鏈完整性驗證

GitHub Check Runs

8/8
Success，已由 GitHub API 驗證

Adapter Tests

99/99
CI 日誌確認

SARIF Tests

121/121
CI 日誌確認

CI 原始證據：Ubuntu CI Job。

另外，獨立計算實際檔案 SHA-256，發現委託內容有一處必須更正。

物件

	

驗證結果




兩份 plugin-data-adapter.mjs

	

完全相同




Adapter SHA-256

	

eb36e5fe…18a63703，符合




Manifest 實際 SHA-256

	

c6975913…9315e73e




委託所列 Manifest SHA-256

	

9fae5c9d…6ee76b88，不符合




Evidence Matrix

	

已記錄正確的 c6975913…9315e73e

因此，這是委託證據的摘要值不一致，並非已證實的 TCB 檔案遭竄改。不能將該差異誤報為新的密碼學漏洞。

參考：Tool Integrity Manifest 與 Evidence Matrix L40–51。

五、修復與重新驗收條件

R21-B01 不宜只在 createAuthorizedRegistryUpdate() 補上一個 isRevoked() 呼叫。攻擊者可以直接構造磁碟上的已簽署 Registry，因此儲存與讀取驗證也必須拒絕失效的權威。

建議採取以下修復順序：

定義單一金鑰生命週期授權規則，使 Journal KEY_REVOCATION 同時影響 Registry 更新授權。

在 Registry 建立、保存、讀取及 WAL 復原入口執行一致的授權驗證，避免驗證函式互相呼叫造成遞迴。

建立可信任的歷史授權順序證據，區分「撤銷前已成立的歷史簽章」與「撤銷後新產生的授權」，不可僅依可自行填寫的時間戳判斷。

補上 A 已遭 Journal 撤銷後，仍嘗試簽署 Registry v3 並新增 B 的端對端負向測試。

補上 COMMITTED WAL 寫入、雙見證同步及程序中斷的故障注入測試，並以乾淨程序重啟驗證。

修復後，必須觀察到被撤銷 A 的 Registry 更新遭拒絕、新金鑰 B 無法獲得授權，而撤銷前已合法提交的歷史 Registry 仍可驗證，才能關閉 R21-B01。

六、Round 21 正式裁定
REJECTED
禁止合併

決定性阻擋項：R21-B01 · P1

Journal 撤銷金鑰的效果未涵蓋 Trust Registry 授權鏈。持有已撤銷 delegated private key 的攻擊者，仍可能透過新版 Registry 重新建立簽署權威。

適用範圍：Commit 36d0e9ba1cfc7a7d2b8ece5002f73fda8156081a，2026-11-09 審查。

本裁定由原始碼分析、固定版本檔案雜湊核對與 GitHub CI 證據支持。沒有執行獨立 Node.js 動態漏洞重播，因此不宣稱已取得實際執行時的利用成功紀錄。

不確定清單

未查證：完整端對端 A → Registry v3 → B 簽署攻擊的實際執行結果。

預設：攻擊者掌握已撤銷 A 的私鑰及治理目錄寫入能力，不掌握不可竄改的外部見證。

推測：完整負向測試將重現 R21-B01；若存在目前未觀察到的額外拒絕機制，須以執行證據重新裁定。

下一步（2 分鐘內）： 將 R21-B01 的攻擊路徑與四個關鍵程式碼位置記錄為 PR #52 的 Blocking Finding，維持 PR OPEN，不予合併。
```
