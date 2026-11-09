# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 17

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `1f1c06eea79d652cdc04da3830bd392b9a1ae752`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
REJECTED
Three-Lens PR #52｜Round 17 獨立安全審查

裁定：REJECTED，禁止依本輪審查結果核准合併。

審查欄位

	

結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




固定 Head SHA

	

1f1c06eea79d652cdc04da3830bd392b9a1ae752




PR 狀態

	

OPEN、Mergeable




審查日期

	

2026-11-08（臺灣時間）




審查模式

	

Cold-Start / Adversarial / Read-Only




採納原則

	

Default-Deny




合併授權

	

NOT AUTHORIZED

已透過 GitHub 取得指定 Commit 的實際程式碼，而非只依據修復說明判斷。GitHub 回報該 SHA 的 Pull Request CI 與 Semgrep 工作流程均成功。

不過，CI 成功無法抵銷以下已發現的授權邊界問題。

一、已確認的阻擋發現
R17-B01 · Critical：公開 API 仍能直接推進永久 Monotonic Witness

R16-B02 修復未形成完整權限封閉

直接程式碼證據

檔案：scripts/adapters/plugin-data-adapter.mjs

L2649–2653：updateMonotonicWitness() 仍是公開匯出函式，沒有驗證呼叫者是否持有內部權限。

L2655–2684：直接接受呼叫者提供的 Registry Version 與 Digest，並更新見證狀態。

L2737–2760：由同一公開函式進入持有私有 Symbol Token 的寫入路徑，將結果持久化至兩份 Witness。

這代表 safeWriteFileSync() 封鎖外部旗標雖然有效，卻沒有封鎖較高階的公開寫入入口。

可由程式碼推導的反例： 同一執行權限下的呼叫者，無須取得私有 Symbol 或 Ed25519 私鑰，即可透過已匯出的 updateMonotonicWitness() 提交極高 Registry Version 與任意格式正確的 Digest。隨後正常載入較低版本 Registry 時，將遭遇 Monotonic Regression，形成持久性可用性阻斷。

這是權限界限的缺陷，不是單純少寫一個測試。

必要修正： 將 Witness 狀態變更收斂至不可由公開 API 直接呼叫的受控交易通道，並在寫入前驗證完整的授權來源及已提交狀態。

R17-B02 · High：Registry Digest 仍未涵蓋完整安全身分

R16-B04 的完整內容承諾宣告不成立

原始碼 L1215–1282 顯示：

computeRegistryAuthorizationPayload() 的每筆 Key 只選取 keyId、keyFingerprint、publicKeyPem、status、issuedAt，沒有納入每筆 Key 的 roles、validFrom、validUntil。

computeRegistryIdentityPayload() 的 authorizationProof 選取 signerKeyId、signedAt、signature、priorRegistryVersion，但實際驗證器使用的是 authorizationProof.authorizedBy，該欄位沒有納入身分承諾。

revocationHighWaterMark 亦未納入 Registry Identity Payload。

因此，修改上述未承諾欄位，可能產生不同的 Registry 物件，卻具有相同的 Registry Digest。

這是可由欄位投影直接證明的缺陷，不需要假設 SHA-256 發生密碼學碰撞。它也不等同於已證明能繞過其他獨立的 HWM 或簽章驗證，兩者必須區分。

必要修正： 對實際持久化的 Registry 建立明確、安全欄位完整的 Canonical Identity Schema，並增加每個安全欄位單獨異動的 Digest 差異測試。

R17-B03 · High：COMMITTED WAL 仍未驗證整條 Journal

R16-B03 修復不完整

原始碼 L766–870

程式確實新增 validateTrustRegistry(curReg)，但 Journal 驗證仍存在缺口。

在第 803–835 行，程式讀取整份 Journal 後，僅取出 journalLines[journalLines.length - 1]，驗證尾筆的索引、Digest 及簽章。

程式沒有在 COMMITTED 復原流程中呼叫完整的 doLoadRevocationJournal() 驗證，也沒有逐筆驗證中間紀錄。

相較之下，L3325–3386 已經存在完整逐筆驗證邏輯，但 COMMITTED 復原路徑未使用。

對抗反例： 保留合法且簽署完成的 WAL、Registry、Checkpoint 與 Journal 尾筆，僅竄改 Journal 中間紀錄。COMMITTED 分支仍可能通過尾筆檢查，然後執行 updateMonotonicWitness()，最後刪除 WAL。

此情境沒有證明攻擊者能偽造有效的 Ed25519 簽章，但足以推翻「復原前已驗證完整 Journal」的安全宣告。

R16-B03 測試 L3871–3961 只測試無效的 v100 Registry，沒有覆蓋「合法 Registry 搭配損壞的中間 Journal 紀錄」。

必要修正： COMMITTED 復原在推進 Witness 前，必須完成整條 Journal 的索引、Hash Chain、簽章與金鑰生命週期驗證。PREPARED WAL 的已完成交易判定路徑也應適用同一驗證條件。

R17-B04 · High：WAL 簽署者仍可能使用已退休的歷史根金鑰

R16-B03 金鑰生命週期檢查存在缺口

原始碼 L698–749

第 703–712 行只有在 txnData.signedBy 能於現行 curReg.keys 找到時，才檢查該金鑰是否為 RETIRED 或 REVOKED。

如果舊根金鑰已被移除，程式沒有直接拒絕。

反而在第 722–729 行仍可能透過 DEFAULT_SUPERVISOR_PUBLIC_PEM 或 Embedded Root Registry 驗證 WAL 簽章。

因此，「能通過歷史根金鑰的密碼學簽章驗證」仍可能被誤用為「具有目前 WAL 授權」。

這不代表攻擊者已能繞過所有 COMMITTED 後置條件；但簽署者必須屬於現行有效金鑰集合的前置不變量，並未由程式完整保證。

必要修正： WAL 簽署者必須在經過驗證的現行 Registry 中存在，而且其狀態必須是 ACTIVE 或 ACTIVE_PINNED_ROOT。只有在明確受控的 Genesis Bootstrap 情境下，才能採用 Embedded Root 授權。

R17-B05 · Critical（條件式）：雙本機 Witness 無法保證抵抗全狀態回滾

R16-B01 的防護範圍仍受信任錨點限制

原始碼 L2417–2426

系統的兩份 Witness 分別儲存在 PLUGIN_DATA 目錄，以及使用者家目錄下的 .three-lens/witness。

第 2553–2591 行 顯示外部 Witness 是選用設定，並非強制可信來源。

在攻擊者具備覆寫兩份本機 Witness、Registry、History 與 Journal 的能力，且能重新啟動程序的前提下，可將整組檔案還原成曾經有效的歷史快照。

重新啟動後，程序內記憶體 Witness 也無法保留後續版本的資訊。

此時兩份 Witness 彼此一致，不能證明它們就是最新狀態。

這是 Anti-Rollback 信任模型的限制，而不單純是 SHA-256 或 Ed25519 實作問題。

必要修正是明確定義威脅模型：若承諾抵抗全狀態回滾，必須使用攻擊者無法同步回滾、且能提供新鮮度保證的外部信任錨點；若不支援，則必須縮限安全宣告。

二、Round 16 五項阻擋點覆審

前輪項目

	

Round 17 結果

	

主要理由




R16-B01：歷史鏈摘要

	

PARTIALLY HOLDS

	

歷史遍歷已加入，但全狀態回滾保證不足




R16-B02：私有寫入權限

	

OVERTURNED

	

公開 updateMonotonicWitness() 可推進永久見證




R16-B03：COMMITTED WAL

	

OVERTURNED

	

完整 Journal 未驗證，且簽署者生命週期檢查有缺口




R16-B04：Registry Digest

	

OVERTURNED

	

authorizedBy、timestamp、HWM 與部分 Key 欄位未承諾




R16-B05：Witness Schema

	

PARTIALLY HOLDS

	

指定格式檢查存在，但無法保證歷史承諾完整性與來源可信

另外，Witness Schema L2495–2512 只要求最大版本對應 Digest 存在，並未要求所有先前版本的 Digest 鍵都存在。這應納入下一輪負向測試，但不另列成獨立的高風險阻擋項。

三、CI 與 TCB 證據驗證

GitHub API 確認指定 Commit 有八項成功的 Check Runs，包括 CodeQL、Semgrep、三個作業系統的 CI，以及兩個 CodeQL Analysis Jobs。

Ubuntu CI 紀錄亦確認：

檢查

	

GitHub 紀錄




Plugin Data Tests

	

81 PASS、0 FAIL




Release Evidence

	

29 files verified




Release Invariants

	

62 Specifications、40 Invariants PASS




Windows / macOS / Ubuntu

	

全數成功

但是，本輪並未在獨立本機環境重新執行測試。這些數據屬於已查證的 GitHub CI 執行紀錄，不是本審查員重新執行的證據。

另有一項需要修正的證據基準差異：指定 SHA 的實際 Manifest 與 Evidence Matrix 已不是委託內容列出的雜湊值。

項目

	

委託提供

	

指定 Commit 的記錄




Adapter SHA-256

	

15717ec0…26c

	

7e5793b7…d09




Manifest SHA-256

	

1a86a1ee…cc

	

9942400c…f63

這兩組差異代表委託所附雜湊值與固定 Commit 的記錄不一致，不代表已證明該 Commit 內部的雙層完整性檢查失敗。GitHub CI 的檢查確實成功，且兩份 Adapter 檔案回傳相同 Git Blob SHA。

來源：Tool Integrity Manifest；Evidence Matrix。

四、重新核准的必要條件

優先序

	

必須完成的驗證

	

可推翻本輪發現的觀察




P0

	

封閉公開 Witness 更新入口

	

外部模組無法改寫或推進 Witness，且兩份持久檔案維持不變




P0

	

完整 WAL 復原驗證

	

中間 Journal 紀錄遭竄改時，Witness 不更新、WAL 不刪除




P1

	

WAL 簽署者有效性

	

從現行 Registry 移除的舊根金鑰不能核准 WAL




P1

	

Registry Identity 完整承諾

	

每個安全關鍵欄位的獨立修改都產生不同 Digest




P1

	

明確定義 Anti-Rollback 邊界

	

全狀態回滾被可信外部錨點偵測，或正式縮限保證範圍

以上測試必須針對修復後的新 SHA 執行，不能沿用本次 CI 成績作為修復完成證據。

五、獨立審查限制

本輪完成指定 Commit 原始碼、相關專屬測試、CI 工作流程與雙層 Manifest 記錄的唯讀查核。沒有修改、提交、合併或公開發布任何程式碼。

不確定清單

未查證：尚未獨立重播上述對抗反例，因此實際執行效果仍需測試確認。

預設前提：全狀態回滾情境假設攻擊者能覆寫兩份本機 Witness 及其依賴狀態。

推測：跨程序競爭可能擴大公開 Witness 更新入口的影響，但本輪未重現該競爭條件。

未獨立驗證：指定 SHA 之原始檔案 SHA-256 尚未由本審查環境重新計算。

最終處置：R17-B01～R17-B05 應保留為 OPEN；PR #52 維持 REJECTED。

下一步：先針對 R17-B01 建立一個負向測試，直接從外部模組呼叫 updateMonotonicWitness()，確認是否能在沒有任何簽署權限的情況下推進永久 Witness。這是本輪最直接、最容易獨立驗證的阻擋反例。
```
