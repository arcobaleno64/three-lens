# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 18

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `8eb5bb5c499481c13d2d992c44b6451c14b9a010`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52｜Round 18 獨立安全審查報告
REJECTED · 不核准合併

裁定：REJECTED。指定 Commit 仍存在可由原始碼直接確認的 WAL 簽署者授權缺口，R17-B04 未完成封閉。

本輪已直接讀取 GitHub 上指定 Commit 的程式碼，並非僅根據修復說明或既有審查結論判斷。

審查項目

	

固定基準




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




Target

	

main




審查分支

	

feat/m54-phase-2-governance




固定 Commit

	

8eb5bb5c499481c13d2d992c44b6451c14b9a010




審查日期

	

2026-11-08（臺灣時間）




審查模式

	

Cold-Start / Adversarial / Read-Only




審查規則

	

Default-Deny




合併授權

	

NOT AUTHORIZED

一、已確認的阻擋缺陷
R18-B01 · High：WAL 仍容許已移除的創世根金鑰繞過現行 Registry 授權

對應前輪：R17-B04，修復宣稱遭原始碼推翻。

檔案：scripts/adapters/plugin-data-adapter.mjs

直接證據：

L766–786：讀取現行 Registry 後，只在簽署者仍存在於 curRegRaw.keys 時，才檢查 RETIRED 或 REVOKED；若金鑰已被移除，並未直接拒絕。

L788–796：當 txnData.signedBy 等於 DEFAULT_SUPERVISOR_KEY_ID 時，直接採用 DEFAULT_SUPERVISOR_PUBLIC_PEM，未要求該金鑰仍存在於現行 Registry。

L797–813：只有未命中前述預設根金鑰等條件時，才嘗試透過 doLoadTrustRegistry() 尋找現行有效金鑰。

L819–831：隨後使用選定的公鑰驗證 WAL 簽章。

原始碼：固定 Commit，L766–831

這形成明確的授權繞過路徑：

現行 Registry v2

創世根金鑰已從 keys 移除

舊根金鑰簽署 WAL

signedBy === DEFAULT_SUPERVISOR_KEY_ID

舊根公鑰仍被選為驗證金鑰

跳過現行 Registry 的有效金鑰集合檢查

這足以推翻「現行 Registry 存在時，WAL 簽署者必須屬於現行 ACTIVE / ACTIVE_PINNED_ROOT 金鑰集合」的不變量。

此處確認的是授權驗證缺陷，不是宣稱已實際取得舊根私鑰，也不是宣稱所有 WAL 後置檢查都可被繞過。攻擊者仍須持有能產生有效簽章的私鑰，或已有符合該條件的歷史簽署 WAL。

必要修正： 必須先驗證現行 Registry，再從已驗證的現行有效金鑰集合選擇 WAL 簽署者公鑰；只在嚴格證實沒有既存 Registry、沒有後續 Witness 或歷史狀態，且符合 Genesis Bootstrap 授權條件時，才允許創世根金鑰。

可推翻此發現的證據： 對固定 Commit 展示一條必經且不可繞過的現行 Registry 授權守衛，能在上述舊根金鑰情境下於簽章驗證前拒絕 WAL。單純證明簽章正確，不構成授權有效的證據。

R18-B02 · High：Registry Identity Digest 未承諾 HWM，且同版本摘要演進規則與宣告不符

對應前輪：R17-B02，僅部分修復。

程式碼證據：

L1261–1288：computeRegistryAuthorizationPayload() 已納入每筆金鑰的 roles、validFrom、validUntil，這部分修復成立。

L1300–1329：computeRegistryIdentityPayload() 納入部分 authorizationProof 欄位、外層簽章與 Registry metadata，但完全沒有納入 revocationHighWaterMark。

L1306–1318：signerKeyId 與 signedAt 僅作為其他欄位缺失時的替代值，並非兩者都被完整承諾。

L2748–2765：同一 registryVersion 的 Digest 不一致時直接拒絕，並沒有檢查 hwmHeadIndex 是否嚴格遞增後允許合法摘要演進。

原始碼：Registry Digest 投影；Witness 更新規則

因此，就 computeRegistryDigest() 而言，以下不變量並未成立：

𝐻
(
𝑅
𝑣
,
𝐻
𝑊
𝑀
𝑖
)
≠
𝐻
(
𝑅
𝑣
,
𝐻
𝑊
𝑀
𝑖
+
1
)
H(R
v
	​

,HWM
i
	​

)

=H(R
v
	​

,HWM
i+1
	​

)

目前程式會因為 HWM 不在摘要投影中，而讓只改變 HWM 的兩份 Registry 產生相同摘要。

這不等於已證明能繞過獨立的 HWM 簽章、Checkpoint 或 Witness index 驗證，但足以推翻「Registry Identity Digest 完整承諾所有安全關鍵欄位」的宣告。

另一項證據問題出現在 測試 L4217–4265：測試名稱宣稱涵蓋 HWM，實際僅斷言 authorizedBy、timestamp、外層 signature 異動會改變 Digest，沒有 HWM 異動斷言。

測試：R17 Registry Digest 負向測試

必要修正： 先定義 HWM 版本化承諾模型，再一致修改 Digest、Witness 的合法同版本推進規則與歷史驗證。不能只把 HWM 加進 Digest，否則目前的同版本分歧守衛可能把合法 Revocation Append 也拒絕。

可推翻此發現的證據： 在固定版本下，單獨變更 headIndex、headDigest、updatedAt、authorizedBy、HWM signature，每次都能得到不同 Digest，且經授權的 HWM 遞增可通過 Witness 更新，而同索引分岔必須被拒絕。

R18-B03 · High：公開 Getter 洩漏可變的內部 Witness 物件

對應前輪：R17-B01，直接更新入口已封閉，但記憶體完整性仍有缺口。

本輪確認 updateMonotonicWitness() 在 L2734–2737 確實加入模組私有 WeakSet 守衛。assertSafeStorageTarget() 也採用同樣的物件身分檢查。

然而，另一個公開函式仍暴露內部可變狀態：

L2491：_DIR_MONOTONIC_WITNESS 是模組內部 Map。

L2503–2519：getMonotonicWitness() 直接取得 Map 中的 memWitness 物件。

L2638–2679：允許呼叫者傳入 externalMonotonicWitness 推高記憶體中的版本界線。

L2680：直接 return memWitness，沒有複製、凍結或隔離。

原始碼：Witness 公開 Getter 與可變狀態

依 JavaScript 物件參考語義，外部呼叫者可以取得與模組內部相同的 Witness 物件，並修改其欄位。

JavaScript
// 對抗性反例：公開 API 記憶體污染
const witness = getMonotonicWitness(pluginDataDir, options);
witness.maxSeenRegistryVersion = 1000000;

// 隨後合法的 registryVersion=2 載入，
// 會被記憶體中的 maxSeenRegistryVersion=1000000 阻擋。


這條路徑不需要呼叫 updateMonotonicWitness()，也不需要取得私有 Symbol。

判定邊界必須精確：此反例可由程式碼證明能修改內部記憶體 Witness，並導致同一行程內的合法版本載入被拒絕；尚未證明可以直接污染持久化 Witness 或在行程重啟後繼續生效。

必要修正： 將內部可變 Witness 與公開唯讀 Snapshot 分離。對外回傳深層複本或不可變結構，並防止未認證的呼叫者藉由 externalMonotonicWitness 改寫共用的單調狀態。

可推翻此發現的證據： 外部模組修改 Getter 回傳值，或提交極高的 externalMonotonicWitness.minRegistryVersion 後，內部 Witness 的權威狀態及後續合法載入結果完全不受影響。

R18-B04 · High：完整 Journal 驗證器的歷史金鑰生命週期判斷不一致

對應前輪：R17-B03，Journal 全鏈驗證已實作，但授權語意未完整收斂。

新增的 verifyFullJournalChain() 在 L643–697 確實逐筆驗證 entryIndex、prevEntryDigest、Ed25519 簽章與目標 Head Digest。

COMMITTED 分支於 L875–882 呼叫此函式，PREPARED 的已完成交易判定也在 L1043–1050 呼叫。這部分修復成立。

不過，驗證器存在兩個問題：

L668–673：只要歷史紀錄的簽署金鑰在現行 Registry 中標為 RETIRED，便直接拒絕，即使該紀錄是在金鑰仍有效時簽署。

L675–677：若金鑰不存在於現行 Registry，仍可能回退採用 DEFAULT_SUPERVISOR_PUBLIC_PEM，無法證明該簽署者在紀錄產生時具備授權。

相較之下，一般 doLoadRevocationJournal() 在 L3351–3398 另有歷史金鑰有效期間解析邏輯。兩條驗證路徑並未採用同一套授權規則。

原始碼：完整 Journal 驗證器；一般 Journal 歷史金鑰處理

影響： 合法歷史紀錄可能因金鑰輪替而使 COMMITTED WAL 無法復原；另一方面，已移除的創世根金鑰仍可能在 Journal 驗證中獲得不適當的信任。

必要修正是共用經驗證的歷史金鑰授權解析器，以紀錄所屬的可信版本及有效區間判定簽署權，不應將「目前有效」與「簽署當時有效」混為一談。

可推翻此發現的證據：建立包含舊根金鑰合法歷史簽章與新根金鑰後續簽章的完整 Journal，證明 COMMITTED/PREPARED 復原能接受合法歷史紀錄，同時拒絕在撤銷或退休後新產生的非法紀錄。

二、Round 17 阻擋項逐項裁定

前輪項目

	

Round 18 裁定

	

主要依據




R17-B01：Witness 權限封閉

	

PARTIALLY HOLDS

	

WeakSet 守衛成立；Getter 可變狀態洩漏




R17-B02：Registry Digest、歷史完整性

	

PARTIALLY HOLDS

	

Key 欄位及歷史損毀檢查改善；HWM 未納入 Digest




R17-B03：完整 WAL Journal 驗證

	

PARTIALLY HOLDS

	

全鏈遍歷成立；歷史金鑰授權判斷不一致




R17-B04：WAL 現行簽署者授權

	

OVERTURNED

	

舊根金鑰 fallback 仍存在




R17-B05：Anti-Rollback 威脅邊界

	

HOLDS（限縮範圍）

	

已正式揭露全狀態回滾限制

對 R17-B05，已確認 SECURITY.md L91–95 正式新增威脅模型及非保證範圍。這足以支持「已完成文件界定」，但不代表系統已獲得抵抗 Full-Host Snapshot Restore 的技術能力。另外，「isolated filesystems」一詞未由兩個不同路徑的實作保證，應改為「separate local storage locations」，避免誤述實際部署隔離程度。

來源：SECURITY.md §2.9

附加項目 R17-E01（稀疏 Witness）已有逐版本稠密性守衛，R17-E02（COMMITTED WAL 中間紀錄損毀）已有對應測試及完整鏈驗證呼叫。兩者在已檢查範圍內成立，但不能延伸宣稱已覆蓋所有崩潰時間點與跨程序競爭情境。

三、CI 與 TCB 證據查核

雙層 TCB 雜湊一致性：PASS

本輪使用從 GitHub 指定 SHA 取得的實際檔案內容，獨立重新計算 SHA-256，而非僅比對 Manifest 中宣告的文字。

檢查項目

	

結果




主程式 Adapter SHA-256

	

PASS




skills/3lens 鏡像 Adapter SHA-256

	

PASS




Layer 1 Manifest 的 Adapter 雜湊

	

PASS




Manifest 檔案 SHA-256

	

PASS




Layer 2 Evidence Matrix 參照雜湊

	

PASS

Adapter：兩份檔案實際計算的 SHA-256

c247a07273c0f3cc23d79ea184758a49479a4f164edb4c4c48c34a400b6aafd2

Tool Integrity Manifest：實際計算的 SHA-256

05084bdf6208e173fa7fb20fbcab76342c4b9242601e7b32dbcd1b328257c12c

GitHub CI 已核對工作：SUCCESS

本輪取得固定 SHA 的 Pull Request CI 與 Semgrep 執行紀錄：

Ubuntu、Windows、macOS CI：均成功。

Semgrep workflow：成功。

Ubuntu CI Log：Plugin Data Tests 88 PASS、0 FAIL。

render-sarif.mjs：121/121 PASS。

Release Evidence：29 files verified；Release Gate：62 specifications、40 security invariants PASS。

上述數據已透過 GitHub Actions 工作紀錄核對。8/8 全部 Check Runs 的逐項列表未在本輪介面完整取得，因此不宣稱已逐一獨立確認八項。

CI 與對抗性安全審查不是同一件事。尤其 R17-B04 的現有測試 L4393–4490 只建立了舊金鑰仍留在 keys、狀態為 RETIRED 的情境，沒有建立舊金鑰已完全移除的情境。因此該測試通過，並不能推翻 R18-B01。

測試證據：R17-B04 既有測試；Pull Request CI；Semgrep

四、正式裁定及驗收門檻
ROUND 18
REJECTED
Open Blocking Findings
4
Release Authorization
NOT AUTHORIZED

本裁定僅適用於固定 SHA 8eb5bb5c499481c13d2d992c44b6451c14b9a010，不適用於後續 Commit。

重新申請 APPROVED 前，至少必須完成以下驗證：

移除 WAL 驗證對已存在 Registry 的舊根金鑰 fallback。

完整承諾 Registry HWM，並修正同版本合法演進規則。

封閉公開 Witness Getter 對內部可變物件的存取。

統一 WAL 復原與一般 Journal 的歷史金鑰授權語意。

於修復後的新 SHA 執行對應負向測試及獨立覆審。

本輪未修改、提交、合併或發布任何程式碼，也未在獨立本機環境重播完整 npm 測試套件。

不確定清單

未查證：上述對抗反例尚未在完整專案環境獨立動態重播。

預設前提：攻擊者可觸及公開 Adapter API；WAL 舊根金鑰案例假設攻擊者具備該歷史金鑰的有效簽署能力。

推測：歷史金鑰判斷不一致可能影響更多金鑰輪替後的崩潰復原情境，影響範圍尚未窮舉。

下一步： 先在 R17-B04 測試增加一個「Registry v2 的 keys 完全移除舊根金鑰」案例。它能直接檢查目前最明確、且足以阻擋合併的授權缺陷。
```
