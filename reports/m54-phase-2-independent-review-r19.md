# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 19

**Review Date**: 2026-11-08  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: rcobaleno64/three-lens  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (eat/m54-phase-2-governance)  
**Evaluated Commit SHA**: 57887c1a6e80268f75c06415b18bad42d3b9c497  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

`markdown
Three-Lens PR #52｜Round 19 獨立安全審查報告
REJECTED · 不核准合併

正式裁定：REJECTED。R18-B01～R18-B04 尚未全部完成安全閉環，禁止依本輪審查結果核准合併。

本輪直接讀取指定 Commit 的實際程式碼、單元測試及 GitHub Actions 紀錄，另獨立計算關鍵 TCB 檔案的 SHA-256，而非僅採信修復說明。

審查發現，Registry 同版本更新仍存在身分承諾與驗證條件不一致的問題，WAL 復原也有可能留下 Registry 與 history 不同步的狀態。歷史金鑰生命週期的驗證及其負向測試同樣未完成充分證明。

一、審查基準與已確認證據

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




審查分支

	

feat/m54-phase-2-governance




審查目標

	

main




固定 Commit

	

57887c1a6e80268f75c06415b18bad42d3b9c497




PR 狀態

	

OPEN、Mergeable: TRUE




GitHub Actions

	

8/8 SUCCESS，已查證




TCB 雙路徑一致性

	

PASS，已逐位元組比較




Layer 1 / Layer 2 雜湊參照

	

PASS，已獨立計算與比對




本輪安全裁定

	

REJECTED

查核日期：2026-11-08（臺灣時間）。本輪為指定 SHA 的唯讀靜態與證據審查；不將程式碼檢視等同於完整動態攻擊重播。

CI 與完整性驗證

GitHub API 回傳的八項 Check Runs 全部為 completed / success，包括 CodeQL、Semgrep OSS、semgrep、三個作業系統的 CI，以及兩項 Analyze 工作。

此外，已獨立計算下列雜湊值：

對象

	

SHA-256 檢查




scripts/adapters/plugin-data-adapter.mjs

	

PASS




skills/3lens/scripts/adapters/plugin-data-adapter.mjs

	

PASS




skills/3lens/tool-integrity-manifest.json

	

PASS




evals/evidence-matrix.json 中的相關雜湊參照

	

PASS

兩份 Adapter 的實際 SHA-256 均為：

192102ee99c7a047dbf7eda1b4a3d561ca1dbe76756a568c8eeb68e29a07cd81

Layer 1 Manifest 的實際 SHA-256 為：

8d157688173001919efbaa3226c54464fc7cf4cb939f50e9994c1c88837cdd50

這部分可以確認一致，但完整性一致不代表安全授權邏輯正確。

二、Round 18 阻擋項覆審結果

原阻擋項

	

Round 19 狀態

	

判定




R18-B01：移除 Genesis Root 後仍可 fallback

	

修補有效（限已驗證路徑）

	

通過




R18-B02：Registry Digest 與 HWM 單調演化

	

存在新反例

	

未通過




R18-B03：Witness 共享記憶體污染

	

核心修補有效

	

通過




R18-B04：歷史金鑰生命週期與視窗

	

撤銷語義缺口、測試不充分

	

未通過




SECURITY.md §2.9

	

措辭已精確修正

	

通過

以下列出本輪阻擋發現。嚴重程度依安全影響與必要攻擊前提評估，並區分直接程式碼證據與尚未動態重播的攻擊情境。

三、Round 19 阻擋發現
R19-B01 · High：revokedKeyIds 與 keys[].status 存在授權語義不一致
OPEN · High

結論：當某金鑰已列入 revokedKeyIds，但在 keys[] 中仍保留 ACTIVE 狀態，部分讀取及驗證流程仍可能接受它的簽章。

直接程式碼證據：

plugin-data-adapter.mjs L649–659：resolveJournalTrustedKeyWindows() 僅檢查 status，對 ACTIVE 金鑰直接設定 Infinity，沒有檢查 currentRegistry.revokedKeyIds。

L1646–1661：validateTrustRegistry() 的 HWM 簽署者撤銷檢查只參考 priorReg.revokedKeyIds，未排除當前版本剛被撤銷、但仍標為 ACTIVE 的金鑰。

L3794–3805：正常寫入 API 反而同時檢查 revokedKeyIds 及 status，顯示寫入與驗證的授權規則並不一致。

攻擊情境：

一把合法授權的金鑰 A，在新版 Registry 的 revokedKeyIds 中被撤銷，但 keys[] 仍將它標記為 ACTIVE。

攻擊者持有已撤銷的 A 私鑰，且具有修改本機治理檔案的能力。

攻擊者以 A 簽署新增的 Journal Entry 與 HWM，並同步修改 Registry、history 及 checkpoint。

Journal 驗證器將 A 視為有效視窗 Infinity；HWM 驗證器亦可能接受其簽章。

若 HWM 索引高於既有 witness，Registry Digest 演化規則可能允許新的狀態承諾。

這不是宣稱單憑撤銷私鑰就能遠端突破系統。攻擊另需本機治理檔案寫入能力，以及可通過原有 Registry 授權證明的狀態。

但這個組合正是本 PR 宣稱需要防禦的金鑰生命週期混淆與多檔案狀態操弄。

必要修正： 撤銷狀態必須形成單一、不可矛盾的有效權限判斷。對新增的 Journal Entry 及 HWM，revokedKeyIds 與 keys[].status 任一表示已撤銷，都不得授權新簽章；歷史簽章則必須依明確且經驗證的時間／索引視窗處理。

推翻本發現的條件：使用完整、合法授權的 Registry 建立上述矛盾狀態後，證明 validateTrustRegistry() 必定在進入相關 Journal／HWM 驗證之前拒絕，且提供擊中該條件的負向測試。目前未見此保證。

R19-B02 · High：同版本 HWM 推進可掩護非 HWM 權威欄位變更
OPEN · High

R18-B02 確實讓 computeRegistryDigest() 納入更多欄位，但將欄位納入 Digest，不等於所有欄位的變更都經過授權。

直接程式碼證據：

L1420–1460：Identity Payload 納入 signerKeyId、signedAt、algorithm、priorRegistryVersion 等。

L1381–1408：Registry 授權簽章的 Payload 不包含這些 Proof 中繼資料。

L1974–1985：實際密碼學驗證的是 computeRegistryAuthorizationPayload()。

L3094–3116：只要 HWM 索引嚴格增加，便放寬同版本 Registry Digest 不一致的檢查，沒有進一步確認變更僅限 HWM。

因此可能出現下列狀況：

原本 Registry v2 的 Proof 是根金鑰授權產生的，HWM 索引為 4。當合法的 HWM 簽署者將索引推進至 5 時，能修改本機 Registry 與 history 的攻擊者，同時改動 authorizationProof.signedAt、signerKeyId 或 priorRegistryVersion。

原本的 Registry 授權簽章未必因此失效，因為相關欄位不在其簽署 Payload 中；而 witness 只觀察到 HWM 增加，便可能接受新的 Registry Digest。

此情境能破壞授權來源中繼資料的完整性。尚未證實這些欄位會被下游用來直接授予新的操作權限，因此不將它誇大為已完成特權提升，但它足以推翻「完整身份承諾受到嚴格保護」的宣稱。

必要修正是將同版本 Registry 更新明確拆分為兩個判斷：

非 HWM 身分載荷必須與既有版本完全一致，除非另有經過驗證的 Registry 更新授權。

HWM 的索引、Digest 與簽章必須另行驗證其授權及單調性。

推翻本發現的條件：在有效 HWM 推進期間，嘗試單獨篡改上述 Proof 中繼資料，系統必須確定性拒絕，而不只是計算出不同的 Digest。

R19-B03 · High：WAL 復原與歷史 Registry 同步規則存在衝突
OPEN · High（可用性／復原正確性）

這項缺陷最直接影響交易中斷後的可靠復原，而不是直接造成權限提升。

R18-B02 修復說明宣稱，當同版本的 on-disk Registry HWM 高於 history，且其他身分載荷一致時，系統允許合法的 HWM 推進。

但指定 Commit 的程式碼仍包含以下判斷：

plugin-data-adapter.mjs L2237–2257

JavaScript
if (sameVersionHistRegistry) {
  const histContent = fs.readFileSync(
    path.join(histDir, `trust-registry.v${parsed.registryVersion}.json`),
    'utf8'
  );
  const diskHash = sha256Digest(raw);
  const histHash = sha256Digest(histContent);
  if (diskHash !== histHash) {
    // Reject
  }
}

這裡沒有宣稱的「僅 HWM 合法推進例外」。即使 on-disk Registry 的 HWM 索引較新，只要 history 尚未同步，仍會被拒絕。

更重要的是，寫入程序明確存在兩次獨立的檔案更新：

L3963–3966：先寫入 Registry，再寫入 history。

L1135–1184：PREPARED WAL 復原若判定目標 Registry、checkpoint、Journal 已完成，可更新 witness 並移除 WAL 標記。

因此存在具體的交易中斷時序：

中斷時序與後續失敗點

Journal、checkpoint 與當前 Registry 已寫入 HWM = N。
在 history 尚保留 HWM = N−1 時發生程序中斷。
重新啟動後，PREPARED WAL 將已完成的三個檔案判定為目標狀態。
復原流程可能更新 witness 並移除 WAL，但未補齊 history。

後續 doLoadTrustRegistry() 因同版本 Registry／history SHA-256 不一致而拒絕載入。

這是一條由指定程式碼推導的可達路徑，尚未在本輪以實際程序中斷重播確認。

它指出 WAL 的「已復原」認定範圍，可能小於後續讀取流程要求的一致性範圍。

必要修正： 統一 WAL 完成條件與 Registry／history 同步條件。若允許從中斷點復原，必須在移除 WAL 前完成 history 重建與驗證；不能僅放寬 SHA-256 比對而犧牲歷史一致性。

推翻本發現的條件：在 Registry 寫入成功、history 寫入前強制中斷，重新啟動後證明 WAL 能完整復原，且 loadTrustRegistry()、loadRevocationJournal() 與雙 witness 全部一致。

R19-B04 · Medium：R18-B04 負向測試未確實命中退休金鑰視窗
OPEN · Medium

這是測試保證力問題，不代表本身已構成額外的可利用漏洞。

新增測試位於：

tests/test-plugin-data-adapter.mjs L4764–4923

其中 L4884–4888 嘗試將 Journal Entry 改由退休金鑰簽署，但修改的是：

JavaScript
forgedEntry1.signerKeyId = authA.keyId;

驗證器實際使用的是：

JavaScript
trustedKeys.get(entry.signedBy)

而且測試產生的替代簽章並非針對實際的 computeRevocationEntrySignPayload()。

因此測試可能因為一般簽章錯誤、Journal 損毀或 HWM 不一致而失敗，而不是因為真正觸發退休金鑰視窗限制。

L4917–4919 又允許一般性的 TRANSACTION_WAL_CORRUPTION_DETECTED 作為成功條件，使這個問題更難被測試發現。

必要修正：使用正確的 signedBy、正確的 Ed25519 簽署 Payload，以及一致的 Journal／HWM／checkpoint，排除其他錯誤後，僅針對超出金鑰有效視窗的條件驗證拒絕結果。

此外，L655–695 對當前標為 REVOKED 的金鑰，仍可能從歷史 ACTIVE 記錄恢復非負的有效索引視窗。這與修復說明的「已 REVOKED 者無條件拒絕」不一致。若設計本意是保留撤銷前簽章的歷史有效性，必須重新明定撤銷生效界線，而非用含糊的狀態描述代替。

四、已通過項目

R18-B01 的核心修補，在本輪可確認的範圍內成立。當磁碟上已有 Registry 時，程式碼要求 WAL 簽署者存在於通過驗證的當前 keys[]，且狀態必須有效。被完全移除的 Genesis Root 不會再落入預設根金鑰 fallback。對應負向測試亦已於 CI 通過。

R18-B03 的核心隔離修補也成立。getMonotonicWitness() 回傳凍結複本，外部 witness 參數只影響當次計算，不直接污染共享記憶體。需另註明：updateMonotonicWitness() 實作並未如修復說明所述回傳凍結複本，但此差異本身尚未形成原 B03 的安全繞過。

SECURITY.md §2.9 已改用 separate local storage locations，且明確揭露全部本機信任錨點遭同步控制時，無法單靠本機儲存保證外部時間新鮮度。該措辭修正可以接受。

五、最終裁定與解除阻擋條件

發現

	

嚴重度

	

解除阻擋所需證據




R19-B01

	

High

	

撤銷狀態矛盾時，Journal／HWM 新簽章確定遭拒




R19-B02

	

High

	

HWM 推進時，未經授權的非 HWM 身分欄位變更遭拒




R19-B03

	

High

	

Registry／history 寫入中斷後可完整復原且一致




R19-B04

	

Medium

	

具備密碼學上有效、精確命中退休視窗的負向測試

最終決定：REJECTED。

本裁定不是因為 CI 失敗，也不是因為未找到足夠多的測試，而是指定 Commit 的授權判斷、同版本演化與復原不變量仍有可核對的邏輯缺口。

Round 19 未向 GitHub 提交任何 Review、Comment、Commit，也未修改儲存庫。

不確定清單

未查證：本輪未在獨立沙盒重新執行完整原始碼測試，動態執行證據取自指定 SHA 的 GitHub Actions 紀錄。

預設條件：R19-B01、B02 的攻擊情境假設攻擊者具有相應本機檔案寫入能力；R19-B01 另需持有已撤銷私鑰。

推測：R19-B03 的完整中斷後果已由控制流程支持，但仍需實際故障注入確認所有狀態轉移及錯誤碼。

下一步： 將 R19-B01～R19-B03 登記為合併前必須解除的 High 阻擋項，維持 PR #52 不合併。
`
