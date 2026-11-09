# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 33

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `ac1a9adde4b115fc266a95baed5e5a7a97174193`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 33 獨立安全審查
REJECTED · 不得合併

正式裁定：REJECTED。 固定審查 Commit ac1a9adde4b115fc266a95baed5e5a7a97174193 已實作 R32-B01 與 R32-B02 的主要修補，但本輪發現新的 P1 主權 Root 退休授權缺口（R33-B01）。

持有合法 ACTIVE 委託金鑰的行為者，可能透過簽署新的 Registry 版本，將不可撤銷的 Root 金鑰標記為 RETIRED，進而阻止 Root 使用正常介面執行撤銷及復原授權操作。

這是根據固定 Commit 的實際控制流程與既有測試建立的程式碼級反例。尚未在完整獨立執行環境重現該攻擊，因此不宣稱已完成端到端利用驗證。

一、審查基準與結果

項目

	

審查結果




Repository

	

arcobaleno64/three-lens




PR

	

#52




固定 Commit

	

ac1a9adde4b115fc266a95baed5e5a7a97174193




審查模式

	

Cold-Start／Adversarial／Read-Only




R32-B01

	

CLOSED，限定已驗證的 Registry 驗證路徑




R32-B02

	

CLOSED，限定已驗證的公開 Journal 路徑




R33-B01

	

P1 · OPEN · Merge Blocking




GitHub Actions 8/8

	

使用者宣稱；本輪未能獨立確認全部 Check Runs




獨立測試執行

	

未執行完整測試套件




最終裁定

	

REJECTED

已透過 GitHub 連線直接取得指定 Commit 的 Adapter、測試檔、TCB Manifest 與 Evidence Matrix。

二、Round 32 阻擋項覆審
R32-B01：頂層 Root 身分綁定

裁定：CLOSED（限定 validateTrustRegistry() 及其正常儲存驗證路徑）。

已確認下列防護存在：

activeKeyId === rootId 時，頂層公鑰與 Fingerprint 均須符合固定 Root。

非 Root 的 active key 不得使用 Root PEM。

activeKeyId 必須在 keys[] 中恰有一筆對應紀錄。

對應紀錄的 PEM、Fingerprint（存在時）與狀態須符合頂層內容。

證據：plugin-data-adapter.mjs L2286–2364

原先透過頂層 Root PEM 替換的反例，會在簽章授權檢查前遭拒絕。

R32-B02：Journal Root 撤銷免疫

裁定：CLOSED（主要公開讀取、驗證與寫入路徑）。

實際確認：

路徑

	

Root KEY_REVOCATION 行為




getJournalRevokedKeyMap()

	

拋出 ROOT_REVOCATION_REJECTED




doLoadRevocationJournal()

	

拋出錯誤或回傳 valid: false




verifyFullJournalChain()

	

拋出交易損毀錯誤




appendRevocationEntry()

	

禁止撤銷 Root，並排除 Root 遭既有撤銷紀錄阻擋的情形

證據：Journal 撤銷地圖 L1978–1989、Journal 讀取 L4823–4835。

保留事項：advanceJournalRevocations() 遇 Root 撤銷時使用 break，並非直接拋錯。已檢查的後續公開驗證路徑仍會拒絕該非法條目，因此目前不將此差異單獨判為可利用漏洞。

三、新增阻擋項 R33-B01
P1 · OPEN

名稱：Delegated-Key Sovereign Root Retirement Bypass

攻擊前提：攻擊者控制一把 Registry 前版本中合法 ACTIVE 的委託金鑰 K，具有該金鑰的簽署能力，並可透過合法更新流程提交新版本。

建立合法 v2 Registry，Root 狀態為 ACTIVE_PINNED_ROOT，K 狀態為 ACTIVE。

使用 K 簽署 v3 Registry，保持 Root 的 keyId 和 PEM 不變，但將 Root 狀態改成 RETIRED，頂層 active key 指向 K。

validateTrustRegistry() 的 Root 防護僅拒絕 REVOKED，並未禁止此種由委託金鑰授權的 RETIRED 狀態轉換。

如果 v3 通過其他狀態與持久化檢查，Root 後續呼叫 appendRevocationEntry() 時，將因自身狀態為 RETIRED 而遭拒絕。

關鍵證據：

Root 狀態驗證 L2377–2386 只拒絕 Root REVOKED，沒有要求非 active 的 Root 必須維持 ACTIVE_PINNED_ROOT。

Registry 授權建立 L2941–3035 允許合法 ACTIVE 金鑰簽署新版本，未看到對 Root 退休轉換另設 Root 本人授權。

Journal 寫入 L5010–5033 明確要求簽署金鑰狀態為 ACTIVE 或 ACTIVE_PINNED_ROOT。

此外，既有測試確實存在 Root 轉為 RETIRED、再由委託金鑰簽署後續 Registry 版本的合法輪替案例，證明 Root 退休並非完全被程式設計排除。

證據：test-plugin-data-adapter.mjs L644–685。

安全判斷： 若 Root 的主權包含最終撤銷與復原權限，委託金鑰不應能單方面終止該權限。即使系統允許 Root 合法退休，也必須區分「Root 本人授權退休」與「受委託者使 Root 退休」。

推翻本阻擋項的必要證據：在固定版本建立 K 簽署的完整 v3 測試，證明此轉換必然被拒絕；或提供已驗證、由 Root 簽署且明確允許 K 單方面退休 Root 的不可變授權政策。

四、負向測試與完整性驗證

已獨立重算：

驗證對象

	

結果




兩份 Adapter SHA-256

	

530959d9…5e31b1c，一致




兩份 Adapter 內容

	

完全相同




TCB Manifest SHA-256

	

d7589d03…1107254d，一致




Evidence Matrix 中的 Adapter／Manifest 雜湊

	

與實際重算值一致

另外，Negative Test H 實際可辨識三個情境，而非宣稱的四個完整情境。測試包含 validateTrustRegistry() 與 getJournalRevokedKeyMap() 的斷言，但未見相應的 loadRevocationJournal() 端到端第四情境。因此，測試覆蓋完整性尚不能視為已證明。

本輪 GitHub 連線未取得可確認 8/8 的 Workflow Run 清單，不能將空結果解讀為 CI 失敗，也不能冒稱已獨立驗證 CI 全綠。

五、正式裁示

Final Verdict: REJECTED

R32-B01 與 R32-B02 的指定修補具有直接程式碼證據，足以支持其主要路徑的局部閉合。

但 R33-B01 揭露新的主權狀態轉換缺口：Root 的公鑰雖不可替換，Root 的操作權限仍可能被合法委託金鑰透過 RETIRED 狀態間接剝奪。

在此風險未經獨立負向測試排除，或未提出可信任的 Root 授權政策證明之前，依 Default-Deny 原則，不得核准合併。

不確定清單

未查證：完整 8/8 CI Check Runs 與 PR 當下 Mergeable 狀態。

預設：主權 Root 應保有最終撤銷權，除非有明確的 Root 授權退休政策。

推測：完整多檔案持久化攻擊可達性尚未執行獨立端到端測試，但關鍵狀態轉換與拒絕條件均有直接程式碼證據。

下一步（兩分鐘內）： 將 R33-B01 登錄為 P1 Merge Blocking Finding，暫停 PR #52 合併，並要求新增「委託金鑰不得單方面退休 Root」的負向測試。
```
