# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 31

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `3e878ca146955ae7e9a47f090ca0816fb4ba8849`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED**

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 31 獨立安全審查
Default-Deny 審查中

本輪固定審查基準為 3e878ca146955ae7e9a47f090ca0816fb4ba8849，不以後續分支變更取代。

已直接向 GitHub 取得下列一手證據：

項目

	

查核結果




Repository

	

arcobaleno64/three-lens




Pull Request

	

PR #52




PR 狀態

	

OPEN，尚未合併




Target Branch

	

main




Head SHA

	

與指定 SHA 完全一致




GitHub Mergeable

	

true




Commit 訊息

	

fix(governance): resolve Round 30 blocker R30-B01 isolating delegated prefix entries from truncating root revocations

Mergeable: true 只代表 GitHub 判定可以進行合併，不代表密碼學安全性合格。R30-B01 必須經過獨立的控制流程及負向測試驗證，才能裁定 CLOSED。

1. R30-B01 修復查核

針對原始反例，修補方向成立：

L778–780：Genesis Root 的有效視窗設為 Infinity。

L825–851：歷史 ACTIVE 金鑰不再受先前 HWM=-1 直接截斷；RETIRED 金鑰則取前一個 Registry 的 HWM。

L680–717：委託金鑰簽署的合法前置紀錄可繼續驗證，後續 Root 撤銷會更新 journalRevokedKeyIds。

L888–900：當前 Registry 若由已撤銷金鑰授權，會在匯入其 keys[] 前拒絕。

tests/test-plugin-data-adapter.mjs:L6838–6914：Negative Test F 涵蓋 current 與 historical v3 兩種注入路徑。

R30-B01 原指定反例：原始碼修補證據成立，暫評 CLOSED（限定該反例）。 完整 Adapter 的獨立端對端重播尚未執行，因此不將它擴張為整體安全證明。

但繼續檢查發現另一個 Root 信任邊界問題。它不需要破壞 Ed25519，也不需要偽造既有 Root 私鑰。

2. Round 31 正式裁定：REJECTED
P1 · Blocking

拒絕合併 PR #52。 本輪新增 R31-B01：Root keyId 與公鑰 PEM 的綁定可被已授權的委託金鑰替換，進而使攻擊者以 Root 名義驗證 Journal 紀錄。

R31-B01：Root 身分替換與權威冒用

P1 · 新增阻擋項 · 原始碼確認，精簡模型重現

攻擊條件是攻擊者取得具備 Registry 更新權限的 ACTIVE 委託金鑰 K，而非 Root 私鑰。

關鍵程式碼證據：

L781–827：後續 Registry 主要驗證前一版本 ACTIVE 簽署者及授權簽章，未重新限制 Root PEM。

L829–854：trustedKeys.set(hk.keyId, hk.publicKeyPem) 可覆寫既有 Root keyId 對應的可信公鑰。

L1861–1876：完整 Journal 驗證使用該可信金鑰表中的 PEM 驗證簽章。

獨立 Node.js 精簡模型以真實 Ed25519 金鑰成功重現：替換前拒絕攻擊者簽章；替換後接受相同 rootId 名義的攻擊者簽章。

推翻條件： 固定 SHA 的完整 Adapter 能以明確的 Root 身分綁定檢查拒絕有效 K 簽署的惡意 v3，且拒絕發生在替換公鑰進入信任表之前。

R31-B02：Root 撤銷處理不一致

P2 · 次要發現

advanceJournalRevocations() 排除 Root 作為撤銷目標，但 getJournalRevokedKeyMap() 與完整 Journal 驗證仍可能將 Root 加入撤銷集合或截斷簽署視窗。appendRevocationEntry() 亦缺少對委託金鑰撤銷 Root 的一致限制。

這違反宣告的 Root 錨點免疫不變量，須統一寫入、預驗證和完整讀取三條路徑。

3. CI 與證據完整性

項目

	

本輪證據




Plugin Data tests

	

105/105 PASS，GitHub CI 日誌




render-sarif

	

121/121 PASS，GitHub CI 日誌




Release evidence

	

29 files verified




跨平臺 CI

	

Ubuntu、macOS、Windows 均成功




Adapter 雙路徑

	

Git blob SHA 與讀取內容一致




SHA-256 宣告值

	

Manifest 已核對，未在本地獨立重算




完整原始 Adapter 重播

	

未執行




獨立 Ed25519 精簡模型

	

重現成功

正式審查附件

Round 31 獨立安全審查報告

Markdown，含阻擋項、固定 SHA 行號證據、閉合條件及限制

R31-B01 Ed25519 對抗性重現程式

可執行 Node.js 精簡模型，非完整 Adapter 測試

不確定清單：完整 Adapter 未獨立重播；未窮舉 WAL、TOCTOU 與外部 Witness 的所有組合；8/8 Check Runs 未逐項獨立列舉，但已核對可取得的成功 CI 日誌。

下一步： 將 R31-B01 登記為 P1 · BLOCKING · OPEN，要求在所有 Registry 版本及信任表匯入位置固定 Root keyId、PEM 與 fingerprint，不得由委託金鑰替換；在獨立覆驗前，維持 PR #52 未合併狀態。

round-31-independent-security-review.md
文件
r31_root_keyid_substitution_repro.mjs
程式碼
```
