# Milestone 5.4 Phase 2: Independent Third-Party AppSec & Cryptographic Systems Review — Round 23

**Review Date**: 2026-11-09  
**Auditor**: Independent Third-Party Principal AppSec / Cryptographic Systems Auditor (ChatGPT Pro, High/Deep Reasoning Effort)  
**Target Repository**: `arcobaleno64/three-lens`  
**Target Pull Request**: [#52](https://github.com/arcobaleno64/three-lens/pull/52) (`feat/m54-phase-2-governance`)  
**Evaluated Commit SHA**: `665dc87f9f9ead78446a6c7bb9de6f413e614f98`  
**Audit Principle**: Presumption of Non-Pass (Default-Deny on Authority Claims)  
**Final Verdict**: **REJECTED** · 禁止合併

---

## 1. Full Independent Review Transcript

```markdown
Three-Lens PR #52：Round 23 獨立安全審查
REJECTED · 禁止合併

正式裁定：R22-B01 尚未完全收斂，PR #52 不符合 Default-Deny 安全驗收條件。

本輪直接取得指定 Commit 的 GitHub 原始碼、測試與 CI 紀錄，確認修補確實存在，但發現新的 P1 阻擋缺陷：Journal 檔案存在但遭截斷或內容遭竄改時，撤銷查詢仍可能回傳錯誤的空集合，讓已撤銷金鑰重新參與 Registry 授權。

審查基準如下：

| 項目 | 獨立核對結果 |
| :--- | :--- |
| Repository | arcobaleno64/three-lens |
| PR | #52 |
| Target | main |
| Head SHA | 665dc87f9f9ead78446a6c7bb9de6f413e614f98 |
| PR 狀態 | OPEN、Mergeable |
| Workflow Runs | 2/2 Success |
| 審查模式 | Cold-Start、Adversarial、Read-Only |
| 安全裁定 | REJECTED |

---

### 一、R23-B01：P1 · 撤銷日誌截斷／竄改造成授權狀態誤判

狀態：OPEN，阻擋合併。

直接證據位於：
`plugin-data-adapter.mjs` L1441–1537

關鍵程式碼：
```javascript
const lines = content.split(/\r?\n/)
  .filter(l => l.trim().length > 0);

for (let i = 0; i < lines.length; i++) {
  // JSON parsing and targetId validation
}

return revokedMap;
```

當 `.irv-revocation-journal.jsonl` 存在，但內容為空字串時：
1. `fs.existsSync(journalPath)` 為 true，因此繞過檔案缺失的 HWM 檢查。
2. `readFileSync()` 正常完成，不產生 I/O 例外。
3. `lines.length` 為 0，不執行任何條目驗證。
4. 函式回傳空的 Map，將「撤銷紀錄遭截斷」誤判為「不存在撤銷紀錄」。

即使 Checkpoint、Trust Registry 與 Witness 仍記錄已建立的撤銷 HWM，此函式也不會在 Journal 存在的分支比對這些持久化錨點。

這是由實際程式碼直接確立的 Fail-Open 邏輯缺陷，不只是測試覆蓋率不足。完整跨入口利用仍須與其他防線分開評估，不能因為輔助函式失效就直接宣稱所有特權提升都已動態重現。

#### 攻擊鏈：已撤銷金鑰 A 重新授權 Rogue Key B
程式碼路徑推導，尚非獨立端對端動態重播

- **S0：合法撤銷狀態**  
  Registry v2 中 A 仍為 ACTIVE；Root 已透過 Journal 撤銷 A，並將 HWM 寫入 Registry、Checkpoint 與 Witness。
- **S1：攻擊者截斷 Journal**  
  攻擊者持有 A 的舊私鑰，且具備修改 Journal 檔案內容的能力。將 Journal 清為零位元組，保留其他信任錨點。
- **S2：撤銷查詢失去證據**  
  `getJournalRevokedKeyMap()` 回傳空 Map。`createAuthorizedRegistryUpdate()` 因而不會從 Journal 得知 A 已撤銷。
- **S3：A 嘗試簽署 v3**  
  A 使用原私鑰產生授權更新，將 B 加入 ACTIVE 金鑰集合。候選 Registry 保留原有、有效簽署的 HWM。
- **S4：Registry 儲存與驗證風險**  
  `saveTrustRegistry()` 和 `validateTrustRegistry()` 使用同一個不完整的 Journal 撤銷查詢。既有 Witness 比對候選 HWM，不等於驗證實際 Journal 內容。

關鍵交叉證據：
- 授權更新 L2313–2354
- Registry 簽署者驗證 L2147–2292
- Witness Journal Prefix 驗證條件 L3661–3699
- Registry 儲存與撤銷檢查 L3730–3766

更重要的是，攻擊者甚至不必清空 Journal。只要將 KEY_REVOCATION 改為其他可解析的字串，保留原本無效的簽章，輔助函式仍不會進行完整 Ed25519、hash chain 或 headDigest 驗證。

專門的 `loadRevocationJournal()` 確實具有這些驗證，但授權更新、Registry 驗證及儲存的上述路徑沒有以它的完整驗證結果建立共同的撤銷狀態依據。

影響判斷：已確立撤銷狀態可被錯誤判為空集合，且存在穿越 Registry 授權路徑的合理攻擊鏈。B 取得 Registry 授權的完整利用效果仍待隔離測試。`appendRevocationEntry()` 另外呼叫完整 Journal 驗證，因此不能宣稱 B 已可成功追加撤銷紀錄。

能推翻完整利用鏈的觀察，是在相同有效金鑰、HWM、Witness 與 Registry 前提下，找到另一道實際執行且能拒絕零位元組 Journal 的必要門禁，並用可重現測試證明。這不會推翻目前輔助函式本身的 Fail-Open 缺陷。

---

### 二、R23-B02：P2 · Journal 缺失偵測仍有結構性漏洞

OPEN · 直接程式碼證據

原始碼 L1462–1505

原始碼實際使用的 Registry 路徑是：
`supervisor-trust-registry.json`

但缺失 Journal 偵測卻讀取：
`trust-registry.json`

因此，這項實體產物檢查沒有查到正式的 Registry。

此外，`history/` 驗證的 catch 僅重新拋出包含 `JOURNAL_ROLLBACK_DETECTED` 的錯誤。目錄讀取失敗、歷史 Registry 解析失敗等其他例外會被忽略。

這使「任何無法確認撤銷狀態皆 Fail-Closed」的宣告不成立。

須保留一項限制：其他 Checkpoint 與 Witness 防線可能攔截部分組合攻擊，因此本項尚未獨立證明完整授權復活，不能直接與 R23-B01 的利用效果合併計算。

---

### 三、R23-B03：P2 · R22 負向測試存在錯誤驗證目標

OPEN · 測試有效性缺陷

`tests/test-plugin-data-adapter.mjs` L6287–6359

測試有三個問題：
1. **第一，偽造 Registry 寫入錯誤路徑**。  
   L6335 將偽造 v3 寫入 `trust-registry.json`，但正式載入器讀取 `supervisor-trust-registry.json`。隨後的拒絕結果無法證明正式 Registry 路徑已抵抗偽造 v3。
2. **第二，偽造 Registry 本身的密碼學證據不完整**。  
   測試使用 `computeRegistryNonHwmDigest(updatePayload)` 作為授權簽章訊息，但正式驗證端使用 `computeRegistryAuthorizationPayload(registry)`。測試建立的 HWM 也缺少必需的 signature。因此，即使撤銷檢查失效，這個偽造候選仍可能因其他密碼學驗證失敗而被拒絕，不能作為撤銷防護的獨立有效性證明。
3. **第三，缺少本輪真正重要的負向案例**。  
   R22 測試覆蓋 malformed JSON、缺少 targetId、Journal 被刪除，以及格式破壞，但沒有直接證明「Journal 存在但為空」或「JSON 合法但簽章無效」時會拒絕既有有效金鑰發起的 Registry 授權。

這不是增加測試數量就能解決的問題，而是測試必須具備能識別失效防線的正確 oracle。

---

### 四、已獨立確認的修復與驗證證據

| 驗證項目 | Round 23 判定 |
| :--- | :--- |
| Journal `readFileSync()` 直接失敗時拋出例外 | SUPPORTED |
| Malformed JSON 與缺少 targetId 時拒絕 | SUPPORTED |
| Journal 缺失且 Checkpoint 已記錄 HWM 時拒絕 | SUPPORTED |
| Journal 存在但為空時拒絕 | CONTRADICTED |
| Journal 每筆紀錄均完成密碼學驗證 | CONTRADICTED，限本輔助函式 |
| 所有歷史讀取失敗均 Fail-Closed | CONTRADICTED |
| WAL 恢復的完整攻擊邊界已驗證 | INSUFFICIENT_EVIDENCE |
| TCB 雙路徑與雜湊一致 | SUPPORTED |

兩份 Adapter 已獨立重新計算 SHA-256，皆為：
`5996d13263f64f10f998a8f9fd3bd0073e77d932d3dd021f992b439c99f32f06`

Manifest 的 SHA-256 亦符合：
`5291f7cd7feb35aa1e583b60e715628ef33c2550a811c91b8625a1f160b06c4b`

`evals/evidence-matrix.json` 包含這兩項預期雜湊。

GitHub CI 直接核對結果：
- 8/8 Checks Success
- 102/102 Adapter Tests
- 29/29 Evidence Files
- GitHub Actions Run #42552182229

CI 的成功是真實證據，但它只能證明目前已執行的測試通過，不能證明缺少的對抗條件也受到保護。

---

### 五、正式結案裁示

| Finding | 嚴重度 | 狀態 | 合併門禁 |
| :--- | :--- | :--- | :--- |
| R22-B01 | P1 | FIXED_PENDING_VERIFY | 未關閉 |
| R23-B01 | P1 | OPEN | BLOCKING |
| R23-B02 | P2 | OPEN | 待修正及重驗 |
| R23-B03 | P2 | OPEN | 待修正及重驗 |

R22-B01 的 I/O 與格式錯誤修補成立，但「完整收斂」主張已被新的輸入類型反例推翻。因此不得標記 CLOSED。

建議下一輪修補以同一份經完整驗證的 Journal 撤銷狀態作為授權依據，並在儲存門禁中核對實際 Journal、Checkpoint、Registry HWM 與 Witness，而非僅使用個別解析結果。WAL 恢復所需的 skipJournalRevocationCheck 應限縮為受控的復原專用路徑，不可讓一般授權入口任意沿用。

本輪不執行：GitHub 修改、PR Review 發佈、合併，以及對正式儲存狀態的破壞性故障注入。

不確定清單：
- 已查證：指定 Commit、主要程式碼路徑、測試原始碼、CI 日誌、雙層雜湊。
- 未執行：在獨立 Node.js 工作目錄重新執行完整端對端 A → v3 → B 動態重播。
- 推測：具備 Journal 修改能力且持有已撤銷 A 私鑰的攻擊者，可進一步使 B 取得持久化 Registry 授權；需實際重播確認全部門禁結果。

下一步（兩分鐘內）：在 tests/test-plugin-data-adapter.mjs 的 R22-B01 測試中，新增「有效撤銷 Journal 被截斷為空字串後，createAuthorizedRegistryUpdate() 必須拒絕 A」的負向斷言。先讓該測試確定失敗，再修補授權驗證邏輯。

Round 23 最終裁定：REJECTED。不得合併。
```
