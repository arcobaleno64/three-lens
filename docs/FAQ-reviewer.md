## 常見問題（審核與資安視角）

> 適用版本：three-lens v1.11.0。本節內容以本儲存庫的程式碼、`SECURITY.md` 與測試證據為準，不構成任何平台或機構的認證。
> 對應的 JSON-LD 結構化資料：[`docs/faq.jsonld`](faq.jsonld)（兩者文字需同步維護）。

### Q1：three-lens 會把我的原始碼、金鑰或個資送到外部嗎？

three-lens 本身不含遙測或任何對外回傳程式碼；但弱點分析由 Antigravity CLI（`agy`）所設定的模型執行，送進模型的是**去敏後**的程式碼片段、檔名與提示上下文。送出前有兩道本機防護：

1. **去敏影子副本**：`prepare-review-context.mjs` 在 `scratch/context/` 建立副本，把 AWS 金鑰、GitHub Token、Bearer Token、私鑰、密碼、JWT 換成 `<SECRET:class=…:hash=…>` 並保留行號；還原對照表只存在記憶體，不寫入檔案、報告或 SARIF。
2. **PreInvocation 機密守門**：`hooks/pre-invocation-secret-guard.mjs` 在提示送往模型前掃描機密，偵測到即中止（fail-closed）。

限制：規則式偵測無法涵蓋所有非結構化個資；使用雲端模型時，資料保留依宿主與模型供應商條款而定。

### Q2：支援哪些 Antigravity CLI 與系統環境？這是 Google 官方外掛嗎？

不是。three-lens 是社群維護的 MIT 授權開源外掛，**與 Google LLC、Anthropic、OpenAI 均無隸屬、背書或贊助關係**。

| 項目 | 需求 |
| :--- | :--- |
| Antigravity CLI（`agy`） | `>= 1.2.0`（PreInvocation 中止 hook 與原生 ACP 傳輸建議 `>= 1.5.1`） |
| Node.js | `>= 20.0.0` |
| Git | `>= 2.30.0` |
| GitHub CLI（`gh`） | 選用，`>= 2.50.0`，僅發行來源驗證需要 |
| 作業系統 | Windows、Linux、macOS |

安裝後在外掛目錄執行 `npm run doctor` 可自動檢查環境；各平台的驗證等級見 [`docs/reproduction/platform-compatibility.md`](reproduction/platform-compatibility.md)。

### Q3：「零外部依賴」是真的零嗎？我要怎麼驗證？

指的是 **0 個 npm 套件**：`package.json` 沒有 `dependencies`、`devDependencies`、`peerDependencies`、`optionalDependencies`，核心只用 Node.js 內建模組（`fs`、`path`、`crypto`、`child_process`）。用途是縮小供應鏈攻擊面。

自行驗證：

1. `npm run check:release`：發行閘門會檢查四種依賴欄位皆為空。
2. `skills/3lens/tool-integrity-manifest.json`：關鍵腳本的 SHA-256 完整性清單。
3. `npm run test:provenance`：以 `gh` 驗證發行來源與 SLSA 認證。

「零 npm 依賴」不等於整體零依賴：執行仍需要 Node.js、`agy`、Git，以及 `agy` 所連接的模型。

### Q4：跟直接請一個 LLM 審查程式碼，差在哪裡？

單一 LLM 審查是「模型說有就有」；three-lens 把**判定權從模型手上拿走**：

1. **分階段管線**：目錄盤點 → 去敏上下文 → 威脅建模 → 弱點探索 → 三視角驗證 → 確定性終審。
2. **合取式三視角**：可達性（Reachability）、防禦控制（Defenses）、實際影響（Impact）三個驗證者各自獨立檢驗；任一視角提出**附行號證據**的反證，就不能被其他兩票推翻（不是 2 比 1 多數決）。
3. **確定性終審**：最終處置由 `finalize-scan.mjs` 這段 JavaScript 依 Default-Deny 規則計算，不由模型自行宣告。有效票少於 2 張自動轉 `DEFERRED`（人工複審）；覆蓋率為 `PARTIAL` 時不得宣告「無弱點」。

限制：三個視角預設使用同一個模型，代表三種分工而非三家供應商；公開的 20/20 基準量測的是終審決策邏輯，不是真實專案的弱點發現率。

### Q5：審查來路不明的儲存庫時，外掛會被提示詞注入劫持，或擅自改動、推送我的程式碼嗎？

設計上以四層縱深防禦降低這類風險：

| 層 | 機制 | 作用 |
| :--- | :--- | :--- |
| 1 | `agy --sandbox` | OS 層隔離，阻斷目標程式碼執行任意指令與對外連線 |
| 2 | `recommended-security-audit-permissions.json` | 依角色限縮工具；探索與驗證角色唯讀，拒絕 `git push`、網路外聯、寫入 `.git/*` 與 `.github/*` |
| 3 | `hooks/shadow-context-guard.mjs` | PreToolUse 攔截讀檔，導向去敏副本並阻擋符號連結逃逸（CWE-59） |
| 4 | `path-containment.mjs` | 以檔案描述子原子讀取，防止 TOCTOU 與相似前綴目錄欺騙 |

另外，Git 操作一律經 `safe-git.mjs` 執行，停用目標儲存庫的 hooks、`core.fsmonitor`、外部 diff 與 textconv。修補只會在 `scratch/patches/` 產生候選 patch，不會自動提交、推送或部署。

限制：用 XML 分隔符包住待審程式碼只是政策層防護，不是密碼學保證；第 2 層的效果取決於 `agy` 是否實際載入該權限設定。審查不受信任的儲存庫時，請務必搭配 `agy --sandbox`。
