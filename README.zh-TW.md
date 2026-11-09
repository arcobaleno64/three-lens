# Three-Lens (3lens) v1.12.0

three-lens 是以證據為本、多階段的安全保證與弱點驗證外掛，專為 Antigravity CLI（`agy`）打造。

其防禦性架構對齊 **NIST SSDF (SP 800-218)**、**OWASP ASVS 5.0.0**、**OWASP SAMM**、**CWE 分類法**、**CVSS v4.0** 與 **SARIF 2.1.0**，並融入 Anthropic Claude Security 與 OpenAI Codex Security 研究中的防禦性概念。

[English →](README.md)

## 相關專案

[`agy-plugin-cc`](https://github.com/arcobaleno64/agy-plugin-cc) 是獨立的 Claude Code 協作外掛，可透過 Gemini CLI 或 Antigravity CLI（`agy`）進行跨模型任務委派與程式碼審查。它從 Claude Code 委派工作；`three-lens` 則原生執行於 Antigravity CLI 內。兩個專案都不會隨另一個一併提供，也不是使用另一個的必要條件。

> **獨立專案。** `three-lens` 由社群維護，**與 Google LLC、Anthropic 及 OpenAI 均無隸屬、背書或贊助關係**。第三方名稱僅用於指稱本專案互通或討論的工具、標準或研究；使用相關系統時，適用其各自條款。

## 快速上手 (Getting Started)

### 先決條件與支援矩陣 (Prerequisites & Support Matrix)
- **Node.js**: `>= 20.0.0`（純 Node.js 內建模組；0 外部 npm 依賴）。
- **Antigravity CLI (`agy`)**: `>= 1.2.0`。
- **作業系統**: Windows (PowerShell)、Linux (Bash)、macOS (Zsh/Bash)。
- **Git**: `>= 2.30.0`（用於差異審查與安全儲存庫隔離）。
- **GitHub CLI (`gh`)**: `>= 2.50.0`（選用；僅嚴格 SLSA 來源認證與發行證明核驗所需）。

### 安裝方式 (Installation)
將外掛複製或安裝至 Antigravity 外掛目錄：
```bash
git clone https://github.com/arcobaleno64/three-lens.git ~/.gemini/config/plugins/three-lens
```

### 執行第一次安全審查 (Running Your First Security Audit)
切換至任何您擁有權限進行審查的目標儲存庫：
```bash
cd /path/to/target-repo
agy
```
在 Antigravity 對話提示中，調用此技能：
```text
/three-lens:3lens
```
或直接使用簡潔指令：
```text
/3lens
```
或使用非互動式範圍旗標執行：
- **全代碼庫掃描**：`/three-lens:3lens --scope codebase`（或 `/3lens --scope codebase`）
- **指定路徑審查**：`/three-lens:3lens --scope path --path src/`（或 `/3lens --scope path --path src/`）
- **Git 變更審查**：`/three-lens:3lens --scope changes`（或 `/3lens --scope changes`）

### 預期產出 (Expected Outputs)
4 階段管線執行完成後，發現與證據會生成於：
- `reports/scan.md`（或 `reports/review.md`）：結構化、綁定客觀證據之決策 Markdown 報告。
- `reports/scan.sarif`：OASIS SARIF 2.1.0 標準日誌，供 IDE、GitHub Advanced Security 或 CI 系統讀取。
- `scratch/context/`：去敏、已遮蔽機密之陰影檢查工件。

---

## 核心公理：權威聲明以不通過為前提 (Default-Deny on Authority Claims)

所有權威聲明（弱點候選項目、補丁修復與覆蓋率完整性）預設為 **`UNVERIFIED`**。受審代碼本身不預設存在漏洞，審查合理產生 0 候選項（Zero Findings，無配額壓力）；候選項目無法自行宣告 `CONFIRMED` 或 `REPORTABLE`；在無驗證者共識、法定人數不足（< 2 票）或 0 票狀態下一律強制歸類為 `DEFERRED` (`NEEDS_MANUAL_REVIEW`)。當目錄核算覆蓋率不完整時，系統嚴格禁止宣告代碼庫為乾淨（Clean Claim Fail-Closed）。宣告乾淨（Clean）代表在界定範圍內無已驗證且未修復之實質弱點與證據缺口，屬於有界保證（Bounded Assurance），而非萬無一失的絕對認證。

---

## 審查意圖與收斂語義 (Audit Intents)

1. **`DISCOVERY`**: 開放式探索代碼庫組件與弱點家族矩陣，產生附帶客觀證據之候選假說。無發現配額，0 弱點為合法常態。
2. **`VALIDATION`**: 針對特定候選項進行獨立 3-Lens 面板審核，判定最終處置。
3. **`REGRESSION`**: 補丁驗證與覆蓋收斂模式。重跑時僅重審受變更影響的攻擊面，防止無止盡的發散探索。

---

## 支援工作合約 (Operational Job Modes)

1. **`scan`**: 全代碼庫弱點掃描，採用嚴格確定性目錄會計制度 (`Directory Accounting`)。
2. **`review`**: 針對 Git commit/PR 變更之增量審查，100% 核對變更與刪除檔案，並透過安全 pre-image 檢視歷史原貌。
3. **`validate`**: 針對現有弱點報告進行獨立驗證，無需全庫重掃即可檢驗單一候選項。
4. **`deep`**: 多輪隨機發現 (`Multi-Run Deep Scan`)，採用長度前綴確定性指紋去重並統計再現次數 (`recurrenceCount`)。
5. **`remediate`**: 於獨立 `scratch/patches/` 沙箱內生成最小手術式補丁，受 Patch Jail 周界防護。
6. **`verify-fix`**: 補丁驗證合約，結合 3-Lens 驗證專家團（DEFENSES、REACHABILITY、IMPACT）與基準過期檢測 (`detectStalePatch`)，嚴格防止迴歸與後門。

---

## 3-Lens 驗證面板 (Conjunctive 3-Lens Verifier Panel)

採用合取邏輯 (Conjunctive Logic)，防止 2-to-1 民主式投票覆蓋具體技術事實：
- **Reachability Lens**: 檢驗呼叫圖與污點路徑可達性；若反駁 (`REFUTES`) 則判定不可達。
- **Defenses Lens**: 檢驗消毒器與安全不變量；反駁必須附帶行號與證據 (`mitigationProofLine` + `mitigationReason`)，阻斷民主投票碾壓。
- **Impact Lens**: 驗證 CVSS v4 11 維向量與實質危害；反駁必須證明無實質危害。

---

## 四層縱深防禦架構與沙盒規範 (4-Layer Defense-in-Depth)

審計不受信任的目標代碼需要多層防護，以抵禦提示詞注入、目錄穿越、未授權工具呼叫與主機入侵。本專案正式確立四層縱深防禦體系：

| 防禦層 | 組件 | 邊界與防護機制 | 安全目標 |
| :--- | :--- | :--- | :--- |
| **Layer 1** | **終端沙盒**<br>`agy --sandbox` | OS 層級容器 / 命名空間 / Seatbelt 隔離 | 阻斷不受信任目標代碼在終端執行任意指令、惡意網路外聯或持久破壞檔案系統。 |
| **Layer 2** | **權限引擎**<br>`recommended-security-audit-permissions.json` | AGY CLI 執行期工具調度 (`deny > ask > allow`) | 依審計角色 (`coordinator`、`discovery`、`verifiers`、`remediation`) 限縮可用工具，杜絕越權調度或資料外洩。 |
| **Layer 3** | **陰影上下文守衛**<br>`hooks/shadow-context-guard.mjs` | PreToolUse 生命週期勾點 | 攔截檔案讀取操作，透明重定向至 `scratch/context/` 去敏沙盒複本，阻斷符號連結目錄逃逸 (CWE-59)。 |
| **Layer 4** | **確定性 TCB**<br>`path-containment.mjs` | 原子檔案描述子檢驗 (`fs.openSync` + `fs.fstatSync`) | 消除檔案系統競爭條件 (TOCTOU) 與同級目錄欺騙 (如 `scratch/context-evil`)。 |

### 推薦權限設定檔使用方式

為在生產環境以最小權限運行安全審計，建議啟用終端沙盒啟動 Antigravity：

```bash
# 於 OS 沙盒與角色權限管控下執行安全審計
agy --sandbox "audit this repository for security vulnerabilities"
```

`recommended-security-audit-permissions.json` 所定義的角色權限邊界：
- **`coordinator`** (主協調代理)：允許協調工具 (`invoke_subagent`、`send_message`、`run_command:node skills/3lens/scripts/*`)；詢問 `run_command:git *`；嚴格拒絕網路外聯 (`read_url_content`、`search_web`、`curl`、`wget`) 與寫入操作。
- **`discovery`** (漏洞發現代理)：僅唯讀探索 (`view_file`、`list_dir`、`grep_search`、`find_by_name`)；嚴格拒絕所有寫入、網路與命令執行。
- **`verifiers`** (3-Lens 驗證群)：僅唯讀檢驗；嚴格拒絕所有寫入、命令執行與網路存取。
- **`remediation`** (修復代理)：於隔離 scratch 工作區生成外科手術式最小修復；詢問 `write_to_file`；嚴格拒絕 CI/CD 清單 (`.github/*`)、Git 元資料 (`.git/*`)、遠端推送 (`git push`) 與網路外聯。

---

## 目錄結構

```text
three-lens/
├── package.json                          # npm test, test:evals, test:semantic, test:discovery, test:stability, check:release (1.12.0)
├── plugin.json                           # Antigravity 外掛清單 (含 schema，無 BOM)
├── hooks.json                            # Antigravity hook 註冊（PreInvocation、PreToolUse）
├── hooks/                                # 生命週期勾點實作
│   ├── pre-invocation-secret-guard.mjs   # PreInvocation hook：在送往模型前掃描提示中的機密
│   └── shadow-context-guard.mjs          # PreToolUse 拒絕未經審核之原庫存取並導向 scratch/context/
├── recommended-security-audit-permissions.json # AGY Default-Deny 角色最小權限設定檔
├── SECURITY.md                           # 誠實信任模型與沙箱邊界說明
├── CHANGELOG.md                          # 發行紀錄
├── CONTRIBUTING.md                       # 貢獻指南
├── LICENSE                               # MIT 授權
├── agents/                               # 專責子代理定義 (位於外掛根目錄)
│   ├── security-audit-coordinator.md     # 主要協調者代理（mainAgent）
│   ├── threat-modeler.md                 # 威脅建模專員
│   ├── discovery-agent.md                # 9x10 矩陣探索專員
│   ├── verifier-reachability.md          # 3-Lens 可達性檢驗專家
│   ├── verifier-defenses.md              # 3-Lens 防禦機制檢驗專家
│   └── verifier-impact.md                # 3-Lens 危害校準檢驗專家
├── evals/                                # 測試語料庫與語意基準
│   ├── vulnerable/                       # 10 大地面真值漏洞 (True Positives)
│   ├── safe/                             # 10 大修復對照組防禦屏障 (False Positive Guards)
│   ├── prompt-injection/                 # 5 大提示詞注入穿透測試
│   ├── report-injection/                 # 5 大報告投毒與控制字元測試
│   ├── secret-leak/                      # 5 大機密憑證脫敏測試
│   ├── coverage-gap/                     # 5 大會計覆蓋邊界測試
│   ├── git-config/                       # 5 大惡意 Git 配置隔離測試
│   ├── patch-regression/                 # 5 大惡意補丁與陳舊基準測試
│   ├── semantic-benchmark/               # L1.5 配置地面真值基準 (20 對照組：10 弱點 + 10 防禦對照組)
│   ├── holdout-benchmark/                # 保留集基準測試樣本
│   ├── live-runs/                        # 實機基準測試的錄製結果
│   ├── micro-corpus/                     # 微型語料與 ground-truth.json
│   ├── oss-corpus/                       # 開源專案的修復 diff
│   ├── protocols/                        # 評測協定定義
│   ├── recorded-runs/                    # 穩定性基準測試用的多輪錄製結果
│   ├── reproduction-records/             # 重現紀錄
│   └── test-reports/                     # 測試執行輸出存檔
├── schemas/                              # R2-P1-08 版本化 JSON 綱要 (Draft-07)
│   ├── scan-manifest.schema.json         # 目錄會計清單綱要
│   ├── threat-model.schema.json          # 威脅模型綱要
│   ├── candidate.schema.json             # 候選弱點綱要 (Security Property & Lineage)
│   ├── verifier-ballot.schema.json       # 檢驗選票綱要 (3-Lens 證據綁定)
│   ├── canonical-finding.schema.json     # 權威規範弱點綱要 (分類法與原因碼)
│   ├── execution-attestation.schema.json # 執行證明綱要 (階段覆蓋完整性)
│   ├── audit-baseline.schema.json        # 審計歷史基準綱要
│   ├── empirical-benchmark-run.schema.json # 實證評測 run envelope 綱要
│   ├── permissions-profile.schema.json  # 角色權限設定檔綱要
│   ├── candidate-set.schema.json        # 候選集合 Schema
│   ├── cross-model-protocol.schema.json # 跨模型協定 Schema
│   ├── doctor-report.schema.json        # Doctor 報告 Schema
│   ├── eval-protocol.schema.json        # 評測協定 Schema
│   ├── evidence-matrix.schema.json      # 證據矩陣 Schema
│   ├── operator-metrics.schema.json     # 操作者指標 Schema
│   ├── reproduction-record.schema.json  # 重現紀錄 Schema
│   ├── shadow-cohort-record.schema.json # Shadow cohort 紀錄 Schema
│   └── verifier-ballot-set.schema.json  # 驗證者投票集合 Schema
├── rules/
│   └── AGENTS.md                         # 全域零信任與資料審查邊界規則
├── .github/                              # CI 工作流程（PR CI、發行、Semgrep）
├── .security-audit/                      # 本 repo 的專案安全脈絡
├── docs/                                 # 指南、重現說明與 RFC
├── reports/                              # 含日期的基準測試與重現報告
├── scripts/                              # 專案工具：doctor、發行來源驗證、基準測試、版本遞增
├── test/                                 # 測試樣本（例如 Cloudflare adapter）
├── tests/                                # 治理與不變量測試套件
└── skills/
    └── 3lens/
        ├── SKILL.md                      # 主技能進入點與工作流程調度
        ├── tool-integrity-manifest.json  # 關鍵腳本的完整性清單
        ├── standards/                    # R2-P1-01 標準映射層
        │   ├── standards-map.json        # CWE -> ASVS 5.0 / SSDF / OWASP 映射
        │   └── applicability-profiles.json # 專案類型適用性設定檔
        ├── jobs/                         # 6 大標準工作合約規格
        │   ├── scan.md                   # 全庫會計審查合約
        │   ├── review.md                 # 差異與 pre-image 審查合約
        │   ├── validate.md               # 獨立弱點校驗合約
        │   ├── deep.md                   # 多輪隨機發現與聯集合約
        │   ├── remediate.md              # 最小手術補丁生成合約
        │   └── verify-fix.md             # 補丁驗證與防禦不變量確認合約
        ├── references/
        │   ├── discovery.md              # 9 大元件 × 10 大弱點家族矩陣
        │   ├── patching-jail.md          # 補丁監獄邊界規格
        │   ├── swarm-consensus.md        # 3-Lens 連取共識規範
        │   ├── threat-modeling.md        # 威脅建模與 11 維向量基準
        │   ├── verifier-protocol.md      # 檢驗協議與證據綁定不變量
        │   ├── finding-lineage.md        # 弱點血統追蹤與指紋架構
        │   ├── safe-proof-policy.md      # 安全防禦證明政策與禁止指令
        │   └── model-independence.md     # 模型與供應商獨立性規格
        └── scripts/
            ├── path-containment.mjs      # 權威 TCB 路徑包容與抗 TOCTOU 原子檔案讀取器
            ├── safe-git.mjs              # 強化安全 Git 執行隔離器
            ├── finalize-scan.mjs         # 權威確定性終審器與標準整合
            ├── standards-mapping.mjs     # 業界標準映射與依賴邊界檢測器
            ├── render-sarif.mjs          # SARIF 2.1.0 / Markdown 渲染與 121 項不變量測試
            ├── build-inventory.mjs       # 地面真值目錄會計清單生成器
            ├── build-threat-model.mjs    # 確定性威脅模型生成器
            ├── validate-attack-path.mjs  # 攻擊路徑 Schema 2.0 校驗與證明缺口偵測
            ├── validate-patch.mjs        # 補丁語法、Patch Jail、過期檢測與修復驗證
            ├── run-evals.mjs             # 50 題確定性安全不變量與對抗迴歸套件
            ├── run-semantic-eval.mjs     # L1.5 決策地面真值基準測試 (Disposition Ground-Truth)
            ├── run-discovery-eval.mjs    # 代理發現評測套件 (Simulated CI / Recorded Agent Run)
            ├── run-stability-eval.mjs    # 發現穩定度與多輪實證基準評測引擎
            ├── record-benchmark-run.mjs  # 真實模型實證基準封套記錄工具
            ├── prepare-review-context.mjs   # 送入模型前的脈絡準備與機密保護
            ├── project-context.mjs          # 專案安全脈絡的載入、驗證與漂移偵測
            ├── adapters/                    # 發現產出者轉接器
            │   └── cloudflare-adapter.mjs   # Cloudflare security-audit-skill 發現轉接器
            └── check-release-invariants.mjs # Section 24 發行不變量閘門 (62 項規格，40 項安全不變量)
```

---

## 測試與發行驗證

在專案目錄內執行：
```bash
# 執行全域安全不變量自動化測試：
npm test

# 執行 50 題確定性安全不變量與對抗迴歸套件：
npm run test:evals

# 執行 L1.5 處置決策地面真值基準測試 (20 對照組)：
npm run test:semantic

# 執行代理發現評測基準測試 (Simulated CI)：
npm run test:discovery

# 執行穩定度基準測試 (Synthetic Harness)：
npm run test:stability

# 執行記錄合成穩定度基準測試 (多輪評測模式)：
npm run test:stability-recorded

# 執行 Section 24 發行閘門檢驗 (檢查必要規格、安全不變量與零外部依賴)：
npm run check:release

# 驗證文件完整性與防止文件漂移：
npm run check:docs

# 驗證發行來源與 SLSA 認證政策：
npm run test:provenance
```

---

## 公開基準宣稱政策 (Public Benchmark Claims Policy - R2-P2-02)

本工具嚴格遵循誠實揭露原則，不進行誇大或誤導性宣稱：
- **不宣稱「100% 準確率」或「絕對無漏洞」**：Clean 審查結果僅代表在**宣告範圍內完成定義覆蓋**、未發現具備驗證證據之可報告問題，並非全域安全證明。
- **測試集與基準測量透明度揭露**：
  - **確定性安全不變量與對抗迴歸套件**：50 案例（覆蓋 8 種邊界威脅），驗證確定性規則與防禦邊界（Invariant Rate: 100%）。
  - **L1.5 處置決策地面真值基準**：20 對照組（10 弱點，10 安全防護），評測 Finalizer 確定性處置決策邏輯 (100% 20/20 PASS)，度量決策合規性而非 LLM 發現率。
  - **記錄合成穩定度評測**：在 `evals/recorded-runs/` 中跨 3 輪合成執行評測 10 個獨立語意血統之跨輪確定性與行號位移不變性 (100% 10/10 血統，Mean Jaccard 100.0%)。
  - **實證模型發現評測**：真實 AGY CLI 執行 Harness (`scripts/run-live-model-benchmark.mjs`) 追蹤開發基準（SEM-03 迴歸組）與保留泛化測試組。

| 基準測試項目 (Benchmark) | 語料規模 (Corpus) | 測量類型 (Measurement Type) | 公開狀態 (Status) |
| :--- | :--- | :--- | :--- |
| 確定性安全不變量 (Deterministic Invariants) | 50 案例 (8 類邊界威脅) | 確定性規則測量 (MEASURED) | 100% PASS |
| 處置決策地面真值 (Disposition Ground Truth) | 20 對照組 (10 弱點 / 10 防護) | 確定性決策測量 (MEASURED) | 100% PASS (20/20) |
| 記錄合成穩定度 (Recorded Synthetic Stability) | 10 獨立血統 (3 輪合成 pass) | 合成穩定度自檢 (RECORDED_SYNTHETIC) | 100% PASS (10/10 血統) |
| 穩定度評測 Harness (Synthetic Stability) | 3 語料庫合成 pass | 合成管線自檢 (SYNTHETIC_HARNESS) | PASS |
| 實證模型發現 (Empirical Model Discovery) | 10 基準測試案例 (SEM-03 開發基準) | 實體模型觀測 (MODEL_OBSERVED) | 基準已建立 (BASELINE ESTABLISHED) |

- **模型無關架構**：所有代理契約均採用資料架構與 JSON Schema 進行嚴格規格化，協調器與裁決核心不依賴任何特定 LLM 之專有隱藏行為。

---

## 授權與治理規範 (Governance & Defensive Use - R2-P2-07)

- 本專案採用 **MIT 授權條款**（詳見 [LICENSE](LICENSE)）。
- **專案範疇與防禦用途聲明**：本工具專為合法授權之防禦性安全審查、弱點驗證與防禦性研發設計並提供支援。非設計、不預期亦不支援用於未經授權之滲透測試、漏洞利用、破壞性指令執行、憑證重用或非經同意之外部系統探測。
