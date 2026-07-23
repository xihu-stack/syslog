# IP-Guard 员工行为 AI 分析系统 · 设计文档（v1）

- **日期**：2026-07-22
- **状态**：草案，待评审
- **定位**：纯靠 IP-Guard 日志、零外部数据依赖、架构简单但检测不窄、能跑通闭环的最小可用版本

---

## 1. 背景与目标

公司部署了 IP-Guard 终端安全 / DLP 系统，持续产生大量员工行为日志。本系统利用**本地大模型**对这些日志进行**行为意图分析**，覆盖**数据泄露**与**离职风险**两类核心场景，并支持**近实时告警**。

- **首要目标**：两者并重——同时服务**安全/IT 团队**（数据泄露检测）与 **HR/管理层**（离职/稳定分析），统一数据底座、按角色隔离视图。
- **v1 目标**：用最低风险拿到一个**可解释、可上线、能闭环**的系统，把"AI 意图分析"的价值真正跑出来；数据与需求齐备后再迭代增强。

---

## 2. 范围

### 2.1 v1 包含
- 接入 IP-Guard 三类日志：**文档操作(DOC)、网页浏览(WEB)、网页搜索(SEARCH)**
- 每用户**轻量行为画像（基线）**
- **触发器 + 本地 LLM 检测**（意图 + 偏离 + 风险）
- **多通道数据外发检测**（U盘 / 网盘 / 个人邮箱，**语义识别，非字典硬匹配**）
- **求职行为检测**、**行为偏离基线检测**、批量异常、高危搜索
- **单通道告警 + 推送**（钉钉/飞书/邮件）
- 分析师前端：告警总览 / 告警详情 / 员工视图 / 字典配置
- **TP/FP 标注反馈**（为后续反哺做准备）

### 2.2 v1 不含（后续迭代）
- 员工目录打通（部门/岗位/在职时间）、文件密级分类接入
- 案件调查工作流、RBAC、完整审计、留存治理
- HR/高管专属视图、风险大屏
- 重型 ML 异常模型、双人复核、跨信号复杂关联编排
- Redis/Kafka 等流式中间件（v1 用 PG 轮询/批量）

### 2.3 后续迭代路线
- **v1.1**：稳定 AI 意图层、基线更精细、简单跨信号关联
- **v2**：打通员工目录与文件密级、案件台、反馈闭环反哺、RBAC+审计
- **v3**：高管大屏、ML 异常模型（方案B）、双人复核等治理能力

---

## 3. 关键约束与决策（汇总）

| 维度 | 决策 | 理由 |
|---|---|---|
| 数据接入 | IP-Guard **OTransLog → Syslog 推送** | 官方支持、推送式、解耦、可按类型过滤；不直连生产库 |
| 实时性 | **近实时**，端到端 5–15 分钟 | IP-Guard 客户端默认 5 分钟上报，是物理下限；对目标场景足够 |
| AI 部署 | **本地私有化大模型**（vLLM/Ollama, Qwen2.5-7B/14B） | 员工日志高敏感，数据不出内网，PIPL 合规 |
| 检测架构 | **触发器（便宜门）+ LLM 当检测器** | 规则会"窄"，靠枚举漏报严重；LLM 语义泛化 + 意图理解才是核心价值 |
| 基线 | **轻量滚动统计画像，喂给 LLM 当上下文** | 不上重型 ML；LLM 自行做偏离判断；简单且够用 |
| 身份 | 直接用 **IP-Guard 报上来的 Windows 账号/机器名** | v1 无员工目录，零外部依赖 |
| 敏感判定 | 关键词/域名字典作为 **LLM 提示，非命中门槛** | 无数据分级；字典辅助泛化、可配置 |
| 规模 | 小（<500 人，<100 万事件/天） | 轻量栈，PG 轮询，不上分布式中间件 |
| 技术栈 | Python(FastAPI) + PostgreSQL + React(AntD) | AI 生态好、团队背景匹配 |

---

## 4. 数据源

### 4.1 接入路径
```
IP-Guard 客户端 ─默认5min─▶ IP-Guard 服务器 ─缓存文件移交─▶ OTransLog 工具
                                                                   │ Syslog 推送
                                                                   ▼
                                                          本系统 ingest-svc
```

IP-Guard 侧配置要点：
- 服务器 `OServer3.ini` 配置 `TOOLS` 与移交目录 `Path`
- `Type` 指定移交的日志类型（网页浏览 / 文档操作 / 移动存储操作 / 文档打印 / 应用程序 / 基本事件等）
- `TOOL/OTransLog.ini` 配置 Syslog 服务器地址
- **M0 前必须向厂商确认本版本支持 OTransLog/Syslog**（旧版可能仅有 OKafkaUploadTool 或不支持；不支持则降级为"控制台定时导出文件"）

### 4.2 三类日志 → 标准事件

| IP-Guard 日志 | 标准 category | 说明 |
|---|---|---|
| 文档操作 / 文档打印 / 移动存储操作 | **DOC** | 文件读写/拷贝/删除/打印；U盘挂载与拷贝 |
| 网页浏览 | **WEB** | URL 访问（含网盘 / 个人邮箱 / 招聘 / 竞对域名） |
| 解析自网页浏览的搜索引擎 URL（或自带搜索日志） | **SEARCH** | 搜索引擎 query 关键词 |

> SEARCH 的 query 从搜索引擎 URL 参数解析（如 `baidu.com/s?wd=关键词` → `关键词`）；若 IP-Guard 版本自带"搜索关键词"日志则直接用。

### 4.3 测试 / 回放入口（CSV/Excel 导入）

为在 Syslog 接入打通前（或回放历史日志时）验证检测效果，提供 **CSV/Excel 批量导入**入口，与 Syslog 共用同一套标准事件 schema，写入同一张 `events` 表。

- **用途**：① M0/M1 阶段用样本/历史日志快速验证 AI 检测效果（不依赖 IP-Guard 实时接入）；② 回放真实历史日志做端到端测试（见第 13 节）；③ 后续作为"手动补录/重跑"通道。
- **支持格式**：`.csv` / `.xlsx` / `.xls`，列同标准事件 schema（见下表）。
- **去重**：按 `event_hash` 幂等，重复导入不产生重复事件。
- **示例数据**：见 `samples/ipguard-sample-events.csv`（含数据外发 / 求职 / 基线偏离 / 正常基线 四类场景）。
- **导入后**：可手动触发 `profile-builder` + `detector` 对导入数据跑一遍，在前端看告警效果。

**导入 CSV 列（标准事件 schema）：**

| 列 | 说明 | 示例 |
|---|---|---|
| `occurred_at` | 事件时间 | `2026-07-22 02:30:00` |
| `employee_id` | IP-Guard 报上来的账号/机器用户 | `zhangsan` |
| `device_id` | 计算机名 | `PC-001` |
| `category` | DOC / WEB / SEARCH | `DOC` |
| `action` | READ/WRITE/COPY/DELETE/PRINT/MOUNT/VISIT/SEARCH | `COPY` |
| `target_type` | FILE / URL / DEVICE | `FILE` |
| `target_value` | 文件名 / URL / 设备名 | `客户名单_2026.xlsx` |
| `size_bytes` | 字节数（批量量纲） | `20480000` |
| `count` | 数量（批量量纲） | `200` |

---

## 5. 架构

### 5.1 组件图

```
        ┌───────────────┐
IP-Guard│  ingest-svc   │  Syslog → 解析 → 标准事件
OTransLog│  采集器       │  (DOC / WEB / SEARCH)
─Syslog▶│               │─────────────▶ events 表
        └───────┬───────┘
                │
   ┌────────────┼─────────────────┐
   │            │                  │
   ▼            ▼                  ▼
profile-    detector-pipeline     (供前端查询)
builder     ┌──────────────────┐
(每日统计)  │ ① windower 攒窗口 │
   │        │ ② trigger 便宜门   │─无兴趣─▶跳过(省钱)
   ▼        │ ③ llm-analyzer    │◀─ profiles 表(画像)
profiles表  │   意图+偏离+风险   │◀─ 本地 LLM(Ollama/vLLM)
            └────────┬─────────┘
                     ▼ verdicts
              alert-engine(去重/分级)
                     │
              ┌──────┴──────┐
              ▼             ▼
         notify-svc      alerts 表
         (钉钉/飞书/邮件)   │
                            ▼
                      api-gw (FastAPI) ◀── feedback(TP/FP)
                            │
                            ▼
                    Frontend (React + AntD)
```

### 5.2 组件职责（单一职责、接口清晰、可独立测试）

| 组件 | 职责 | 接口 | 依赖 |
|---|---|---|---|
| `ingest-svc` | 收 Syslog → 解析 → 标准事件（DOC/WEB/SEARCH），幂等去重 | 写 `events` | PG |
| `profile-builder` | 每日滚动算每用户画像（时段/量/通道/对象） | 读 events → 写 `profiles` | PG |
| `detector` | 攒窗口 → 便宜触发门 → 调 LLM 出（意图/偏离/风险） | 读 events+profiles → 写 `verdicts` | PG、本地 LLM |
| `alert-engine` | 去重、按风险分级、生成告警 | 写 `alerts` | PG |
| `notify-svc` | 推钉钉/飞书/邮件（限流+重试） | 读 alerts | IM/邮件 |
| `api-gw` | 前端 REST API + TP/FP 反馈 + 字典配置 | REST | PG |
| `frontend` | 告警分流 / 调查 / 员工视图 / 配置 | 调 api-gw | — |

**LLM 宕机兜底**：detector 调不通 LLM 时，对已触发窗口跑极简规则分（如"敏感文件名 + U盘/网盘/个人邮箱域名"），照常出粗告警并标记 `ai_participated=false`，闭环不断。

### 5.3 端到端数据流
1. IP-Guard → Syslog → `ingest-svc` 解析为标准事件 → `events`
2. `profile-builder` 每日滚动更新 `profiles`
3. `detector` 周期性：按"员工+时间窗"攒窗口 → 触发门判断 → 有兴趣则送 LLM（带画像）→ 出 verdict
4. LLM 不可用 → 极简规则兜底出粗 verdict
5. `alert-engine` 去重分级 → `alerts`
6. `notify-svc` 推送；前端经 `api-gw` 展示
7. 分析师标注 TP/FP → `feedback`（后续反哺阈值与 prompt）

---

## 6. 数据模型（PostgreSQL）

| 表 | 关键字段 | 说明 |
|---|---|---|
| `events` | id, occurred_at, ingested_at, employee_id, device_id, category, action, target_type, target_value, size_bytes, count, raw(JSONB), event_hash | 标准事件；按 occurred_at 月分区；event_hash 幂等去重 |
| `profiles` | employee_id, as_of, active_hours, daily_doc_op_p50/p90, channels_used[], file_keywords{}, search_topics{}, web_categories{}, version | 用户画像（滚动统计，JSONB） |
| `verdicts` | id, employee_id, window_start/end, event_refs, intent_label, deviation_level, risk_score, intent_score, deviation_score, confidence, explanation, detected_channels[], model, prompt_version, ai_participated, created_at | LLM/兜底判断结果 |
| `alerts` | id, employee_id, scenario, severity, risk_score, verdict_id, summary, status, dedup_key, routed_to, notified_at, created_at | 告警；status: NEW/TRIAGING/CONFIRMED/FP/CLOSED |
| `feedback` | id, alert_id, label(TP/FP), labeled_by, reason, created_at | 分析师标注 |
| `dict_*` | — | 配置字典：敏感文件名词、招聘网站、外发通道域名（网盘+个人邮箱）、风险搜索词、竞对域名 |
| `audit_logs` | actor, action, target, occurred_at | v1 lite 审计 |

### 标准事件 Schema（系统通用语）

| 字段 | 说明 | 示例 |
|---|---|---|
| `category` | DOC / WEB / SEARCH | DOC |
| `action` | READ/WRITE/COPY/DELETE/PRINT/MOUNT/VISIT/SEARCH… | COPY |
| `target_type` | FILE / URL / DEVICE | FILE |
| `target_value` | 受控脱敏后的对象 | `客户名单_2026.xlsx` |
| `employee_id` / `device_id` / `occurred_at` | 谁、哪台机器、何时 | |
| `size_bytes` / `count` | 量纲（批量检测用） | count=200 |
| `raw` | JSONB 原始日志兜底 | `{...}` |

---

## 7. 检测核心

### 7.1 触发器（便宜门）
目的：**成本控制，不漏检**。规则宽，某窗口含以下任一即送 LLM：
- 文档操作（尤其 COPY/DELETE/PRINT）
- 外发通道相关动作（U盘挂载、访问网盘/个人邮箱域名）
- 网页搜索
- 与画像偏离的迹象（首次使用某通道、时段异常）
- 无任何上述动作的纯常规浏览 → 跳过

### 7.2 LLM 检测器
**输入**：当前行为窗口 + 该用户画像摘要 + 场景指引 + 字典提示。
**PII 最小化**：LLM 只看结构化特征序列，不看文件正文/正文内容。

**输出（强制结构化 JSON）**：
```json
{
  "intent_label": "data_exfiltration | job_seeking | baseline_deviation | normal_work | ...",
  "deviation_level": "none | minor | major | severe",
  "risk_score": 0,
  "intent_score": 0,
  "deviation_score": 0,
  "confidence": 0.0,
  "explanation": "一句/一段中文解释",
  "evidence_refs": ["evt_id"],
  "detected_channels": ["usb", "netdisk:pan.xunlei.com", "personal_email:mail.qq.com"]
}
```

**工程要点**：
- 低温(0.1) 保一致；记录 `model + prompt_version` 可复现
- 强制 JSON 输出 + 封闭枚举校验（越界降级为规则兜底）
- 按窗口哈希缓存
- few-shot 正反例库（由 feedback 喂养，越用越准）

### 7.3 兜底（LLM 不可用）
对已触发窗口跑极简规则分：如"敏感文件名词 + U盘/网盘/个人邮箱域名" → 粗告警，标记 `ai_participated=false`。

---

## 8. 场景定义

| 场景 | 典型信号（LLM 语义判定，非穷举字典） |
|---|---|
| 数据外发（多通道） | 敏感文档操作 + 外发通道（U盘/网盘/个人邮箱）；含规避行为（改名/压缩/加密）；偏离基线加权 |
| 求职行为 | 访问招聘网站 + 搜索求职词 + 简历类文档操作 |
| 行为偏离基线 | 时段/数量/通道/对象任一显著偏离个人画像 |
| 批量异常 | 短时大量打印/拷贝 |
| 高危搜索 | 搜索"绕过DLP/网盘/数据恢复/匿名邮箱/外发工具/竞对公司"等 |

---

## 9. 告警

- **严重度基于 LLM 给出的 `risk_score`**（由意图分 `intent_score` 与偏离分 `deviation_score` 综合得出）；档位：0-30 🟢 / 31-60 🟡 / 61-85 🟠 / 86-100 🔴
- **去重**：`dedup_key = employee + scenario + window`，冷却期 2h 内同键更新不新建
- **路由（v1）**：单通道推送给安全/IT；后续按角色分安全/HR/高管
- **抑制**：字典/规则可配白名单与单人静默

---

## 10. 前端设计

### 10.1 原则
1. **AI 解释前置**——每条告警第一眼就是一句人话解释（信任与采纳的命门）
2. **证据可追溯**——解释 → 证据时间线 → 原始日志，三层下钻
3. **基线上下文**——永远展示"平时 vs 现在"
4. **快速分流**——TP/FP 一键、键盘友好
5. **v1 是分析师工具**（高效分流/调查），不先搞高管大屏
6. **合理性/伦理**——结论用"疑似/可能"由人定夺；身份/证据按角色可见、全程审计

### 10.2 页面
- **告警总览**：收件箱式，按风险排序，AI 摘要前置，多维筛选（场景/严重度/状态/搜索）
- **告警详情**：AI 判断卡（意图/偏离/置信度/解释/分项分）+ 证据时间线 + **基线对比** + TP/FP/升级
- **员工视图**：画像（活跃时段/常用通道/常碰对象）+ 历史告警与事件 + 风险趋势
- **字典配置**：维护各类字典，即时生效

### 10.3 线框（要点）
- 总览行：`[🔴95][外发] 张三·凌晨批量拷客户名单到U盘(从未用U盘) [2分钟·新]`
- 详情卡：意图/偏离/置信度 + 一段解释 + 意图分/偏离分/复合分；基线对比用 ❗ 标注每项偏离

---

## 11. 技术栈与部署

- **后端**：Python 3.11, FastAPI, SQLAlchemy + Alembic, APScheduler, httpx
- **存储**：PostgreSQL 15（events 月分区）
- **LLM**：Ollama(开发) / vLLM(生产)，Qwen2.5-7B/14B-Instruct
- **前端**：React + TypeScript + Ant Design + ECharts
- **部署**：Docker Compose（应用主机 + GPU 主机）
- **硬件估算**：应用 8–16 vCPU / 32GB / 500GB SSD；GPU 1×24GB（4090/A10）跑 7–14B

---

## 12. 合规与隐私（v1 基线 + 后续强化）

- **数据最小化**：LLM 只看结构化特征，不看文件正文/正文内容
- **按角色可见**：身份/证据按角色控制；访问审计（v1 lite）
- **留存**：events 可配保留期（默认 90 天），告警长期保留（后续）
- **告知义务**：配合 HR/法务履行员工告知（劳动法/PIPL），系统提供水印/最小化/审计支撑
- **结论"疑似"化、人工定夺**，防滥用

---

## 13. 测试策略

- **解析器**：用真实 IP-Guard 样本日志做契约测试
- **触发器**：合成事件验证"该跳过的跳过、该送审的送审"
- **LLM**：建立标注 eval 集（TP/FP），测每场景 precision/recall；prompt 改动做回归
- **兜底**：LLM down 时回退路径
- **端到端**：回放历史日志验证告警质量

---

## 14. 里程碑（建议）

| 里程碑 | 周期 | 交付 |
|---|---|---|
| **M0** | 1–2 周 | 环境 + 接入打通（OTransLog、第一份真实 Syslog、解析器、schema 定稿） |
| **M1** | 2–3 周 | events 入库 + profile-builder + detector 骨架 + 极简规则兜底 + 最简告警页（无 LLM 也能闭环） |
| **M2** | 2–3 周 | 本地 LLM 部署 + detector 接 LLM + 告警详情页（解释/证据/基线） |
| **M3** | 1–2 周 | 员工视图 + 字典配置 + 推送 + TP/FP 反馈 |
| **M4** | 1 周 | 硬化、文档、合规 lite |

---

## 15. 风险与待办

| 编号 | 风险 | 缓解 |
|---|---|---|
| R1 | IP-Guard 版本是否支持 OTransLog/Syslog | M0 前向厂商确认；不支持则降级"定时导出文件" |
| R2 | 本地 LLM 质量与一致性 | eval 集 + few-shot + 低温 + 反馈反哺 |
| R3 | 基线需 1–2 周养成 | 头期退回"通用可疑度"判断，仍可用 |
| R4 | 误报扰民 | 基线对比 + TP/FP + 白名单 |
| R5 | 合规告知与权限 | 配合 HR/法务，最小化 + 审计 |

---

## 附录 A：术语
- **触发器（trigger）**：便宜的前置过滤，只判断"值不值得让 AI 看一眼"，不负责定性。
- **画像（profile）**：每用户滚动统计的行为基线，喂给 LLM 做偏离判断。
- **verdict**：LLM/兜底对一个行为窗口的判断结果（意图/偏离/风险/解释）。
- **外发通道**：U盘/网盘/个人邮箱 等可能将数据带出企业的途径。
