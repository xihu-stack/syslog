# AI 灵魂：案例库自进化 设计文档

日期：2026-09-04 ｜ 状态：设计已批准（八节全通过），待实施计划
决策记录：案例库自进化 × 案例源=人工处置+抽样审计 × 两层学习（蒸馏准则+案例few-shot） × 分类=顶层骨架稳+子类开放 × 方案B分期落地

## 边界声明

本地 vLLM（glm-5.3-flash）不改变模型权重。"自我学习"发生在系统知识层：
案例 → 准则 → 场景标签三层知识自我增长，全部可审计、可回滚。
路由终态（已定，不再动）：代码管事实（计数/聚合/成本门控/降噪），语义全归 AI
（意图/定性/分数），案例库管口径对齐。

## 一期：案例管道 + 难例注入

### 数据模型
- `cases` 表：source(disposition_confirm/disposition_fp/exemption/sample_audit)、
  employee_id、intent、outcome、facts_digest(窗口事实摘要，与 daygate digest 同源格式)、
  feature_keys(JSON: intent/域名类集/行为集/时段/量级)、ai_verdict(当时AI结论摘要)、
  delta(人工结论与AI结论差异)、verdict_id/alert_id 溯源链接、created_at。
- 去重：同(员工+意图+特征键hash)近30天只留最新 outcome。不清理（量小）。

### 入库钩子（全部 try/except，失败只打日志不碰主流程）
- 告警处置（确认/误报）：api.py 处置端点写 feedback 时同步 upsert case。
- 豁免创建：入 case(source=exemption)。
- sampleaudit.backfill() 回填 outcome 时顺带入库(source=sample_audit)。

### 检索注入（结构键，不用向量）
- 键=(intent, 域名类集, 行为集, 时段, 量级) 加权评分取 top5，纯 Python/SQL。
- 只给难例：|score - risk_threshold| ≤ 15 或 意图摇摆（复核与主判不一致）时，
  研判 prompt 注入【相似历史案例(人工已复核)】段，5条 ≤800字。

## 二期：准则蒸馏器 + 审核UI

- 触发：新案例≥30条且距上次≥7天，或手动按钮。
- 输入：全量现行准则 + 新案例(facts_digest+ai_verdict+outcome+delta)。
- 输出：JSON [{action: add/update/retire, condition_txt, guidance, rationale, source_case_ids}]。
- `criteria` 表：version、condition_txt、guidance、intent、source_case_ids(JSON)、
  status(pending/approved/rejected/retired)、approved_at。
- 人工门：设置页新Tab逐条 批准/拒绝/改文案；批准后生效=研判 prompt 注入
  【已批准判定准则 v N】段（按 intent 相关筛选）。
- 铁律：准则只进 prompt，不进代码锚点。
- 回滚：版本标记 retired 即从 prompt 消失，历史留痕。
- 新模块 distill.py。

## 三期：场景标签挖掘 + 学习健康度

- `scenario_tags` 表：tag_name、intent(挂靠顶层意图)、pattern_desc、
  evidence_samples、status(pending/approved)。
- 周扫近30天行为聚合（按员工×周，复用 digest 思路）→ AI 提议新场景标签
  （如"离职前打包""夜间批量打印"）→ 人工批准 → verdict 研判 prompt 提供可用
  标签清单，AI 输出 JSON 可带 tags → 报表/大屏新增 tags 维度。
- 顶层五意图（求职/外发/违规/偏离/正常）是告警/报表/大屏/豁免的契约，不动。
- 健康度：/api/system/stats 加 soul 字段（cases_total/criteria_version与active/
  fp_rate_30d/miss_rate(已有)/last_distill/last_mine），大屏一行芯片；
  误报率随准则版本的变化曲线 = 学习是否生效的直接证据。
- 新模块 mine.py。

## 生命体征（并入一期末，防再死16小时无人知）

- faulthandler.register(SIGUSR1)：`docker exec ipguard-ai kill -USR1 1`
  随时安全 dump 全线程栈到 docker logs。
- 研判看门狗：phase=LLM研判中 且 done 停滞>30min → faulthandler.dump_traceback()
  + [soul-watchdog] 告警日志行。

## 错误处理与测试

- 所有新 AI 功能 fail-soft：LLM 挂→不注入不蒸馏不挖掘，主流程照跑
  （复用 llm_enabled=0 快速失败路径）。
- 案例入库失败不影响处置主流程。
- 容器密闭测试（改动文件 /tmp 挂载 + 独立 data 目录）+ mock LLM 验证
  蒸馏 JSON 解析/准则回滚/检索命中/难例触发条件；前端 DOM 验证（不用视觉模型）。

## 交付顺序

一期（案例管道+难例注入+生命体征）→ 二期（蒸馏器+审核UI）→ 三期（场景挖掘+健康度）。
每期独立可用可验收；部署仍走 deploy.py 全量链路（新模块须登记 PY_FILES——
2026-09-03 教训）。
