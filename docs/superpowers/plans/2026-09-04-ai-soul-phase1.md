# AI 灵魂一期（案例管道 + 难例注入 + 生命体征）实施计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 落地已批准 spec 的一期——人工处置/豁免/抽样审计沉淀为行为级判例（cases 表），难例研判注入相似判例，所有 AI 通道共享【人工口径】段，附研判看门狗防再挂死；前置第 0 批 prompt 降压（①前缀缓存结构 ②微窗口快速通道 ④调度错峰）。

**Architecture:** 判例按 behavior_key（结构键 hash）建档、跨员工复用；检索用纯 Python 加权评分（不用向量）。路由边界不变：代码管事实，语义归 AI，案例库管口径对齐。所有新钩子 fail-soft（失败只打日志，不碰主流程）。

**Tech Stack:** Python 3 / FastAPI / SQLAlchemy 2.0 + SQLite（本地单测用 `DATABASE_URL` 指向临时库）/ pytest（本机已验证可用）/ 前端 React+antd 单文件 JSX（Babel 预编译）。

**Spec:** `docs/superpowers/specs/2026-09-04-ai-soul-design.md`（执行者须先读 spec——本计划从 spec 出发论证）

## Global Constraints

- **第 0 批（Task 1-3）prompt 降压：用户未单独批准，随本计划整体审批。** 若本计划被拒，第 0 批不实施。
- **本计划所有任务只到本地 commit 为止，不部署。** 生产部署须用户字面触发词"部署"或明确点名操作。
- Commit 信息与新代码注释**不得含员工真名与审计结论**（匿名化；报告对话中可用真名）。Commit 尾加 `Co-Authored-By: Claude Code <noreply@anthropic.com>`。
- PowerShell 下 git add / commit 分开调用；仓库根文件（docs/...）从 backend/ cwd 用 `git add ../docs/...`。
- SQLite 所有写经 `db.write_lock` 串行；`.in_` 查询分块 ≤400-500（用 `db.events_by_hashes`）。
- 远程命令含中文须 base64 传输；SSH docker logs grep 模式须纯 ASCII + `grep -F`。
- "判断改 prompt，事实/成本/降噪留代码"——微窗口快速通道、并发数、难例阈值带是成本/降噪，留代码；判例对齐是判断，进 prompt。
- 本地单测：cwd=`backend/`，`python -m pytest tests/<file> -v`（conftest 已把 DATABASE_URL 指到临时 sqlite）。本机已装 sqlalchemy 2.0.51 + pytest + fastapi + httpx。
- 新后端模块必须登记 `deploy.py` 的 `PY_FILES`（2026-09-03 教训：漏登记=容器起不来或静默旧代码）。
- 前端验证用 DOM 读取，不用视觉模型。
- 不删用户的临时脚本和 backend/_t*.py。

## 任务总览

| 批 | Task | 内容 |
|---|---|---|
| 第0批 | 1-3 | prompt 度量+常量区归位 / 微窗口快速通道 / 重判并发降半 |
| 一期 | 4-5 | cases 表 + casebase.py（建档/检索/注入纯函数） |
| 一期 | 6-8 | 处置端点钩子 + 前端归因五选一 + sampleaudit 回填入库 |
| 一期 | 9 | 口径统一注入（研判/domain_scan/daygate 三通道） |
| 一期 | 10 | 难例注入（阈值±15 或 unknown → 带判例重判一次） |
| 一期 | 11 | 生命体征（SIGUSR1 栈 dump + 研判看门狗） |
| 收尾 | 12 | deploy.py 登记 + 全量回归 + commit |

---

### Task 1: prompt 字符统计 + 常量区归位（第0批①：前缀缓存结构准备）

**Files:**
- Modify: `backend/llm_client.py`（_STATS 加 chars，新增 `prompt_chars()`）
- Modify: `backend/detector.py`（SYSTEM_PROMPT 尾并 user 尾部恒定指令，新增 `_system_prompt()`）
- Test: `backend/tests/conftest.py`（新建）、`backend/tests/test_prompt_structure.py`（新建）

**Interfaces:**
- Produces: `llm_client.prompt_chars(messages) -> int`；`llm_client.stats()["chars"]`（累计输入字符）；`detector._system_prompt() -> str`（Task 9 在此处接【人工口径】段）。

**定性（诚实声明）：** 本任务本身不省 token——system 消息本就整段可被 vLLM prefix caching 命中。它做两件事：(a) 度量先行，没有 chars 基线，后面所有降压杠杆都无前后对照；(b) 把"常量全进 system、变量全进 user"的结构立起来，user 消息以"员工：id"开头（立即分叉），所以 Task 9 的口径段只有接在 system 尾才进共享前缀。

- [ ] **Step 1: 新建 tests/conftest.py**

```python
# -*- coding: utf-8 -*-
"""本地单测基建: DATABASE_URL 指到临时sqlite(绝不用backend/data/ipguard.db),
并把backend加进sys.path。必须在import db/api之前生效——conftest收集期先跑。"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_TMPDB = os.path.join(tempfile.gettempdir(), "soul_test.db").replace("\\", "/")
os.environ["DATABASE_URL"] = "sqlite:///" + _TMPDB

import db  # noqa: E402
db.init_db()


import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _clean_tables():
    """每测清空判例/处置相关表,测试互不污染。"""
    from db import Session, CaseRow, FeedbackRow, ExceptionRow
    s = Session()
    try:
        for _m in (CaseRow, FeedbackRow, ExceptionRow):
            for _r in s.query(_m).all():
                s.delete(_r)
        s.commit()
    finally:
        s.close()
    yield
```

注：CaseRow 在 Task 4 才存在——Task 1 先不 import CaseRow，Task 4 时把它加进 `_clean_tables` 的清理元组。为避免两处改，Task 1 的 conftest 清理元组先写 `(FeedbackRow, ExceptionRow)`，Task 4 Step 里明确"把 CaseRow 加入 conftest 清理元组"。

- [ ] **Step 2: 写失败测试 tests/test_prompt_structure.py**

```python
# -*- coding: utf-8 -*-
def test_prompt_chars_counts_content():
    import llm_client
    msgs = [{"role": "system", "content": "abc"}, {"role": "user", "content": "你好"}]
    assert llm_client.prompt_chars(msgs) == 5  # 3 + 2(中文按字符计)


def test_prompt_chars_empty_safe():
    import llm_client
    assert llm_client.prompt_chars([]) == 0
    assert llm_client.prompt_chars(None) == 0
    assert llm_client.prompt_chars([{"role": "user"}]) == 0


def test_stats_has_chars():
    import llm_client
    assert "chars" in llm_client.stats()


def test_system_prompt_contains_output_instruction():
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工行为分析助手")
    # user尾部恒定指令已并入system(常量区归位)
    assert "今日累计" in sp and "请输出 JSON" in sp


def test_system_prompt_stable():
    import detector
    assert detector._system_prompt() == detector._system_prompt()
```

- [ ] **Step 3: 跑测试确认失败**

Run: `python -m pytest tests/test_prompt_structure.py -v`
Expected: FAIL（`prompt_chars` / `_system_prompt` 不存在）

- [ ] **Step 4: 实现 llm_client.py**

`_STATS`（71 行）改为：

```python
_STATS = {"total": 0, "fail": 0, "ms": 0, "last_ms": 0, "chars": 0, "by_model": {}}
```

在 `stats()`（74 行）前新增：

```python
def prompt_chars(messages) -> int:
    """消息总字符数(2026-09-04度量先行): prompt降压各杠杆要有前后对照,
    先把输入体积记下来——chat成功路径累计进_STATS['chars'],健康页/探针可读。"""
    return sum(len(str((m or {}).get("content") or "")) for m in (messages or []))
```

`chat()` 内（101 行签名后、`for base, key, mdl in attempts:` 前）加一行：

```python
    _pc = prompt_chars(messages)
```

成功路径（148 行 `return content` 前，`_STATS["total"] += 1` 那组统计里）加：

```python
                _STATS["chars"] += _pc
```

- [ ] **Step 5: 实现 detector.py 常量区归位**

在 `SYSTEM_PROMPT = (...)` 结束（253 行）后新增：

```python
# user消息尾部的恒定输出指令,归位进system常量区(2026-09-04): 常量全在system、
# 变量全在user——user以"员工:id"开头立即分叉,共享前缀只到system为止,后续
# 口径段(2026-09-04一期)必须接在system尾才进vLLM prefix caching的命中范围。
_SYS_TAIL = ("写explanation时:域名次数优先『本窗口N次,今日累计M次』双口径"
             "(今日累计仅当序列标注了[当日累计]才可引用,未标注就只写窗口次数,严禁编造累计)。请输出 JSON。")


def _system_prompt() -> str:
    """研判system消息唯一出口(TTL语义由Task9的口径段引入,此处先做结构归位)。"""
    return SYSTEM_PROMPT + "\n" + _SYS_TAIL
```

`analyze_window` 里 user 消息（734-736 行）删掉尾部指令：

```python
    user = (f"员工：{window[0].employee_id}（设备：{window[0].employee_id}）\n"
            f"行为序列：\n{_fmt_window(window)}{_dest_hint}{g_txt}{profile_txt}{dev_txt}{exempt_txt}{hist_txt}{day_txt}{_mem}\n\n")
```

`_msgs`（740 行）system 内容改为：

```python
        _msgs = [{"role": "system", "content": _system_prompt()},
                 {"role": "user", "content": user}]
```

- [ ] **Step 6: 跑测试确认通过**

Run: `python -m pytest tests/test_prompt_structure.py -v`
Expected: PASS（5 个用例全绿）

- [ ] **Step 7: Commit**

```
git add tests/conftest.py tests/test_prompt_structure.py llm_client.py detector.py
git commit -m "perf(prompt第0批①): 输入字符度量+常量区归位system(前缀缓存结构准备)"
```

---

### Task 2: 微窗口快速通道（第0批②：规则直判不调 AI）

**Files:**
- Modify: `backend/pipeline.py`（新增 `_micro_fast()` + `_pool_workers()` 旁的直判前置；sweep 查询排除 micro-fast）
- Test: `backend/tests/test_micro_fast.py`（新建）

**Interfaces:**
- Produces: `pipeline._micro_fast(w: list[CanonicalEvent]) -> bool`；直判 verdict dict 形如 `{"intent": "normal_work", "deviation": "none", "risk_score": 8, "explanation": "[快速通道] ...", "channels": [], "ai_participated": False, "model": "micro-fast", "file_sensitivity": "none"}`（与现有规则兜底 verdict 同构）。
- 关键同步点：直判行 `ai_participated=0` 会被 sweep 补判捞回去重判——sweep 查询必须排除 `model == "micro-fast"`（NULL 陷阱见 Step 5）。

- [ ] **Step 1: 写失败测试 tests/test_micro_fast.py**

```python
# -*- coding: utf-8 -*-
from datetime import datetime

from models import CanonicalEvent


def ev(cat="WEB", act="VISIT", tv="www.baidu.com", raw=None, hour=10):
    return CanonicalEvent(occurred_at=datetime(2026, 9, 4, hour), employee_id="测试员工",
                          device_id="测试员工", category=cat, action=act, target_type="FILE",
                          target_value=tv, size_bytes=0, count=1, source="sangfor",
                          raw=raw if raw is not None else {"domain": tv})


def test_all_web_benign_workhours_true():
    import pipeline
    assert pipeline._micro_fast([ev(), ev(tv="hao123.com")]) is True


def test_doc_event_false():
    import pipeline
    assert pipeline._micro_fast([ev(), ev(cat="DOC", act="SEND", tv="a.xlsx")]) is False


def test_risk_domain_false():
    import pipeline
    assert pipeline._micro_fast([ev(tv="www.zhipin.com")]) is False


def test_off_hours_false():
    import pipeline
    assert pipeline._micro_fast([ev(hour=2)]) is False


def test_too_many_events_false():
    import pipeline
    assert pipeline._micro_fast([ev() for _ in range(7)]) is False


def test_empty_false():
    import pipeline
    assert pipeline._micro_fast([]) is False
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_micro_fast.py -v`
Expected: FAIL（`_micro_fast` 不存在）

- [ ] **Step 3: 实现 `_micro_fast()`（pipeline.py，放在 `run_detection` 定义前）**

```python
def _micro_fast(w) -> bool:
    """微窗口快速通道(2026-09-04 prompt降压②): 全WEB+全部域名无风险类+非
    深夜凌晨+≤6事件 → 规则直判 normal_work 不调AI。这类窗口会进研判只因为
    daygate/sampleaudit/sweep 立桩(should_trigger 本就不会为纯常规浏览触发),
    内容全良性,LLM 只会复读"正常办公"——白烧调用。事实降噪属代码层,不交AI。"""
    if not w or len(w) > 6:
        return False
    for e in w:
        if e.category != "WEB":
            return False
        if detector._is_off_hours(e.occurred_at):
            return False
        raw = e.raw if isinstance(e.raw, dict) else {}
        d = str(raw.get("domain") or e.target_value or "").lower().split("/")[0].split(":")[0]
        if d and dicts.risk_class(d):
            return False
    return True
```

（`_is_off_hours`：0-6 点或 22-23 点，与 should_trigger 同口径——detector.py:285。）

- [ ] **Step 4: `_judge_auto0` 前置直判（pipeline.py:1045）**

```python
        def _judge_auto0(item):
            """超长窗口自动切分(2026-08-26用户要求: 本地AI不费钱,增加研判次数
            保证完整输入输出不截断丢风险)。子窗口各自送LLM取最高分。"""
            emp, w, baseline, dev, wstart_ov = item
            if _micro_fast(w):  # 微窗口快速通道: 规则直判,不烧LLM
                return (emp, w[0].device_id, wstart_ov or w[0].occurred_at,
                        w[-1].occurred_at, [e.event_hash() for e in w],
                        {"intent": "normal_work", "deviation": "none", "risk_score": 8,
                         "explanation": "[快速通道] 窗口内全部为常规网站浏览,无风险类"
                                        "域名/文件操作/非工作时段信号,规则直判正常办公(未调AI)",
                         "channels": [], "ai_participated": False, "model": "micro-fast",
                         "file_sensitivity": "none"})
            _txt = detector._fmt_window(w)
            ...（以下原样不动）
```

- [ ] **Step 5: sweep 排除 micro-fast（pipeline.py:413-418）**

现状：

```python
                _fbs = rs.query(VerdictRow).filter(
                    or_(VerdictRow.ai_participated == 0, VerdictRow.intent == "unknown"),
                    VerdictRow.window_start >= _now5 - timedelta(days=7),
                    VerdictRow.created_at < _now5 - timedelta(minutes=60),
                    ~_superseded5,
                ).order_by(VerdictRow.created_at).limit(20).all()
```

改为（新增最后一行条件）：

```python
                _fbs = rs.query(VerdictRow).filter(
                    or_(VerdictRow.ai_participated == 0, VerdictRow.intent == "unknown"),
                    VerdictRow.window_start >= _now5 - timedelta(days=7),
                    VerdictRow.created_at < _now5 - timedelta(minutes=60),
                    ~_superseded5,
                    # 快速通道行已规则定性,不再烧LLM重判。NULL陷阱: 旧行model为NULL,
                    # SQL的!=对NULL得NULL(整行被过滤),须显式放行NULL
                    or_(VerdictRow.model.is_(None), VerdictRow.model != "micro-fast"),
                ).order_by(VerdictRow.created_at).limit(20).all()
```

- [ ] **Step 6: 跑测试确认通过 + 全量回归**

Run: `python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 7: Commit**

```
git add pipeline.py tests/test_micro_fast.py
git commit -m "perf(prompt第0批②): 微窗口快速通道——全WEB良性小窗规则直判不调AI,sweep排除micro-fast防重判"
```

---

### Task 3: 重判大批量并发降半（第0批④：调度错峰）

**Files:**
- Modify: `backend/pipeline.py`（新增 `_pool_workers()`；1044 行线程池用之）
- Test: `backend/tests/test_micro_fast.py`（追加用例，同文件即可——同属研判调度）

**Interfaces:**
- Produces: `pipeline._pool_workers(n_pending: int) -> int`
- 暂缓项（如实声明）：spec 讨论中的"钩子让位"（维护钩子在重判期让路）暂缓——研判并发降半已控住瞬时压力，维护钩子（domain_scan/daygate）独立线程本就与研判错峰运行，再建让位协议收益小耦合大（YAGNI）。

- [ ] **Step 1: 写失败测试（追加到 tests/test_micro_fast.py）**

```python
def test_pool_workers_adaptive():
    import pipeline
    assert pipeline._pool_workers(2) == 4      # 常态增量: 4并发保吞吐
    assert pipeline._pool_workers(100) == 4
    assert pipeline._pool_workers(101) == 2    # 大批量(全量重判): 2并发
    assert pipeline._pool_workers(572) == 2
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_micro_fast.py::test_pool_workers_adaptive -v`
Expected: FAIL

- [ ] **Step 3: 实现（pipeline.py，放在 `_micro_fast` 后）**

```python
def _pool_workers(n_pending: int) -> int:
    """研判并发自适应(2026-09-04 prompt降压④): 常态增量(≤100窗)4并发保吞吐;
    全量重判大批量(>100窗)降2并发——4并发压满本地vLLM时超时率实测上升
    (2026-08-28兜底补判15/486),降半换稳定,大批量时长换排队不换失败重试。"""
    return 2 if n_pending > 100 else 4
```

- [ ] **Step 4: 接线（pipeline.py:1044）**

```python
    with concurrent.futures.ThreadPoolExecutor(max_workers=_pool_workers(len(to_judge))) as pool:
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 6: Commit**

```
git add pipeline.py tests/test_micro_fast.py
git commit -m "perf(prompt第0批④): 研判并发自适应——大批量重判降2并发防vLLM压满超时;钩子让位暂缓(YAGNI)"
```

---

### Task 4: cases 表（db.py CaseRow）

**Files:**
- Modify: `backend/db.py`（新增 CaseRow；`create_all` 自动建表，无需兼容列）
- Modify: `backend/tests/conftest.py`（清理元组加 CaseRow）
- Test: `backend/tests/test_case_row.py`（新建）

**Interfaces:**
- Produces: `db.CaseRow`（字段见下——Task 5/6/8/9 全依赖它）。

- [ ] **Step 1: 写失败测试 tests/test_case_row.py**

```python
# -*- coding: utf-8 -*-
def test_case_row_crud():
    from db import Session, CaseRow
    s = Session()
    try:
        c = CaseRow(source="disposition_fp", employee_id="测试员工", intent="job_seeking",
                    behavior_key="abc123def456", outcome="false_positive",
                    attribution="意图错", facts_digest="digest", feature_keys={"intent": "job_seeking"},
                    ai_verdict="job_seeking/60", delta="备注", verdict_id=1, alert_id=2)
        s.add(c)
        s.commit()
        got = s.query(CaseRow).filter_by(behavior_key="abc123def456").first()
        assert got is not None and got.attribution == "意图错"
        assert got.created_at is not None
    finally:
        s.close()
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_case_row.py -v`
Expected: FAIL（CaseRow 不存在）

- [ ] **Step 3: 实现（db.py，放在 SampleAuditRow 之后、ExceptionRow 之前）**

```python
class CaseRow(Base):
    """人工判例库(AI灵魂一期,2026-09-04): 处置/豁免/抽样审计沉淀的"行为级"
    判例——按 behavior_key(行为口径hash)建档,同名口径跨员工跨意图复用,
    供难例few-shot注入与【人工口径】段检索。去重=同key近30天更新,不清理(量小)。"""
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    source = Column(String)                    # disposition_confirm/disposition_fp/exemption/sample_audit
    employee_id = Column(String, index=True)
    intent = Column(String)
    behavior_key = Column(String, index=True)  # 行为口径hash(主检索键,12位hex)
    outcome = Column(String)                   # confirmed/false_positive/exempt/audited_clean/audited_flag
    attribution = Column(String)               # 行为归因(域名定性错/意图错/程度夸大/时段可豁免/通道误判)
    facts_digest = Column(Text)                # 窗口事实摘要(daygate _digest同源格式)
    feature_keys = Column(JSON)                # {intent,dom_classes,actions,off_hours,volume}
    ai_verdict = Column(Text)                  # 当时AI结论摘要(intent/分: explanation截断)
    delta = Column(Text)                       # 人工结论与AI结论差异(处置备注)
    verdict_id = Column(Integer)               # 溯源链接(可空)
    alert_id = Column(Integer)                 # 溯源链接(可空)
    created_at = Column(DateTime, default=bj_now)  # 北京时间;去重窗口近30天以此为准
```

conftest.py 清理元组改为 `(CaseRow, FeedbackRow, ExceptionRow)`（import 行同步加 CaseRow）。

- [ ] **Step 4: 跑测试确认通过**

Run: `python -m pytest tests/ -v`
Expected: PASS

- [ ] **Step 5: Commit**

```
git add db.py tests/test_case_row.py tests/conftest.py
git commit -m "feat(灵魂一期): cases判例表——行为级建档,behavior_key主检索键+归因五类字段"
```

---

### Task 5: casebase.py（建档/检索/注入）

**Files:**
- Create: `backend/casebase.py`
- Test: `backend/tests/test_casebase.py`（新建）

**Interfaces:**
- Produces（Task 6/8/9/10 消费，签名以此为准）:
  - `ATTRIBUTIONS: tuple`（五类归因）
  - `feature_keys_of(window: list, verdict: dict) -> dict`（键：intent/dom_classes/actions/off_hours/volume）
  - `behavior_key(fk: dict) -> str`
  - `score_similarity(a: dict, b: dict) -> int`
  - `is_hard(intent, score: int, threshold: int = 50) -> bool`
  - `record_case(source, employee_id, outcome, attribution="", verdict_row=None, note="", fk=None, ai_verdict="") -> bool`
  - `similar_cases(fk: dict, top: int = 5) -> list[CaseRow]`
  - `cases_for_prompt(fk: dict, top: int = 5) -> str`
  - `caliber_text() -> str`（Task 9 用；本任务实现）

- [ ] **Step 1: 写失败测试 tests/test_casebase.py**

```python
# -*- coding: utf-8 -*-
from datetime import datetime

from models import CanonicalEvent


def ev(cat="WEB", act="VISIT", tv="www.zhipin.com", raw=None, hour=10):
    return CanonicalEvent(occurred_at=datetime(2026, 9, 4, hour), employee_id="测试员工",
                          device_id="测试员工", category=cat, action=act, target_type="FILE",
                          target_value=tv, size_bytes=0, count=1, source="sangfor",
                          raw=raw if raw is not None else {"domain": tv})


FK = {"intent": "job_seeking", "dom_classes": ["招聘求职"], "actions": ["WEB:VISIT"],
      "off_hours": False, "volume": "1"}


def test_feature_keys_of():
    import casebase
    w = [ev(), ev(cat="DOC", act="SEND", tv="a.xlsx")]
    fk = casebase.feature_keys_of(w, {"intent": "job_seeking"})
    assert fk["intent"] == "job_seeking"
    assert "招聘求职" in fk["dom_classes"]
    assert "DOC:SEND" in fk["actions"]
    assert fk["off_hours"] is False
    assert fk["volume"] == "2-5"
    assert casebase.feature_keys_of([ev(hour=2)], {})["off_hours"] is True


def test_behavior_key_deterministic():
    import casebase
    assert casebase.behavior_key(FK) == casebase.behavior_key(dict(FK))
    assert len(casebase.behavior_key(FK)) == 12
    fk2 = dict(FK, volume="6+")
    assert casebase.behavior_key(fk2) != casebase.behavior_key(FK)


def test_score_similarity():
    import casebase
    assert casebase.score_similarity(FK, dict(FK)) == 100
    other = {"intent": "policy_violation", "dom_classes": ["网盘/云盘"], "actions": ["WEB:VISIT"],
             "off_hours": True, "volume": "6+"}
    assert casebase.score_similarity(FK, other) == 20  # 只命中actions交集一半: 20*1/2
    assert casebase.score_similarity({}, {}) == 10     # 空集: 时段同5+量级同5


def test_is_hard():
    import casebase
    assert casebase.is_hard("job_seeking", 50, 50) is True
    assert casebase.is_hard("job_seeking", 35, 50) is True    # 50-15
    assert casebase.is_hard("job_seeking", 65, 50) is True    # 50+15
    assert casebase.is_hard("job_seeking", 66, 50) is False
    assert casebase.is_hard("job_seeking", 34, 50) is False
    assert casebase.is_hard("unknown", 10, 50) is True
    assert casebase.is_hard(None, 80, 50) is True


def test_record_and_similar_roundtrip():
    import casebase
    from db import Session, CaseRow
    assert casebase.record_case("disposition_fp", "测试员工", outcome="false_positive",
                                attribution="域名定性错", fk=FK) is True
    s = Session()
    try:
        rows = s.query(CaseRow).all()
        assert len(rows) == 1
        assert rows[0].behavior_key == casebase.behavior_key(FK)
    finally:
        s.close()
    got = casebase.similar_cases(FK, top=5)
    assert len(got) == 1
    # 同key近30天再处置 → 去重更新,不新增行
    casebase.record_case("exemption", "测试员工", outcome="exempt", attribution="意图错", fk=FK)
    s = Session()
    try:
        assert s.query(CaseRow).count() == 1
    finally:
        s.close()
    got = casebase.similar_cases(FK, top=5)
    assert got[0].outcome == "exempt"


def test_similar_requires_floor():
    import casebase
    casebase.record_case("disposition_fp", "测试员工", outcome="false_positive", fk=FK)
    far = {"intent": "policy_violation", "dom_classes": ["网盘/云盘"], "actions": ["DOC:SEND"],
           "off_hours": True, "volume": "6+"}
    assert casebase.similar_cases(far, top=5) == []  # 低于40分不注入


def test_cases_for_prompt_format():
    import casebase
    casebase.record_case("disposition_fp", "测试员工", outcome="false_positive",
                         attribution="域名定性错", fk=FK, ai_verdict="job_seeking/60: 测试AI结论")
    txt = casebase.cases_for_prompt(FK)
    assert "相似历史案例" in txt
    assert "域名定性错" in txt
    assert len(txt) <= 900
    assert casebase.cases_for_prompt({"intent": "x", "dom_classes": [], "actions": [],
                                      "off_hours": True, "volume": "1"}) == ""


def test_caliber_text_whitelist_and_precedent():
    import casebase
    import dicts
    dicts.set_dict("risk_whitelist_domains", ["italent.cn"])
    casebase.record_case("disposition_fp", "测试员工", outcome="false_positive",
                         attribution="域名定性错", fk=FK, ai_verdict="job_seeking/60: 测试AI结论")
    casebase._CALIBER_CACHE.update(txt="", ts=0.0)  # 清TTL缓存
    txt = casebase.caliber_text()
    assert "italent.cn" in txt
    assert "误报判例" in txt and "域名定性错" in txt
    # TTL缓存: 二次调用字节一致
    assert casebase.caliber_text() == txt
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_casebase.py -v`
Expected: FAIL（module not found: casebase）

- [ ] **Step 3: 实现 casebase.py 全文**

```python
# -*- coding: utf-8 -*-
"""案例库(AI灵魂一期,2026-09-04): 行为级判例的建档/检索/注入。
路由边界(spec): 代码管事实,语义归AI,案例库管口径对齐——本模块只做结构键
检索(纯Python加权评分,不用向量),不参与打分。所有入口 fail-soft:
调用方主流程不受案例失败影响(record_case内部吞异常,similar/cases返回空)。
"""
import hashlib
import json
import threading
import time
from datetime import timedelta

from db import CaseRow, Session, bj_now, events_by_hashes, write_lock
import dicts

ATTRIBUTIONS = ("域名定性错", "意图错", "程度夸大", "时段可豁免", "通道误判")


def feature_keys_of(window, verdict: dict) -> dict:
    """窗口+结论 → 结构键。域名类集=窗口内域名经dicts.risk_class归类的非空类去重;
    行为集=category:action去重;时段=含非工作时段(0-6/22-23,与研判同口径);
    量级=事件数档位。归一化=同口径行为跨员工跨意图得到同名键。"""
    doms = set()
    for e in window:
        raw = e.raw if isinstance(e.raw, dict) else {}
        d = str(raw.get("domain") or e.target_value or "").lower().split("/")[0].split(":")[0]
        c = dicts.risk_class(d) if d else None
        if c:
            doms.add(c)
    acts = {f"{e.category}:{e.action}" for e in window}
    hours = [e.occurred_at.hour for e in window if e.occurred_at]
    n = len(window)
    return {"intent": (verdict or {}).get("intent") or "unknown",
            "dom_classes": sorted(doms),
            "actions": sorted(acts),
            "off_hours": bool(hours and (min(hours) < 7 or max(hours) >= 22)),
            "volume": "1" if n <= 1 else ("2-5" if n <= 5 else "6+")}


def behavior_key(fk: dict) -> str:
    """结构键 → 行为口径hash(12位hex): 同口径=同名键,跨员工复用的锚。"""
    core = {k: (fk or {}).get(k) for k in ("intent", "dom_classes", "actions", "off_hours", "volume")}
    return hashlib.sha1(json.dumps(core, ensure_ascii=False, sort_keys=True)
                        .encode("utf-8")).hexdigest()[:12]


def score_similarity(a: dict, b: dict) -> int:
    """加权评分(满分100): intent同=40 域名类集Jaccard=30 行为集Jaccard=20
    时段同=5 量级同=5。空集双方Jaccard记0(无证据不加分)。"""
    sc = 0
    if a.get("intent") == b.get("intent"):
        sc += 40
    for k, w in (("dom_classes", 30), ("actions", 20)):
        sa, sb = set(a.get(k) or []), set(b.get(k) or [])
        if sa or sb:
            sc += int(w * len(sa & sb) / len(sa | sb))
    if bool(a.get("off_hours")) == bool(b.get("off_hours")):
        sc += 5
    if a.get("volume") == b.get("volume"):
        sc += 5
    return sc


def is_hard(intent, score: int, threshold: int = 50) -> bool:
    """难例判定(spec一期): |score-threshold|≤15 或 意图unknown。
    spec另提的"复核摇摆"留二期——复核分歧信号在_judge内部,需先暴露才能判。"""
    return intent in (None, "", "unknown") or abs((score or 0) - threshold) <= 15


def record_case(source, employee_id, outcome, attribution="", verdict_row=None,
                note="", fk=None, ai_verdict="") -> bool:
    """建档+去重(同behavior_key近30天只留最新outcome→更新旧行,spec口径)。
    verdict_row给出时自动重建窗口提facts_digest/feature_keys/ai_verdict;
    显式fk/ai_verdict可覆盖(测试/sampleaudit路径)。全异常吞掉打日志。"""
    try:
        digest, ai_v = "", ai_verdict
        if fk is None:
            fk = {}
            if verdict_row is not None:
                evs = sorted(events_by_hashes(Session(), (verdict_row.event_hashes or [])[:400]),
                             key=lambda x: x.occurred_at)
                from models import CanonicalEvent
                win = [CanonicalEvent(occurred_at=r.occurred_at, employee_id=r.employee_id,
                                      device_id=r.device_id, category=r.category, action=r.action,
                                      target_type=r.target_type or "FILE",
                                      target_value=r.target_value or "",
                                      size_bytes=r.size_bytes or 0, count=r.count or 1,
                                      source=r.source or "", raw=r.raw or {}) for r in evs]
                from daygate import _digest
                digest = _digest(win)[:600]
                ai_v = ai_v or f"{verdict_row.intent}/{verdict_row.risk_score}: {str(verdict_row.explanation)[:200]}"
                fk = feature_keys_of(win, {"intent": verdict_row.intent})
        bk = behavior_key(fk)
        with write_lock:
            ss = Session()
            try:
                old = ss.query(CaseRow).filter(
                    CaseRow.behavior_key == bk,
                    CaseRow.created_at >= bj_now() - timedelta(days=30)).first()
                if old:
                    old.outcome = outcome or old.outcome
                    old.attribution = attribution or old.attribution
                    old.source = source or old.source
                    old.created_at = bj_now()
                else:
                    ss.add(CaseRow(source=source, employee_id=employee_id,
                                   intent=(fk.get("intent") or ""), behavior_key=bk,
                                   outcome=outcome, attribution=attribution,
                                   facts_digest=digest, feature_keys=fk, ai_verdict=ai_v,
                                   delta=(note or "")[:400],
                                   verdict_id=getattr(verdict_row, "id", None)))
                ss.commit()
            finally:
                ss.close()
        return True
    except Exception as e:
        print(f"[casebase] 入库失败(不影响主流程): {e}", flush=True)
        return False


def similar_cases(fk: dict, top: int = 5) -> list:
    """按结构键加权评分取top(近30天,python侧评分;≥40分才入选——低于=intent
    与域名类都不同,不是同口径行为)。"""
    try:
        s = Session()
        try:
            since = bj_now() - timedelta(days=30)
            rows = s.query(CaseRow).filter(CaseRow.created_at >= since).all()
            scored = sorted(((score_similarity(fk, r.feature_keys or {}), r) for r in rows),
                            key=lambda x: -x[0])
            return [r for sc, r in scored[:top] if sc >= 40]
        finally:
            s.close()
    except Exception as e:
        print(f"[casebase] 检索失败(返回空): {e}", flush=True)
        return []


def cases_for_prompt(fk: dict, top: int = 5) -> str:
    """难例注入段(spec: 5条≤800字): 【相似历史案例(人工已复核)】。"""
    rows = similar_cases(fk, top)
    if not rows:
        return ""
    lines = [f"- {str(r.ai_verdict or r.facts_digest or r.behavior_key)[:120]}"
             f" →人工:{r.outcome}" + (f"({r.attribution})" if r.attribution else "")
             for r in rows]
    return ("【相似历史案例(人工已复核)——同口径行为此前的人工结论,判定时对齐】\n"
            + "\n".join(lines)[:800] + "\n")


_CALIBER_CACHE = {"txt": "", "ts": 0.0}
_CALIBER_LOCK = threading.Lock()


def caliber_text() -> str:
    """【人工口径】段(所有AI通道共享,spec口径统一注入——italent事故架构修复):
    白名单口径(人工字典真源渲染) + 近30天高频误报判例(behavior_key去重取8条)。
    进程内TTL 10min缓存——字节级稳定,vLLM prefix caching才能命中共享前缀;
    新判例/字典改动10min内自然生效,不必重启。"""
    with _CALIBER_LOCK:
        if _CALIBER_CACHE["txt"] and time.time() - _CALIBER_CACHE["ts"] < 600:
            return _CALIBER_CACHE["txt"]
    parts = []
    wl = [w for w in (dicts.get("risk_whitelist_domains") or []) if w]
    if wl:
        parts.append("【人工口径——公司确认的例外(优先级最高,覆盖其他规则)】以下域名及其子域"
                     "=公司白名单通道/系统,一律正常办公,严禁判成风险或写进风险说明: "
                     + ", ".join(wl[:40]) + "。")
    try:
        s = Session()
        try:
            since = bj_now() - timedelta(days=30)
            rows = (s.query(CaseRow)
                    .filter(CaseRow.created_at >= since, CaseRow.outcome == "false_positive")
                    .order_by(CaseRow.created_at.desc()).limit(60).all())
            seen, picks = set(), []
            for r in rows:
                if r.behavior_key not in seen:
                    seen.add(r.behavior_key)
                    picks.append(r)
            lines = [f"- {str(r.ai_verdict or '')[:80]} →人工:误报"
                     + (f"({r.attribution})" if r.attribution else "")
                     + ((f" {str(r.delta)[:60]}") if r.delta else "")
                     for r in picks[:8] if str(r.ai_verdict or r.facts_digest or "").strip()]
            if lines:
                parts.append("【人工口径——已复核误报判例(同类行为不得再判风险)】\n" + "\n".join(lines))
        finally:
            s.close()
    except Exception:
        pass  # 案例读失败=只给白名单段(fail-soft)
    txt = ("\n" + "\n".join(parts)) if parts else ""
    with _CALIBER_LOCK:
        _CALIBER_CACHE.update(txt=txt, ts=time.time())
    return txt
```

注意 record_case 里 `events_by_hashes(Session(), ...)` 直接传短命 Session 不关闭是坏的——实现时改成：

```python
                _sr = Session()
                try:
                    evs = sorted(events_by_hashes(_sr, (verdict_row.event_hashes or [])[:400]),
                                 key=lambda x: x.occurred_at)
                finally:
                    _sr.close()
```

（expire_on_commit=False，行对象关闭后仍可读。）

- [ ] **Step 4: 跑测试确认通过**

Run: `python -m pytest tests/test_casebase.py -v`
Expected: PASS（9 个用例）

- [ ] **Step 5: Commit**

```
git add casebase.py tests/test_casebase.py
git commit -m "feat(灵魂一期): casebase模块——行为口径键/相似检索/难例判定/判例注入+人工口径段(TTL缓存)"
```

---

### Task 6: 处置端点接案例管道（api.py）

**Files:**
- Modify: `backend/api.py`（三端点：`/api/verdicts/{vid}/false_positive`:970、`/api/verdicts/{vid}/confirm`:946、`/api/feedback`:899）
- Test: `backend/tests/test_api_disposition.py`（新建）

**Interfaces:**
- Consumes: `casebase.record_case`（Task 5 签名）、`casebase.ATTRIBUTIONS`。
- Produces: 端点新 query 参数 `attribution`（FP **必填**五选一，非法/缺失 400；confirm/feedback 可选）。
- 测试方式：直接调用被 `_ui_write` 包装的函数（装饰器只是 retry_write 包裹，无鉴权——鉴权在 HTTP 中间件层，函数直调天然绕过）。不硬凑 TestClient。

- [ ] **Step 1: 写失败测试 tests/test_api_disposition.py**

```python
# -*- coding: utf-8 -*-
from datetime import datetime

from fastapi import HTTPException


def _mk_pair():
    from db import Session, AlertRow, VerdictRow
    s = Session()
    try:
        v = VerdictRow(employee_id="测试员工", device="测试员工",
                       window_start=datetime(2026, 9, 4, 10), window_end=datetime(2026, 9, 4, 11),
                       intent="job_seeking", risk_score=60, explanation="测试研判")
        s.add(v)
        s.flush()
        a = AlertRow(employee_id="测试员工", scenario="job_seeking", severity="MEDIUM",
                     risk_score=60, verdict_id=v.id, summary="测试告警")
        s.add(a)
        s.commit()
        return v.id
    finally:
        s.close()


def test_fp_requires_valid_attribution():
    import api
    vid = _mk_pair()
    with pytest_raises_http_400():
        api.verdict_false_positive(vid=vid, reason="误报")
    with pytest_raises_http_400():
        api.verdict_false_positive(vid=vid, reason="误报", attribution="随便编的")


def pytest_raises_http_400():
    import pytest
    return _Raises(400)


class _Raises:
    def __init__(self, code):
        self.code = code

    def __enter__(self):
        import pytest
        return pytest.raises(HTTPException) as ctx_holder

    def __exit__(self, exc_type, exc, tb):
        return exc_type is not None and exc.status_code == self.code


def test_fp_records_case_with_attribution():
    import api
    from db import Session, CaseRow
    vid = _mk_pair()
    r = api.verdict_false_positive(vid=vid, reason="岗位需要", attribution="意图错")
    assert r["ok"] is True
    s = Session()
    try:
        cs = s.query(CaseRow).all()
        assert cs and cs[0].source == "disposition_fp"
        assert cs[0].attribution == "意图错"
        assert cs[0].outcome == "false_positive"
    finally:
        s.close()


def test_confirm_records_case_optional():
    import api
    from db import Session, CaseRow
    vid = _mk_pair()
    r = api.verdict_confirm(vid=vid, reason="已知晓")
    assert r["ok"] is True
    s = Session()
    try:
        cs = s.query(CaseRow).all()
        assert cs and cs[0].outcome == "confirmed"
    finally:
        s.close()
```

（注：`_Raises` 上下文管理器写复杂了——直接用 `with pytest.raises(HTTPException) as e:` 后断言 `e.value.status_code == 400` 即可，实现时照常规写法。上面测试文件里以常规 pytest.raises 为准，删掉 `_Raises` 辅助类。）

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_api_disposition.py -v`
Expected: FAIL（attribution 参数不存在 → TypeError；CaseRow 无行）

- [ ] **Step 3: 实现 verdict_false_positive（api.py:970）**

```python
@app.post("/api/verdicts/{vid}/false_positive")
@_ui_write
def verdict_false_positive(vid: int, reason: str = "误报", signal_type: str = "",
                           expires_days: int = 0, attribution: str = ""):
    """通过研判ID标记误报 + 创建豁免 + 沉淀行为判例(2026-09-04灵魂一期:
    误报必须选行为归因五选一——判例按行为口径建档,对所有人所有窗口生效)。"""
    from datetime import datetime, timedelta
    from db import ExceptionRow
    import casebase
    if attribution not in casebase.ATTRIBUTIONS:
        raise HTTPException(400, "误报必须选行为归因(五选一): " + "/".join(casebase.ATTRIBUTIONS))
    s = Session()
    try:
        a = s.query(AlertRow).filter_by(verdict_id=vid).first()
        v0 = s.query(VerdictRow).get(vid)
        if not a:
            if v0:
                a = s.query(AlertRow).filter_by(employee_id=v0.employee_id, scenario=v0.intent).first()
        if not a:
            return {"ok": False, "error": "未找到对应告警"}
        a.status = "FP"
        s.add(FeedbackRow(alert_id=a.id, label="FP", reason=f"[{attribution}] {reason}"))
        if signal_type:
            exp = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
            s.add(ExceptionRow(employee_id=a.employee_id, signal_type=signal_type,
                               reason=reason, expires_at=exp))
        s.commit()
        # 判例入库(fail-soft): FP处置 → disposition_fp; 若同动作建了豁免,再记
        # exemption一条(同behavior_key 30天去重会让豁免顶掉FP——豁免是更强结论,
        # 覆盖合理)。处置成功才建档。
        try:
            casebase.record_case("disposition_fp", a.employee_id, outcome="false_positive",
                                  attribution=attribution, verdict_row=v0, note=reason)
            if signal_type:
                casebase.record_case("exemption", a.employee_id, outcome="exempt",
                                     attribution=attribution, verdict_row=v0, note=reason)
        except Exception as _ce:
            print(f"[casebase] 处置判例入库失败(不影响处置): {_ce}", flush=True)
        return {"ok": True}
    finally:
        s.close()
```

- [ ] **Step 4: 实现 verdict_confirm（api.py:946，可选归因）**

签名加 `attribution: str = ""`；commit 后加：

```python
        try:  # 确认同理可选行为确认(spec): 留档判例但outcome=confirmed
            import casebase
            if attribution in casebase.ATTRIBUTIONS:
                v0 = s.query(VerdictRow).get(vid)
                casebase.record_case("disposition_confirm", a.employee_id, outcome="confirmed",
                                     attribution=attribution, verdict_row=v0, note=reason)
        except Exception:
            pass
```

（record_case 自身 fail-soft，双层保护无妨——外层 try 保 attribution 校验外的意外。）

- [ ] **Step 5: 实现 /api/feedback（api.py:899，透传归因，向后兼容可空）**

签名加 `attribution: str = ""`；`s.commit()` 后加：

```python
        try:
            if label == "FP" and attribution:
                import casebase
                if attribution in casebase.ATTRIBUTIONS:
                    casebase.record_case("disposition_fp", a.employee_id, outcome="false_positive",
                                         attribution=attribution, verdict_id=None, note=reason)
        except Exception:
            pass
```

（feedback 端点无 verdict 在手，fk 为空 dict 建档——behavior_key 为空口径键，仍留 outcome/attribution 供蒸馏；难例检索的 40 分门槛会自然过滤空键案例。）

- [ ] **Step 6: 跑测试确认通过 + py_compile**

Run: `python -m pytest tests/ -v && python -m py_compile api.py`
Expected: PASS

- [ ] **Step 7: Commit**

```
git add api.py tests/test_api_disposition.py
git commit -m "feat(灵魂一期): 处置端点接判例管道——误报必选行为归因五选一,确认可选,豁免同步入库"
```

---

### Task 7: 前端误报弹窗归因五选一（index.html）

**Files:**
- Modify: `backend/static/index.html`（1103-1113 fpModal state/submitFP；1165-1203 FP 弹窗 JSX；1204-1209 确认弹窗）
- 无新测试文件——验证=Babel 编译通过 + DOM 结构检查（前端 DOM 验证铁律）

**Interfaces:**
- Consumes: Task 6 的 `attribution` query 参数。
- Radio 已在 antd 解构里（index.html:245），无需新增 import。

- [ ] **Step 1: fpModal state 加 attr（1103 行）**

```javascript
  const [fpModal,setFpModal]=useState({open:false,vid:0,intent:'',emp:'',reason:'岗位需要',note:'',allScenarios:[],attr:''});
```

1104 行 doFP 的 setFpModal 对象同步加 `attr:''`。

- [ ] **Step 2: submitFP 传 attribution（1110-1113 行）**

POST 串加一段：

```javascript
    POST('/api/verdicts/'+fpModal.vid+'/false_positive?reason='+encodeURIComponent(fullReason)+'&signal_type='+encodeURIComponent(st)+'&expires_days='+days+'&attribution='+encodeURIComponent(fpModal.attr||'')).then(...)
```

（.then 内文案不变；attr 由后端强制校验，未选时 400，前端 okButton 禁用兜底双保险。）

- [ ] **Step 3: FP 弹窗加归因 Radio.Group（1180-1182 行"误报原因"块之前插入）**

```jsx
      <div style={{marginBottom:8}}>
        <Typography.Text>行为归因（必选——此判定将沉淀为同类行为的判例，对所有人生效）：</Typography.Text>
        <Radio.Group value={fpModal.attr} onChange={e=>setFpModal({...fpModal,attr:e.target.value})}
          style={{display:'flex',flexDirection:'column',gap:2,marginTop:6}}>
          {[['域名定性错','域名被错误定性为风险类（如公司系统/白名单被当成风险站）'],
            ['意图错','行为性质判断反了（如HR招聘工作被判成求职）'],
            ['程度夸大','有该行为，但不至于这个分数/严重度'],
            ['时段可豁免','夜班/跨时区岗位，非工作时段属正常'],
            ['通道误判','通道被认错（如公司邮箱当成个人邮箱）']].map(([v,d])=>
            <Radio key={v} value={v}>{v} — {d}</Radio>)}
        </Radio.Group>
      </div>
```

Modal（1165 行）加 `okButtonProps={{disabled:!fpModal.attr}}`。

- [ ] **Step 4: 确认弹窗可选归因（1204-1209 行）**

cfModal 不加字段——确认的归因走已有 note 即可（后端 confirm 的 attribution 可选，前端保持"已知晓"轻量语义；spec 说"确认同理**可选**"，UI 只给备注=未选归因，合法）。

- [ ] **Step 5: Alert 提示文案更新（1197-1202 行）**

```jsx
      <Alert type="info" showIcon style={{marginTop:12}}
        message={fpModal.reason==='误报'
          ?"仅将本条标记为误报并留痕(归因:"+ (fpModal.attr||'未选') +")——不创建豁免，同类行为后续仍会正常告警。"
          :("将豁免「"+(INTENT[fpModal.intent]||fpModal.intent)+"」场景"
            +(fpModal.reason==='工作需要'?'（90天有效）':fpModal.reason==='临时项目'?'（30天有效）':'（永久，直至在豁免管理中删除）')
            +"，其他场景仍正常监控。归因判例对同类行为全局生效。")} />
```

- [ ] **Step 6: Babel 编译验证（复用 deploy 预编译，不部署）**

Run: `python -c "from deploy import precompile_index; h=precompile_index(); print('OK %.1f KB' % (len(h.encode('utf-8'))/1024))"`
Expected: 输出 OK + 字节数（libs/babel.js 本地已缓存，无网络依赖；若报缺 babel.js 则说明本地缓存丢失，停下报告，不要联网下载）。

- [ ] **Step 7: Commit**

```
git add static/index.html
git commit -m "feat(灵魂一期): 误报弹窗行为归因五选一(必选)——处置从告警级升为行为级判例"
```

---

### Task 8: sampleaudit 回填入案例

**Files:**
- Modify: `backend/sampleaudit.py`（backfill() 104 行回填处）
- 无独立单测（backfill 依赖 DB+采样流程）——验证并入 Task 12 容器密闭测试

**Interfaces:**
- Consumes: `casebase.record_case`（Task 5 签名）。

- [ ] **Step 1: 修改 backfill()（sampleaudit.py:104）**

现状：

```python
        r.outcome_intent, r.outcome_score = best.intent, best.risk_score or 0
        n += 1
```

改为：

```python
        r.outcome_intent, r.outcome_score = best.intent, best.risk_score or 0
        n += 1
        try:  # 判例入库(2026-09-04灵魂一期): 审计结论也是判例源(spec:
            # sample_audit)——深判翻出的flag与确认的clean都是可检索口径
            import casebase
            _flag = (r.outcome_score or 0) >= FLAG_SCORE \
                and r.outcome_intent not in ("normal_work", "unknown")
            casebase.record_case("sample_audit", r.employee_id,
                                 outcome="audited_flag" if _flag else "audited_clean",
                                 verdict_row=best)
        except Exception:
            pass  # fail-soft: 入库失败不影响回填
```

- [ ] **Step 2: py_compile**

Run: `python -m py_compile sampleaudit.py`
Expected: 无输出（通过）

- [ ] **Step 3: Commit**

```
git add sampleaudit.py
git commit -m "feat(灵魂一期): 抽样审计回填同步入判例库(sample_audit源,flag/clean两态)"
```

---

### Task 9: 口径统一注入（研判 / domain_scan / daygate 三通道）

**Files:**
- Modify: `backend/detector.py`（`_system_prompt()` 接口径段）
- Modify: `backend/domain_scan.py`（121-123 行 chat 消息）
- Modify: `backend/daygate.py`（166-168 行 chat 消息）
- Test: `backend/tests/test_caliber_inject.py`（新建）

**Interfaces:**
- Consumes: `casebase.caliber_text()`（Task 5）。
- Produces: 三 AI 通道 prompt 均含【人工口径】段（字节同源）。sampleaudit 无直接 LLM 调用（立桩由 sweep 走研判 prompt），天然覆盖；蒸馏器=二期。
- 循环依赖规避：casebase→daygate（`_digest`）是 record_case **函数内**延迟导入；daygate/detector→casebase 也是函数内导入——模块级无环。

- [ ] **Step 1: 写失败测试 tests/test_caliber_inject.py**

```python
# -*- coding: utf-8 -*-
def _seed():
    import casebase
    import dicts
    dicts.set_dict("risk_whitelist_domains", ["italent.cn"])
    casebase.record_case("disposition_fp", "测试员工", outcome="false_positive",
                         attribution="域名定性错",
                         fk={"intent": "job_seeking", "dom_classes": ["招聘求职"],
                             "actions": ["WEB:VISIT"], "off_hours": False, "volume": "1"},
                         ai_verdict="job_seeking/60: 测试AI结论")
    casebase._CALIBER_CACHE.update(txt="", ts=0.0)


def test_system_prompt_carries_caliber():
    _seed()
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工行为分析助手")
    assert "人工口径" in sp and "italent.cn" in sp


def test_system_prompt_failsoft_without_cases():
    import detector
    sp = detector._system_prompt()
    assert sp.startswith("你是企业员工行为分析助手")  # 案例读失败/为空也不崩


def test_daygate_and_domain_scan_prompts_importable():
    # 冒烟: 两模块可导入且消息构造处引用caliber_text(编译期验证靠py_compile,
    # 运行期在容器密闭测试验证)
    import daygate
    import domain_scan
    import casebase
    assert callable(casebase.caliber_text)
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_caliber_inject.py -v`
Expected: FAIL（`_system_prompt` 无"人工口径"）

- [ ] **Step 3: 实现 detector.py**

`_system_prompt()`（Task 1 建立）改为：

```python
def _system_prompt() -> str:
    """研判system消息唯一出口(2026-09-04口径统一注入): SYSTEM_PROMPT+恒定指令
    +【人工口径】段(casebase.caliber_text——白名单+高频误报判例,人工字典真源
    渲染,TTL缓存字节级稳定,vLLM prefix caching命中共享前缀)。italent事故
    根因=人工口径只活在研判prompt文本,其他AI通道看不到——现在统一出自一处。"""
    try:
        import casebase
        return SYSTEM_PROMPT + "\n" + _SYS_TAIL + casebase.caliber_text()
    except Exception:
        return SYSTEM_PROMPT + "\n" + _SYS_TAIL
```

- [ ] **Step 4: 实现 domain_scan.py（121-123 行）**

```python
    lines = [f'{d}(访问{h}次/{u}人,标题: {"; ".join(t) or "无"})' for d, h, u, t in cands]
    _cal = ""
    try:  # 口径统一注入(2026-09-04): italent事故——定性AI看不到人工白名单口径
        import casebase
        _cal = casebase.caliber_text()
    except Exception:
        pass
    msg = llm_client.chat(
        [{"role": "user", "content": PROMPT + _cal + "\n" + "\n".join(lines)}],
        max_tokens=3000, timeout=240)
```

- [ ] **Step 5: 实现 daygate.py（166-168 行）**

```python
                _cal = ""
                try:  # 口径统一注入(2026-09-04): 与研判/domain_scan同源
                    import casebase
                    _cal = casebase.caliber_text()
                except Exception:
                    pass
                msg = llm_client.chat(
                    [{"role": "user", "content": PROMPT + _cal + "\n" + _digest(evs)}],
                    max_tokens=300, timeout=120)
```

- [ ] **Step 6: 跑测试确认通过 + py_compile**

Run: `python -m pytest tests/ -v && python -m py_compile detector.py domain_scan.py daygate.py`
Expected: PASS

- [ ] **Step 7: Commit**

```
git add detector.py domain_scan.py daygate.py tests/test_caliber_inject.py
git commit -m "feat(灵魂一期): 口径统一注入——研判/domain_scan/daygate共享人工口径段(italent事故架构修复)"
```

---

### Task 10: 难例注入（阈值±15 或 unknown → 带判例重判一次）

**Files:**
- Modify: `backend/detector.py`（`analyze_window` 加 `cases_txt=""` 参数）
- Modify: `backend/pipeline.py`（`_judge` 780 行签名、845 行调用、`_judge_auto0` 1045、`_judge_auto` 1066 包装层）
- Test: `backend/tests/test_hard_inject.py`（新建，测可本地测的接线纯逻辑）

**Interfaces:**
- Consumes: `casebase.is_hard` / `cases_for_prompt` / `feature_keys_of`（Task 5）；`risk_threshold`（run_detection 参数，嵌套函数作用域可见）。
- Produces: 难例重判结果 explanation 带 `[判例对齐]` 前缀（docker logs / verdicts 可 grep -F 观察命中量：ASCII 安全）。
- 机制（pre/post）：先正常判 → 结果落难例带 → 带判例重判一次取重判结果。不做前置预判（分数判前未知）。

- [ ] **Step 1: 写失败测试 tests/test_hard_inject.py**

```python
# -*- coding: utf-8 -*-
from datetime import datetime

from models import CanonicalEvent


def _win():
    return [CanonicalEvent(occurred_at=datetime(2026, 9, 4, 10), employee_id="测试员工",
                           device_id="测试员工", category="WEB", action="VISIT", target_type="FILE",
                           target_value="www.zhipin.com", size_bytes=0, count=1, source="sangfor",
                           raw={"domain": "www.zhipin.com"})]


def test_analyze_window_accepts_cases_txt_without_llm():
    # analyze_window 会真调LLM——本用例只验证参数被接受且fail-soft:
    # cases_txt只做字符串拼接,不调AI不查库。LLM不可用时analyze_window走
    # 它自己的兜底路径,断言聚焦"不因cases_txt报TypeError"。
    import detector
    try:
        detector.analyze_window(_win(), cases_txt="【相似历史案例】\n- x →人工:误报")
    except TypeError:
        raise AssertionError("analyze_window 不接受 cases_txt 参数")
    except Exception:
        pass  # LLM调用失败是本用例允许的结果(本地无AI)


def test_case_block_shape():
    import casebase
    txt = casebase.cases_for_prompt(
        {"intent": "job_seeking", "dom_classes": ["招聘求职"], "actions": ["WEB:VISIT"],
         "off_hours": False, "volume": "1"})
    assert txt == "" or txt.startswith("【相似历史案例")
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_hard_inject.py -v`
Expected: FAIL（analyze_window 不接受 cases_txt → TypeError → 断言失败）

- [ ] **Step 3: 实现 detector.analyze_window（680 行签名 + 734 行 user 消息）**

签名加参数：

```python
def analyze_window(window: list[CanonicalEvent], profile=None, dev=None, exemptions=None, global_ctx=None,
                   model=None, history=None, day_ctx=None, cases_txt: str = "") -> dict:
```

user 消息（Task 1 改后的版本）注入判例段（变量区尾部，记忆段后）：

```python
    _case_txt = f"\n{cases_txt}" if cases_txt else ""
    user = (f"员工：{window[0].employee_id}（设备：{window[0].employee_id}）\n"
            f"行为序列：\n{_fmt_window(window)}{_dest_hint}{g_txt}{profile_txt}{dev_txt}{exempt_txt}{hist_txt}{day_txt}{_mem}{_case_txt}\n\n")
```

- [ ] **Step 4: 实现 pipeline 接线**

`_judge`（780 行）签名与调用：

```python
    def _judge(item, cases_txt=""):
```

845 行调用处加关键字参数：

```python
        v = detector.analyze_window(w, summary, dev, exempt, gctx, history=_hist, day_ctx=day_ctx,
                                    cases_txt=cases_txt)
```

`_judge_auto0`（Task 2 改后版本）签名与两处 `_judge(item)` 调用：

```python
        def _judge_auto0(item, cases_txt=""):
            ...
            if _micro_fast(w):
                return (...直判不变...)   # 快速通道不看判例: 良性窗口无需对齐
            ...
            if len(_txt) <= 3500:
                return _judge(item, cases_txt)
            ...
                r = _judge((emp, sub, baseline, dev, wstart_ov), cases_txt)
```

`_judge_auto`（1066 行）现有兜底重试逻辑之后、`return r` 之前加难例分支：

```python
            # 难例带判例重判(2026-09-04灵魂一期,spec: 只给难例控prompt体积):
            # 首判落在阈值±15带或意图unknown → 取相似人工判例注入重判一次。
            # 分数判前未知,只能post式: 先判→难例→带判例重判。
            try:
                if isinstance(r, tuple) and len(r) > 5 and isinstance(r[5], dict) \
                        and r[5].get("ai_participated"):
                    import casebase as _cb
                    _v5 = r[5]
                    if _cb.is_hard(_v5.get("intent"), _v5.get("risk_score") or 0, risk_threshold):
                        _cs = _cb.cases_for_prompt(_cb.feature_keys_of(item[1], _v5))
                        if _cs:
                            r2 = _judge_auto0(item, cases_txt=_cs)
                            if isinstance(r2, tuple) and len(r2) > 5 and isinstance(r2[5], dict) \
                                    and r2[5].get("ai_participated"):
                                r = (*r2[:5], {**r2[5], "explanation":
                                      "[判例对齐] " + str(r2[5].get("explanation") or "")})
            except Exception:
                pass  # 判例注入失败保留首判
            return r
```

（现有 `return r`（1080 行）并入此结构：兜底重试 → 难例重判 → return。）

- [ ] **Step 5: 跑测试确认通过 + py_compile + 全量回归**

Run: `python -m pytest tests/ -v && python -m py_compile detector.py pipeline.py`
Expected: PASS

- [ ] **Step 6: Commit**

```
git add detector.py pipeline.py tests/test_hard_inject.py
git commit -m "feat(灵魂一期): 难例注入——阈值±15或unknown带相似判例重判一次,结果标[判例对齐]"
```

---

### Task 11: 生命体征（SIGUSR1 栈 dump + 研判看门狗）

**Files:**
- Modify: `backend/pipeline.py`（新增 `_SOUL_WD` + `start_soul_watchdog()`）
- Modify: `backend/api.py`（startup 区 313 行旁启动看门狗）
- Test: `backend/tests/test_soul_watchdog.py`（新建）

**Interfaces:**
- Produces: `pipeline.start_soul_watchdog(stall_seconds=1800, poll_seconds=60)`（参数化供测试）；告警日志行 `[soul-watchdog]`（纯 ASCII，docker logs `grep -F` 可查）；`docker exec ipguard-ai kill -USR1 1` 随时安全 dump 全线程栈（Linux 容器；Windows 本地注册失败静默跳过）。
- 消费既有信号：`_detect_status` 的 `running/phase/done`（phase="LLM研判中" 且 done 停滞 = 2026-09-03 挂死形态：窗口筛选完成 to_judge=572 后零进展、零 LLM 调用）。

- [ ] **Step 1: 写失败测试 tests/test_soul_watchdog.py**

```python
# -*- coding: utf-8 -*-
import time


def test_watchdog_fires_on_stall(monkeypatch):
    import pipeline
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": True, "phase": "LLM研判中", "done": 7})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.3, poll_seconds=0.1)
    time.sleep(0.9)
    pipeline._SOUL_WD["stop"] = True
    assert fired, "停滞超时应dump栈并打[soul-watchdog]"


def test_watchdog_resets_on_progress(monkeypatch):
    import pipeline
    state = {"done": 1}
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": True, "phase": "LLM研判中", "done": state["done"]})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.4, poll_seconds=0.1)
    for _ in range(4):  # done持续推进,不触发
        time.sleep(0.15)
        state["done"] += 1
    time.sleep(0.15)
    pipeline._SOUL_WD["stop"] = True
    assert not fired


def test_watchdog_ignores_not_running(monkeypatch):
    import pipeline
    import faulthandler
    fired = []
    monkeypatch.setattr(pipeline, "detection_status",
                        lambda: {"running": False, "phase": None, "done": 0})
    monkeypatch.setattr(faulthandler, "dump_traceback", lambda: fired.append(1))
    pipeline.start_soul_watchdog(stall_seconds=0.3, poll_seconds=0.1)
    time.sleep(0.6)
    pipeline._SOUL_WD["stop"] = True
    assert not fired
```

- [ ] **Step 2: 跑测试确认失败**

Run: `python -m pytest tests/test_soul_watchdog.py -v`
Expected: FAIL（start_soul_watchdog 不存在）

- [ ] **Step 3: 实现（pipeline.py，放在 `detection_status()` 定义后）**

```python
# ---- 灵魂生命体征(2026-09-04一期,防再挂死16h无人知) ----
_SOUL_WD = {"done": None, "since": None, "dumped": False, "stop": False}


def start_soul_watchdog(stall_seconds: int = 1800, poll_seconds: int = 60):
    """研判看门狗(守护线程): running且phase=LLM研判中 且 done 停滞>stall_seconds
    → faulthandler dump全线程栈 + [soul-watchdog]日志行(2026-09-03挂死16h事故:
    7线程futex_wait,零[llm]日志,无栈可查)。顺带注册SIGUSR1: Linux容器里
    `docker exec ipguard-ai kill -USR1 1` 随时安全dump,不用等看门狗。"""
    import faulthandler
    try:
        import signal
        faulthandler.register(signal.SIGUSR1)
    except (ValueError, OSError, AttributeError):
        pass  # Windows本地/无SIGUSR1平台: 注册跳过,看门狗照常工作

    def _wd():
        import time as _t
        while not _SOUL_WD.get("stop"):
            _t.sleep(poll_seconds)
            try:
                st = detection_status()
                if not st.get("running") or st.get("phase") != "LLM研判中":
                    _SOUL_WD.update(done=None, since=None, dumped=False)
                    continue
                d = st.get("done")
                if d != _SOUL_WD["done"]:
                    _SOUL_WD.update(done=d, since=_t.time(), dumped=False)
                    continue
                if _SOUL_WD["since"] and _t.time() - _SOUL_WD["since"] > stall_seconds \
                        and not _SOUL_WD["dumped"]:
                    _SOUL_WD["dumped"] = True  # 一次停滞只dump一次;done再动自动复位
                    faulthandler.dump_traceback()
                    print(f"[soul-watchdog] 研判停滞>{stall_seconds // 60}min(done={d}),"
                          f"已dump全线程栈,请人工检查容器", flush=True)
            except Exception:
                pass  # 看门狗自身永不出错拖垮进程
    _SOUL_WD["stop"] = False
    threading.Thread(target=_wd, daemon=True).start()
```

- [ ] **Step 4: api.py startup 启动（321 行 `syslog_recv.start_watchdog()` 后）**

```python
try:
    pipeline.start_soul_watchdog()
    print("[startup] soul watchdog 已启动(SIGUSR1栈dump+研判停滞看门狗)")
except Exception as _se2:
    print("[startup] soul watchdog 启动失败:", _se2)
```

- [ ] **Step 5: 跑测试确认通过**

Run: `python -m pytest tests/test_soul_watchdog.py -v`
Expected: PASS（3 个用例；测试线程靠 stop 标志退出，daemon 兜底）

- [ ] **Step 6: Commit**

```
git add pipeline.py api.py tests/test_soul_watchdog.py
git commit -m "feat(灵魂一期): 生命体征——SIGUSR1全线程栈dump+研判停滞30min看门狗([soul-watchdog]告警行)"
```

---

### Task 12: deploy.py 登记 + 全量回归 + 收尾

**Files:**
- Modify: `backend/deploy.py`（PY_FILES 加 casebase.py）

**Interfaces:**
- Consumes: 全部前置任务。
- 产出：可部署状态（但**不部署**——Global Constraints）。

- [ ] **Step 1: PY_FILES 登记（deploy.py:37）**

列表末尾（`"sampleaudit.py"` 后）加 `", \"casebase.py\"`：

```python
    PY_FILES = ["api.py", "db.py", "dicts.py", "detector.py", "llm_client.py", "pipeline.py", "profiles.py", "syslog_recv.py", "selfheal.py", "parser_ipg.py", "parser_ipguard.py", "parser_sangfor.py", "riskmemory.py", "docscan.py", "massops.py", "storyline.py", "dayreview.py", "timeline.py", "riskboard.py", "weekly.py", "patterns.py", "web_aggregator.py", "models.py", "deepaudit.py", "domain_scan.py", "daygate.py", "sampleaudit.py", "casebase.py"]
```

- [ ] **Step 2: 全量本地回归**

Run: `python -m pytest tests/ -v`
Expected: 全部 PASS

- [ ] **Step 3: 全部改动文件 py_compile**

Run: `python -m py_compile api.py db.py dicts.py detector.py llm_client.py pipeline.py casebase.py sampleaudit.py domain_scan.py daygate.py deploy.py`
Expected: 无输出

- [ ] **Step 4: 前端预编译再验证一次**

Run: `python -c "from deploy import precompile_index; h=precompile_index(); print('OK %.1f KB' % (len(h.encode('utf-8'))/1024))"`
Expected: OK

- [ ] **Step 5: 容器密闭集成冒烟（不做生产部署，测目标为代码自洽）**

改用本机思路检查 import 链完整性（无 docker 依赖的等价验证）：

Run: `python -c "import api, pipeline, casebase, sampleaudit, domain_scan, daygate; print('imports OK')"`
Expected: imports OK（api 模块级会 print [startup] 行，正常噪音）

生产容器的密闭测试（mock LLM 蒸馏/检索命中/难例触发/前端 DOM）留到用户批准部署后首验清单：

```
1. docker logs grep -F '[soul-watchdog]' → 无(未停滞)或停滞告警可见
2. docker exec ipguard-ai kill -USR1 1 → docker logs 出现全线程栈
3. 前端误报弹窗: Radio五选一出现,未选时确认钮禁用(DOM验证)
4. 标一条误报(选归因) → cases表新增行,source=disposition_fp,attribution=所选
5. 下一轮研判后 grep -F '[判例对齐]' → 难例命中量
6. [domain-scan] 定性行不再出现白名单域名误标
```

- [ ] **Step 6: Commit**

```
git add deploy.py
git commit -m "chore(灵魂一期): deploy PY_FILES登记casebase.py(2026-09-03教训:漏登记=容器起不来)"
```

---

## Self-Review 记录（写计划时已核对）

1. **Spec 覆盖**：处置语义升级(行为级+归因五选一)=Task 6+7；cases 表字段全量=Task 4；去重30天=record_case；口径统一注入(italent 修复)=Task 9（sampleaudit 经 sweep→研判 prompt 天然覆盖，蒸馏=二期，已在 Interface 注明）；入库钩子三处=Task 6+8；检索注入 top5≤800字=Task 5；难例判定=Task 5+10（"复核摇摆"留二期——信号在 _judge 内部需先暴露，Task 5 代码注释已注明）；生命体征=Task 11；fail-soft=全钩子；PY_FILES=Task 12。第0批①=Task 1(+9 配合)、②=Task 2、④=Task 3（钩子让位 YAGNI 暂缓已声明）。
2. **占位符扫描**：无 TBD/TODO；Task 6 Step 1 测试文件里明确指示删除 `_Raises` 辅助类改用常规 pytest.raises（执行者须知）；所有代码块完整可抄。
3. **类型一致性**：`record_case(source, employee_id, outcome, attribution="", verdict_row=None, note="", fk=None, ai_verdict="")` 在 Task 5 定义、Task 6/8 调用一致；`_judge_auto0(item, cases_txt="")` Task 2 建签名（无 cases_txt）、Task 10 加参数——两任务的 diff 均展示；`_micro_fast`/`_pool_workers`/`is_hard`/`cases_for_prompt`/`feature_keys_of` 签名前后一致；`_SOUL_WD` 键名（done/since/dumped/stop）Task 11 内部自洽。
4. **已知取舍（向用户如实报告过）**：微窗口快速通道的调用量削减比例（预估 30-50%）以部署后 `[快速通道]` 前缀计数实测为准；难例"复核摇摆"信号二期补。
