# -*- coding: utf-8 -*-
"""准则条款表锁(2026-09-07条款化): SYSTEM_PROMPT 由 CLAUSES 条款拼接而成。
两层保护:
  1) 字节锁——sha256 与条款化完成时基线一致(vLLM prefix caching/判例匹配依赖
     字节稳定)。有意改条款时须同步更新 EXPECTED_SHA256(失败信息会给出新hash)。
  2) 语义金丝雀——关键口径必须在 prompt 里存活。改条款文本合法,但误删以下
     任何一条历史踩坑口径=回归(这些每条都对应一次真实误报/漏报事故)。"""
import hashlib

EXPECTED_SHA256 = "40d1b9f8dacd55e48b48623cc0f1dc31a0703df54061133e905beef8259e1f27"
EXPECTED_LEN = 9331
EXPECTED_N = 44  # C01..C44


def _sp():
    import detector
    return detector.SYSTEM_PROMPT


def test_system_prompt_hash_locked():
    """字节锁: 任何无意变化(拼接顺序/条款边界/字面量)在此拦截。"""
    sp = _sp()
    h = hashlib.sha256(sp.encode("utf-8")).hexdigest()
    assert h == EXPECTED_SHA256, (
        f"SYSTEM_PROMPT字节变了: len={len(sp)}(基线{EXPECTED_LEN}) sha256={h}。"
        "若是有意修改条款: 确认改动条款与since更新后, 把EXPECTED_SHA256/EXPECTED_LEN换成此值")


def test_clauses_join_equals_prompt():
    """拼接一致性: prompt 只能由条款表产生,条款表外无散文本。"""
    import detector
    assert "".join(c["text"] for c in detector.CLAUSES) == detector.SYSTEM_PROMPT


def test_clause_ids_unique_ordered():
    import detector
    ids = [c["id"] for c in detector.CLAUSES]
    assert len(ids) == EXPECTED_N
    assert len(set(ids)) == EXPECTED_N
    assert ids == [f"C{i:02d}" for i in range(1, EXPECTED_N + 1)]


def test_clause_metadata_shape():
    """每条有id/name/since/src/非空text; since为v0或YYYY-MM-DD。"""
    import re
    for c in _clauses():
        assert set(c) >= {"id", "name", "since", "src", "text"}
        assert c["text"].strip(), c["id"]
        assert c["since"] == "v0" or re.fullmatch(r"\d{4}-\d{2}-\d{2}", c["since"]), c["id"]


def _clauses():
    import detector
    return detector.CLAUSES


def _by_id(cid):
    for c in _clauses():
        if c["id"] == cid:
            return c
    raise AssertionError(f"missing clause {cid}")


def test_c06_facts_single_source():
    """C06 是 facts.COMPANY_DOMAIN_FACTS 的动态引用,不是字面副本(单源不回退)。"""
    import detector
    import facts
    assert _by_id("C06")["text"] is facts.COMPANY_DOMAIN_FACTS
    assert facts.COMPANY_DOMAIN_FACTS in detector.SYSTEM_PROMPT


# ---- 语义金丝雀: 历史事故口径必须存活(改写措辞可以,消失不行) ----

def test_canary_italent_not_job_site():
    """italent=北森HR系统非求职站(2026-08-28误标事故)。"""
    assert "italent" in _by_id("C18")["text"]
    assert "不算求职信号" in _by_id("C18")["text"]


def test_canary_sendphotoes_noise():
    """SendPhotoes客户端截图噪声不单独打高分(2026-08-20)。"""
    t = _by_id("C09")["text"]
    assert "SendPhotoes" in t and "通道噪音" in t


def test_canary_job_tier_unified():
    """招聘三规合一分档(2026-09-01自相矛盾告警事故)。"""
    t = _by_id("C17")["text"]
    assert "三规合一" in t and "字段与文字必须同结论" in t


def test_canary_heartbeat_not_counted():
    """心跳计数不计入总次数(2026-08-26虚高计数事故)。"""
    assert "不计入" in _by_id("C39")["text"]


def test_canary_direction_send_recv():
    """方向铁律: 收≠发(下载不得定性为外发)。"""
    assert "↓收" in _by_id("C37")["text"] and "↑发" in _by_id("C37")["text"]


def test_canary_four_questions_disguise():
    """外发四问含④伪装检查(2026-09-07)。"""
    t = _by_id("C30")["text"]
    assert "四问" in t and "疑似伪装外发" in t


def test_canary_sensitivity_no_inflation():
    """file_sensitivity无证据默认none,严禁推断抬高。"""
    t = _by_id("C35")["text"]
    assert "一律none" in t and "严禁" in t


def test_canary_crossday_scope():
    """跨天作用域铁律: 他场景跨天不得给当前场景升档(2026-08-28事故)。"""
    assert "场景作用域铁律" in _by_id("C25")["text"]


def test_canary_time_alignment():
    """说明时间铁律: 日期须与本窗口一致(2026-08-26时间错位事故)。"""
    assert "本窗口时间" in _by_id("C41")["text"] and "完全一致" in _by_id("C41")["text"]
