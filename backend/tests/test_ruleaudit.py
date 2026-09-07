# -*- coding: utf-8 -*-
"""规则体检三类信号(2026-09-07): high_fp(过紧)/dead(零命中)/drift(漂移)。"""
from collections import defaultdict


def _cls(hits=0, weeks=None, people=1):
    w = defaultdict(int)
    for k, v in (weeks or {}).items():
        w[k] = v
    return {"hits": hits, "people": {f"p{i}" for i in range(people)}, "weeks": w}


def test_high_fp_flag():
    import ruleaudit
    by = {"个人邮箱": _cls(hits=100)}
    disp = {"个人邮箱": {"FP": 5, "TP": 0}}  # 处置5条全误报
    flags = ruleaudit._make_flags(by, disp)
    fp = [f for f in flags if f["type"] == "high_fp" and f["cls"] == "个人邮箱"]
    assert fp and "规则过紧" in fp[0]["detail"]


def test_high_fp_needs_min_disposed():
    import ruleaudit
    by = {"个人邮箱": _cls(hits=100)}
    disp = {"个人邮箱": {"FP": 4, "TP": 0}}  # 仅4条(<5不标)
    assert not [f for f in ruleaudit._make_flags(by, disp) if f["type"] == "high_fp"]


def test_dead_flag_for_zero_hit_class():
    import ruleaudit
    by = {"网盘/云盘": _cls(hits=10)}  # 只有网盘有命中
    flags = ruleaudit._make_flags(by, {})
    dead = {f["cls"] for f in flags if f["type"] == "dead"}
    assert "个人邮箱" in dead and "AI助手" in dead and "网盘/云盘" not in dead


def test_drift_flag_on_weekly_spike():
    import ruleaudit
    by = {"招聘求职": _cls(hits=120, weeks={"2026-W35": 5, "2026-W36": 4,
                                             "2026-W37": 6, "2026-W38": 5, "2026-W39": 40})}
    flags = ruleaudit._make_flags(by, {})
    dr = [f for f in flags if f["type"] == "drift" and f["cls"] == "招聘求职"]
    assert dr and "漂移" in dr[0]["detail"]


def test_no_drift_on_flat_usage():
    import ruleaudit
    by = {"招聘求职": _cls(hits=100, weeks={"2026-W35": 10, "2026-W36": 12,
                                             "2026-W37": 9, "2026-W38": 11, "2026-W39": 13})}
    assert not [f for f in ruleaudit._make_flags(by, {}) if f["type"] == "drift"]
