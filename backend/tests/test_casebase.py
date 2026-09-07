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
    casebase._CALIBER_CACHE.update(txt="", ts=0.0)
    txt = casebase.caliber_text()
    assert "italent.cn" in txt
    assert "误报判例" in txt and "域名定性错" in txt
    # TTL缓存: 二次调用字节一致
    assert casebase.caliber_text() == txt
