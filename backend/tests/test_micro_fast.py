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


def test_pool_workers_adaptive():
    import pipeline
    assert pipeline._pool_workers(2) == 4      # 常态增量: 4并发保吞吐
    assert pipeline._pool_workers(100) == 4
    assert pipeline._pool_workers(101) == 2    # 大批量(全量重判): 2并发
    assert pipeline._pool_workers(572) == 2
