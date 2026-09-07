# -*- coding: utf-8 -*-
"""处置端点接判例管道(Task6): 误报必选行为归因五选一(400),判例落CaseRow。
直调被_ui_write包装的函数——装饰器只包retry_write无鉴权(鉴权在HTTP中间件层)。"""
from datetime import datetime

import pytest
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
    with pytest.raises(HTTPException) as e:
        api.verdict_false_positive(vid=vid, reason="误报")
    assert e.value.status_code == 400
    with pytest.raises(HTTPException) as e:
        api.verdict_false_positive(vid=vid, reason="误报", attribution="随便编的")
    assert e.value.status_code == 400


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
