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
