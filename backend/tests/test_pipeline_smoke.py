# -*- coding: utf-8 -*-
"""主流程集成冒烟(2026-09-07盘点②): dev DB + mock LLM 跑 pipeline.run_detection
全链——水位→建窗→触发门→AI研判→verdict/alert落库→水位推进→二轮幂等。
此前主流程零集成测试: 单元测试各管一段,回归只能靠线上撞。
隔离: 员工用 _smoketest_ 前缀;跑前把水位推到当前max(防mock LLM给真实存量
事件写假研判);finally 全量清理+恢复水位/webhook/rejudge标志。"""
import json
from datetime import timedelta

import llm_client
import pipeline
import dicts
from db import (AlertRow, EventRow, FeedbackRow, Session, VerdictRow,
                bj_now, init_db, write_lock)
from models import CanonicalEvent

SMOKE_EMP = "_smoketest_emp"


def _mk_events(base):
    """网盘外发窗口: WEB网盘访问 + DOC上传3MB压缩包(带目的地,避开12分钟证据扣留)。"""
    return [
        CanonicalEvent(occurred_at=base, employee_id=SMOKE_EMP, device_id="SMOKE-PC",
                       category="WEB", action="ACCESS", target_type="URL",
                       target_value="https://pan.baidu.com/disk/main", size_bytes=0, count=2,
                       source="sangfor", raw={"domain": "pan.baidu.com", "channel": "web"}),
        CanonicalEvent(occurred_at=base + timedelta(minutes=2), employee_id=SMOKE_EMP,
                       device_id="SMOKE-PC", category="DOC", action="UPLOAD",
                       target_type="FILE", target_value="实验数据包.zip",
                       size_bytes=3 * 1048576, count=1, source="ipguard",
                       raw={"channel": "browser", "app": "msedge.exe",
                            "dest_path": "https://pan.baidu.com/x"}),
    ]


def _purge_smoke(s):
    """删冒烟员工的全部痕迹(feedback经alert_id关联,先删)。"""
    _ids = [r[0] for r in s.query(AlertRow.id).filter_by(employee_id=SMOKE_EMP).all()]
    if _ids:
        s.query(FeedbackRow).filter(FeedbackRow.alert_id.in_(_ids)).delete()
    for tbl in (AlertRow, VerdictRow, EventRow):
        s.query(tbl).filter(getattr(tbl, "employee_id") == SMOKE_EMP).delete()


def test_run_detection_smoke(monkeypatch):
    init_db()
    orig_wm = dicts.get_setting("last_judged_event_id", "0") or "0"
    orig_hook = dicts.get_setting("notify_webhook", "")
    orig_rejudge = dicts.get_setting("rejudge_pending", "") or ""
    dicts.set_setting("notify_webhook", "")   # 测试不发真webhook
    dicts.set_setting("rejudge_pending", "")  # 防run开头消费重判逻辑删真verdicts
    s = Session()
    try:
        _purge_smoke(s)  # 上次失败残留
        s.commit()
        _mx = s.query(EventRow.id).order_by(EventRow.id.desc()).first()
        dicts.set_setting("last_judged_event_id", str(_mx[0] if _mx else 0))
        rows = [EventRow(event_hash=ce.event_hash(), occurred_at=ce.occurred_at,
                         employee_id=ce.employee_id, device_id=ce.device_id,
                         category=ce.category, action=ce.action,
                         target_type=ce.target_type, target_value=ce.target_value,
                         size_bytes=ce.size_bytes, count=ce.count,
                         source=ce.source, raw=dict(ce.raw or {}))
                for ce in _mk_events(bj_now() - timedelta(hours=1))]
        with write_lock:
            s.add_all(rows)
            s.commit()
        max_id = max(r.id for r in rows)
    finally:
        s.close()

    fake = json.dumps({"intent": "data_exfiltration", "deviation": "major",
                       "risk_score": 82, "file_sensitivity": "mid",
                       "explanation": (f"{SMOKE_EMP}在该时段通过浏览器上传『实验数据包.zip』"
                                       "1个文件(3.0MB)到pan.baidu.com,属数据外发。"),
                       "channels": ["netdisk"]}, ensure_ascii=False)
    monkeypatch.setattr(llm_client, "chat", lambda *a, **k: fake)
    try:
        pipeline.run_detection()
        s = Session()
        try:
            vs = s.query(VerdictRow).filter_by(employee_id=SMOKE_EMP).all()
            assert vs, "冒烟员工应产出verdict(水位→建窗→触发门→落库全链)"
            assert any(v.ai_participated for v in vs), "应至少一个AI参与研判"
            als = s.query(AlertRow).filter_by(employee_id=SMOKE_EMP).all()
            assert als and any((a.risk_score or 0) >= 50 for a in als), "高分verdict应生成告警"
            n1 = len(vs)
        finally:
            s.close()
        assert int(dicts.get_setting("last_judged_event_id", "0")) >= max_id, "水位应推进越过冒烟事件"
        pipeline.run_detection()  # 二轮: 无新事件+已判过抑制 → 不重复产出
        s = Session()
        try:
            n2 = s.query(VerdictRow).filter_by(employee_id=SMOKE_EMP).count()
            assert n2 == n1, f"二轮应幂等(前{n1}/后{n2})"
        finally:
            s.close()
    finally:
        s = Session()
        try:
            with write_lock:
                _purge_smoke(s)
                s.commit()
        finally:
            s.close()
        dicts.set_setting("last_judged_event_id", orig_wm)
        dicts.set_setting("notify_webhook", orig_hook)
        dicts.set_setting("rejudge_pending", orig_rejudge)
