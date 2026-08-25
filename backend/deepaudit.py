"""UI不可见层每小时自检(2026-08-25): 把人工深挖固化为系统不变量。

来源: 用户质问"为什么问题都是我发现的"——结构核对全绿≠数据正确。
以下每项都在UI上看不到、只能靠数据分布/受控实验发现的层面:
  D1 跨源双计回归: IPG先到+深信服后到同域名同10分钟(去重对称化后应为0)
  D2 到期豁免残留: 豁免已过期未删(I3曾不查到期继续删告警)
  D3 计数累加回归: 近1小时WEB行count=1占比异常高(幂等吞计数回归信号)
  D4 研判水位停滞: 水位落后最大事件ID>5000(研判卡死/漏判)
  D5 告警键碰撞: 同dedup_key多行(合并逻辑回归)
  D6 时钟漂移: 出现"未来"事件(采集端时钟错乱)
发现任一异常 → 打日志 + webhook通知(每天每类最多1次,防轰炸)。
"""
from __future__ import annotations

from datetime import timedelta

from db import Session, EventRow, AlertRow, ExceptionRow, bj_now
from sqlalchemy import text
import dicts


def _once_today(flag: str) -> bool:
    key = f"deepaudit_notified_{flag}_{bj_now().strftime('%Y%m%d')}"
    if dicts.get_setting(key):
        return False
    dicts.set_setting(key, "1")
    return True


def _notify(msg: str):
    print(f"[deepaudit] {msg}", flush=True)
    try:
        from pipeline import _notify_webhook
        _notify_webhook("系统自检", 0, msg)
    except Exception:
        pass


def run_deep_audit() -> dict:
    out = {}
    s = Session()
    try:
        now = bj_now()
        # D1 跨源双计(近1小时)
        n1 = s.execute(text("""
            SELECT COUNT(*) FROM events a JOIN events b ON a.employee_id=b.employee_id
              AND a.category='WEB' AND b.category='WEB' AND a.source!=b.source
              AND json_extract(a.raw,'$.domain')=json_extract(b.raw,'$.domain')
              AND b.source!='ipguard' AND a.source='ipguard'
              AND b.occurred_at BETWEEN a.occurred_at AND datetime(a.occurred_at,'+10 minutes')
            WHERE a.occurred_at >= :t"""), {"t": now - timedelta(hours=1)}).scalar() or 0
        out["D1_跨源双计"] = n1
        if n1 > 5 and _once_today("d1"):
            _notify(f"跨源去重回归: 近1小时 {n1} 对同浏览双计(IPG与深信服)")

        # D2 到期豁免残留
        from datetime import datetime as _dt
        expired = [x for x in s.query(ExceptionRow).all()
                   if x.expires_at and x.expires_at <= _dt.utcnow()]
        out["D2_到期豁免"] = len(expired)
        if expired:
            for x in expired:
                s.delete(x)
            s.commit()
            _notify(f"清理已到期豁免 {len(expired)} 条(到期后豁免失效,告警恢复)")

        # D3 计数累加回归(近1小时WEB行count=1占比)
        rows = s.query(EventRow.count).filter(
            EventRow.category == "WEB", EventRow.occurred_at >= now - timedelta(hours=1)).all()
        if len(rows) > 300:
            one = sum(1 for (c,) in rows if (c or 1) == 1)
            ratio = one / len(rows)
            out["D3_count1占比"] = round(ratio, 2)
            if ratio > 0.97 and _once_today("d3"):
                _notify(f"计数累加疑似回归: 近1小时 {len(rows)} 行WEB里 {round(ratio*100)}% count=1")

        # D4 水位停滞
        wm = int(dicts.get_setting("last_judged_event_id", "0") or "0")
        mx = s.query(EventRow.id).order_by(EventRow.id.desc()).first()
        gap = (mx[0] - wm) if mx else 0
        out["D4_水位差"] = gap
        if gap > 5000:
            try:  # 自愈: 直接拉起一轮研判(单飞,卡死多为检测线程退出)
                import pipeline
                pipeline.start_detection()
                _notify(f"研判水位落后 {gap} 条,已自动拉起一轮研判补救")
            except Exception as _pe:
                _notify(f"研判水位落后 {gap} 条且自动拉起失败: {_pe}")

        # D5 告警键碰撞
        dups = s.execute(text("""
            SELECT dedup_key, COUNT(*) c FROM alerts WHERE dedup_key IS NOT NULL
            GROUP BY dedup_key HAVING c > 1 LIMIT 5""")).fetchall()
        out["D5_键碰撞"] = len(dups)
        if dups:
            # 自愈: 保留同键最高分行(与人工修复同规则),防列表重复计数
            from db import write_lock, AlertRow as _AR
            with write_lock:
                for dk, _c in dups:
                    rows = s.query(_AR).filter_by(dedup_key=dk).order_by(_AR.risk_score.desc()).all()
                    for extra in rows[1:]:
                        s.delete(extra)
                s.commit()
            _notify(f"自动合并重复告警键 {len(dups)} 组(各保留最高分)")

        # D6 未来事件(时钟漂移)
        n6 = s.query(EventRow).filter(EventRow.occurred_at > now + timedelta(minutes=5)).count()
        out["D6_未来事件"] = n6
        if n6 > 10 and _once_today("d6"):
            _notify(f"出现 {n6} 条'未来时间'事件(采集端时钟错乱,夜间/频次口径会失真)")
    finally:
        s.close()
    return out


if __name__ == "__main__":
    print(run_deep_audit())
