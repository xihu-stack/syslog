"""UI不可见层每小时自检(2026-08-25): 把人工深挖固化为系统不变量。

来源: 用户质问"为什么问题都是我发现的"——结构核对全绿≠数据正确。
以下每项都在UI上看不到、只能靠数据分布/受控实验发现的层面:
  D1 跨源双计回归: IPG先到+深信服后到同域名同10分钟(去重对称化后应为0)
  D2 到期豁免残留: 豁免已过期未删(I3曾不查到期继续删告警)
  D3 计数累加回归: 近1小时WEB行count=1占比异常高(幂等吞计数回归信号)
  D4 研判水位停滞: 水位落后最大事件ID>5000(研判卡死/漏判)
  D5 告警键碰撞: 同dedup_key多行(合并逻辑回归)
  D6 时钟漂移: 出现"未来"事件(采集端时钟错乱)
  D7 两行分数漂移: NEW告警分≠挂靠verdict分(只改一行的写路径回归;I2的残差探测器)
  D8 说明外来域名: 研判说明提到窗口事实集(WEB域名∪DOC目的地)外的域名(AI跨窗口引用)
  D9 关闭无留痕: CLOSED行缺关闭原因前缀(I11残差,应=0)
  D10 超龄NEW: 窗口>7天仍NEW(I8残差,应=0)
  D11 同场景堆积: 同(员工,场景)≥3条NEW并存(按日立行回归——trend/mass已周键化)
  D12 分数级别错配: NEW行severity≠severity_of(score)(提分未同步级别的回归)
发现任一异常 → 打日志 + webhook通知(每天每类最多1次,防轰炸)。
D7-D12(2026-09-02): 多轮人工审计问题的固化——每类漂移只在审计里付一次学费,
之后由本层每小时盯着; 新聚合场景接入必须照抄周键,否则D11当天报。
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta

from db import Session, EventRow, AlertRow, ExceptionRow, VerdictRow, bj_now, events_by_hashes, severity_of
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

        # D7 两行分数漂移(2026-09-02): NEW告警分≠挂靠verdict分。I2每小时兜底对齐后
        # 残差应=0;>0=出现"只改一行"的写路径(2026-09-01曾因此13条重锚被I2回写)。
        # 只报不修——修复归I2,这里是回归探测器。
        drift = [(a.id, a.risk_score, v.risk_score)
                 for a, v in s.query(AlertRow, VerdictRow)
                 .join(VerdictRow, AlertRow.verdict_id == VerdictRow.id)
                 .filter(AlertRow.status == "NEW").all()
                 if (a.risk_score or 0) != (v.risk_score or 0)]
        out["D7_两行分数漂移"] = len(drift)
        if drift and _once_today("d7"):
            _notify(f"两行分数漂移 {len(drift)} 条(告警分≠verdict分,存在只改一行的写路径): 首个#{drift[0][0]}")

        # D8 说明外来域名(2026-09-02): 研判说明提到的域名不在窗口事实集内=AI跨窗口
        # 引用/幻觉。事实集=WEB域名∪DOC目的地(dest_host);审计工具自身教训:漏掉
        # dest_path会把真实吻合的说明误报成外来(8-31曾因此误报4条)。
        # >1才通知: 已知个别说明带无佐证的同时刻浏览提及(次级瑕疵),单条不轰炸。
        dom_re = re.compile(r"[a-z0-9][a-z0-9.-]{4,60}\.(?:com|cn|net|org|io|ai|dev|cc)", re.I)
        foreign = []
        for a in s.query(AlertRow).filter(AlertRow.status == "NEW").order_by(AlertRow.id).limit(150).all():
            v = s.get(VerdictRow, a.verdict_id) if a.verdict_id else None
            exp = (v.explanation if v else None) or ""
            if not v or not exp:
                continue
            own = set()
            for e in events_by_hashes(s, v.event_hashes or []):
                raw = e.raw or {}
                d = (raw.get("domain") or "").lower()
                if d:
                    own.add(d)
                dh = (dicts.dest_host(raw) or "").lower()
                if dh:
                    own.add(dh)
            ment = {m.lower() for m in dom_re.findall(exp)}
            if own and ment - {m for m in ment if any(m in d or d in m for d in own)}:
                foreign.append(a.id)
        out["D8_说明外来域名"] = len(foreign)
        if len(foreign) > 1 and _once_today("d8"):
            _notify(f"研判说明含窗口外域名 {len(foreign)} 条(AI跨窗口引用,需核对): {foreign[:5]}")

        # D9 关闭留痕(2026-09-02): CLOSED行缺关闭原因前缀(I11每小时补记,残差应=0)
        hint9 = re.compile(r"关闭|降至|不构成|压回|失效|未复现|白名单|豁免|已出库|合并|对齐|降噪")
        nomark = [a.id for a in s.query(AlertRow).filter(AlertRow.status == "CLOSED").all()
                  if not any(hint9.search(m) for m in re.findall(r"\[[^\]\n]{2,200}\]", a.summary or ""))]
        out["D9_关闭无留痕"] = len(nomark)
        if nomark and _once_today("d9"):
            _notify(f"CLOSED告警 {len(nomark)} 条无关闭原因留痕(I11应已补记): {nomark[:5]}")

        # D10 超龄NEW(2026-09-02): 窗口>7天仍NEW(I8兜底后应=0)
        n10 = s.query(AlertRow).filter(AlertRow.status == "NEW",
                                       AlertRow.window_start < now - timedelta(days=7)).count()
        out["D10_超龄NEW"] = n10
        if n10 and _once_today("d10"):
            _notify(f"超龄NEW告警 {n10} 条(窗口>7天,I8应已关闭)")

        # D11 同场景堆积(2026-09-02): 同(员工,场景)≥3条NEW并存——按日立行的回归
        # 探测器。trend/mass已周键化后不应堆积;新聚合场景接入必须照抄周键。
        cnt11 = defaultdict(int)
        for r in s.query(AlertRow.employee_id, AlertRow.scenario).filter(AlertRow.status == "NEW").all():
            cnt11[(r[0], r[1])] += 1
        pile = {f"{k[0]}|{k[1]}": c for k, c in cnt11.items() if c >= 3}
        out["D11_同场景堆积"] = len(pile)
        if pile and _once_today("d11"):
            _notify(f"同人同场景NEW堆积 {len(pile)} 组(≥3条,按日立行回归?): {list(pile.items())[:3]}")

        # D12 分数级别错配(2026-09-02): NEW行severity≠severity_of(score)——提分未
        # 同步级别的回归探测器(2026-08-28曾出现85分挂MEDIUM徽章)
        bad12 = [a.id for a in s.query(AlertRow).filter(AlertRow.status == "NEW").all()
                 if a.severity != severity_of(a.risk_score or 0)]
        out["D12_分数级别错配"] = len(bad12)
        if bad12 and _once_today("d12"):
            _notify(f"NEW告警 {len(bad12)} 条severity与分数档线不符: {bad12[:5]}")
    finally:
        s.close()
    return out


if __name__ == "__main__":
    print(run_deep_audit())
