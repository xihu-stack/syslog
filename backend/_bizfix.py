"""业务数据审计修复(2026-08-24): severity归一/留痕补录/幽灵告警回迁/复犯重开/双身份合并。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
import time

import sqlite3
from db import write_lock

SQLS_FIX = []


def _merge_dup_alerts(db, emp):
    rows = db.execute(
        "SELECT id, dedup_key, risk_score FROM alerts WHERE employee_id=? AND dedup_key IS NOT NULL ORDER BY risk_score DESC",
        (emp,)).fetchall()
    seen = {}
    for r in rows:
        k = r["dedup_key"]
        if k in seen:
            db.execute("DELETE FROM alerts WHERE id=?", (r["id"],))
        else:
            seen[k] = r["id"]
    # 重算dedup_key(账号前缀→新名)
    db.execute("UPDATE alerts SET dedup_key=employee_id||'|'||scenario WHERE employee_id=?", (emp,))


def _rename(db, old, new):
    n = 0
    db.execute("DELETE FROM profiles WHERE employee_id=?", (old,))  # 新名行已存在则丢弃旧行
    for tbl in ("events", "verdicts", "alerts", "profiles", "exceptions"):
        cur = db.execute(f"UPDATE {tbl} SET employee_id=? WHERE employee_id=?", (new, old))
        n += cur.rowcount
    _merge_dup_alerts(db, new)
    return n


def main():
    db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
    db.row_factory = sqlite3.Row
    log = []

    with write_lock:
        for attempt in range(30):
            try:
                # 1) severity 小写归一
                cur = db.execute("UPDATE alerts SET severity=UPPER(severity) WHERE severity IN ('crit','high')")
                log.append(f"1) severity归一: {cur.rowcount}行")

                # 2) 历史CONFIRMED留痕补录
                fb = 0
                for aid in (25, 27, 32, 34, 38, 40, 45):
                    ex = db.execute("SELECT 1 FROM feedback WHERE alert_id=?", (aid,)).fetchone()
                    if not ex:
                        db.execute("INSERT INTO feedback (alert_id, label, reason, created_at) VALUES (?,?,?,datetime('now','+8 hours'))",
                                   (aid, "TP", "历史确认(留痕功能上线前补录)"))
                        fb += 1
                log.append(f"2) 留痕补录: {fb}条")

                # 3) 幽灵告警回迁(机器有映射) + 无映射标注
                for aid, target in ((145, "wangxiaocui"), (146, "chenzheqin"), (164, "huangchunyu")):
                    a = db.execute("SELECT employee_id, scenario, risk_score FROM alerts WHERE id=?", (aid,)).fetchone()
                    if a and a["employee_id"].startswith("IPG:"):
                        n = _rename(db, a["employee_id"], target)
                        log.append(f"3) 回迁alert{aid} {a['employee_id']}->{target} ({n}行)")
                for aid in (134, 154):
                    db.execute("UPDATE alerts SET summary='[历史:该机器未匹配使用人,原始事件已出库] '||substr(summary,1,280) WHERE id=? AND summary NOT LIKE '[历史%'", (aid,))
                log.append("3) 无映射幽灵标注: 2条")

                # 4) 复犯重开: CLOSED+无复核/白名单标记+同研判>=50+窗口近7天
                BLOCK = re.compile(r"(次日复核|N\+1复核|白名单|巡检|豁免|自动关闭|降至|疑误报|重开)")
                rows = db.execute("""SELECT a.id, a.risk_score ar, v.risk_score vr FROM alerts a
                    JOIN verdicts v ON a.verdict_id=v.id AND v.employee_id=a.employee_id
                    WHERE a.status='CLOSED' AND v.risk_score>=50 AND v.window_start>='2026-08-17'""").fetchall()
                reopened = []
                for r in rows:
                    sm = db.execute("SELECT summary FROM alerts WHERE id=?", (r["id"],)).fetchone()["summary"] or ""
                    if BLOCK.search(sm):
                        continue
                    db.execute("UPDATE alerts SET status='NEW', risk_score=?, severity=? WHERE id=?",
                               (r["vr"], "CRITICAL" if r["vr"] >= 76 else "HIGH", r["id"]))
                    db.execute("UPDATE alerts SET summary='[复犯重开:关联研判显示近7天行为再次发生] '||substr(summary,1,280) WHERE id=?", (r["id"],))
                    reopened.append((r["id"], r["ar"], r["vr"]))
                log.append(f"4) 复犯重开: {reopened}")

                # 5) 同机双身份合并(IPG占位→AGT已映射账号)
                agtm = json.loads(db.execute("SELECT value FROM settings WHERE key='ipg_agt_map'").fetchone()[0])
                evemps = {r[0] for r in db.execute("SELECT DISTINCT employee_id FROM events")}
                pairs = []
                for e in list(evemps):
                    if e and e.startswith("IPG:"):
                        acct = agtm.get(e[4:])
                        if acct and acct in evemps and acct != e:
                            pairs.append((e, acct))
                for old, new in pairs:
                    n = _rename(db, old, new)
                    log.append(f"5) 合并 {old}->{new} ({n}行)")
                db.commit()
                break
            except sqlite3.OperationalError as e:
                db.rollback()
                if "locked" in str(e).lower() and attempt < 29:
                    time.sleep(1)
                    continue
                raise

    print(json.dumps(log, ensure_ascii=False, indent=1))


main()
