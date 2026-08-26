# -*- coding: utf-8 -*-
"""每日深度审计 2026-08-26 第一批: 一/二/五类(纯数据核查)。"""
import sys
sys.path.insert(0, "/app")
import json
import re
import sqlite3
from datetime import datetime, timedelta

db = sqlite3.connect("/app/data/ipguard.db", timeout=60)
db.row_factory = sqlite3.Row
q1 = lambda sql, *a: db.execute(sql, a).fetchone()[0]
R = {}

# ============ 一、数据准确性 ============
# 1) 全量对账
wrong = dangle = mismatch = sevb = 0
PREFIX = re.compile(r"(次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开)")
for a in db.execute("SELECT id, employee_id, risk_score, severity, verdict_id, summary, dedup_key FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if not v:
        dangle += 1
        continue
    if v["employee_id"] != a["employee_id"]:
        wrong += 1
    if not PREFIX.search(a["summary"] or "") and a["risk_score"] != v["risk_score"]:
        mismatch += 1
R["一1_对账"] = {"错人链接": wrong, "悬空": dangle, "分不一致": mismatch}
# severity档
sev_bad = db.execute("""SELECT COUNT(*) FROM alerts WHERE
    (risk_score>=76 AND severity NOT LIKE 'CRIT%') OR (risk_score BETWEEN 56 AND 75 AND severity NOT LIKE 'HIGH') OR
    (risk_score BETWEEN 31 AND 55 AND severity NOT LIKE 'MED') OR (risk_score<31 AND severity NOT LIKE 'LOW')""").fetchone()[0]
dupk = db.execute("SELECT COUNT(*) FROM (SELECT dedup_key FROM alerts GROUP BY dedup_key HAVING COUNT(*)>1)").fetchone()[0]
R["一1_档位与键"] = {"severity错档": sev_bad, "dedup重复组": dupk}

# 2) 抽5条近告警对数
samples = []
for a in db.execute("""SELECT id, employee_id, scenario, risk_score, summary, window_start FROM alerts
    WHERE window_start>='2026-08-25' AND scenario IN ('mass_exfil','data_exfiltration') ORDER BY id DESC LIMIT 5""").fetchall():
    d0 = str(a["window_start"])[:10]
    m = re.search(r"累计外发(\d+)次、共([\d.]+)MB", a["summary"] or "")
    if m:
        cnt = q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", a["employee_id"], d0, d0 + " 23:59")
        sz = q1("SELECT COALESCE(SUM(size_bytes),0) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", a["employee_id"], d0, d0 + " 23:59")
        ok = (int(m.group(1)) == cnt) and (abs(float(m.group(2)) - (sz or 0) / 1048576) < 1.5)
        samples.append((a["id"], a["employee_id"][:8], "次%s/MB%s" % (m.group(1), m.group(2)), "实%d/MB%.1f" % (cnt, (sz or 0) / 1048576), "✓" if ok else "✗"))
    else:
        mm = re.search(r"×(\d+)", a["summary"] or "")
        samples.append((a["id"], a["employee_id"][:8], "非数字模板", mm.group(1) if mm else "-", "-"))
R["一2_抽5条"] = samples

# 3) 风险榜/效率复算(2人)
import dicts
agtm = json.loads(db.execute("SELECT value FROM settings WHERE key='ipg_agt_map'").fetchone()[0])
for emp in ("李浩", "唐方毅"):
    ex = q1("SELECT COUNT(*) FROM alerts WHERE employee_id=? AND scenario='mass_delete'", emp)
    n1v = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND intent='data_exfiltration' AND risk_score>=50", emp)
    R.setdefault("一3_风险榜", {})[emp] = {"exfil信号源": n1v, "删除信号源": ex}
R["一3_效率"] = "见API复查"

# ============ 二、漏报 ============
# 1) 高风险域名无verdict(近1天按员工)
HR = ("filehelper", "zhipin", "liepin", "51job", "zhaopin", "pan.baidu", "outlook.live", "outlook.office.com", "mail.163", "mail.qq", "gmail", "weiyun", "alipan")
rows = db.execute("""SELECT employee_id, COUNT(*) c FROM events WHERE category='WEB' AND occurred_at>=datetime('now','+8 hours','-1 day')
AND (""" + " OR ".join(["raw LIKE '%'||?||'%%'" for _ in range(1)]) + """) GROUP BY employee_id""", ("%filehelper%",)).fetchall()
miss1 = []
for r in rows:
    if r["c"] < 3:
        continue
    has_v = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-1 day')", r["employee_id"])
    if has_v == 0:
        # 是否豁免/抑制: 查6小时内研判
        recent = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-7 days')", r["employee_id"])
        miss1.append((r["employee_id"][:12], r["c"], "7天内研判%d次" % recent))
R["二1_高风险无verdict"] = miss1[:10] or "无"

# 2) 非白名单SEND无任何告警/聚合(近1天)
wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
srows = db.execute("""SELECT employee_id, COUNT(*) c, COALESCE(SUM(size_bytes),0) sz FROM events
WHERE action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-1 day') GROUP BY employee_id""").fetchall()
miss2 = []
for r in srows:
    if r["c"] < 10 and (r["sz"] or 0) < 50 * 1048576:
        continue
    al = q1("SELECT COUNT(*) FROM alerts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-2 days')", r["employee_id"])
    if al == 0:
        miss2.append((r["employee_id"][:12], r["c"], round((r["sz"] or 0) / 1048576, 1)))
R["二2_外发无告警"] = miss2[:10] or "无"

# 3) 深夜真实WEB≥3条零研判
nrows = db.execute("""SELECT employee_id, COUNT(*) c FROM events WHERE category='WEB'
AND occurred_at>=datetime('now','+8 hours','-1 day')
AND (CAST(strftime('%H',occurred_at) AS INT)>=22 OR CAST(strftime('%H',occurred_at) AS INT)<7)
AND raw NOT LIKE '%update.%' AND raw NOT LIKE '%telemetry%'
GROUP BY employee_id HAVING c>=3""").fetchall()
miss3 = []
for r in nrows:
    has_v = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-1 day')", r["employee_id"])
    if has_v == 0:
        miss3.append((r["employee_id"][:12], r["c"]))
R["二3_深夜零研判"] = miss3[:10] or "无"

# ============ 五、盲区 ============
# 1) 未分类高频外部域名(近7天≥5次)
doms = db.execute("""SELECT json_extract(raw,'$.domain') d, COUNT(*) c, COUNT(DISTINCT employee_id) u FROM events
WHERE category='WEB' AND occurred_at>=datetime('now','+8 hours','-7 days')
GROUP BY d HAVING d IS NOT NULL AND c>=5 ORDER BY c DESC LIMIT 120""").fetchall()
uncat = []
for r in doms:
    d = (r["d"] or "").lower()
    if not d or "." not in d:
        continue
    if any(d == w or d.endswith("." + w) for w in wl):
        continue
    if dicts.risk_class(d):
        continue
    if any(x in d for x in ("microsoft", "msn.", "bing", "office", "windows", "azure", "akamai", "cdn", "qq.com", "weixin", "baidu", "douyin", "bilivideo", "hdslb", "volces", "zijieapi", "bytedns", "byteimg", "snssdk", "toutiao", "kdocs", "wps", "icloud", "apple", "adnxs", "doubleclick", "cnzz", "umeng", "gstatic", "google", "github", "alicdn", "aliyuncs", "huawei", "mi.com", "jd.com", "taobao", "tencent", "weibo", "zhihu", "xiaohongshu", "douyinvideo", "edgent")):
        continue
    uncat.append((d[:40], r["c"], r["u"]))
R["五1_未分类域名TOP10"] = uncat[:10]

# 2) 白名单域名流量滥用(单人单日向同一白名单域名SEND≥20或≥200MB)
abuse = db.execute("""SELECT employee_id, json_extract(raw,'$.domain') dom, COUNT(*) c, SUM(COALESCE(size_bytes,0)) sz FROM events
WHERE action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-7 days')
GROUP BY employee_id, json_extract(raw,'$.domain')
HAVING (c>=20 OR sz>=200*1048576) ORDER BY sz DESC LIMIT 12""").fetchall()
ab2 = []
for r in abuse:
    d = (r["dom"] or "").lower()
    if d and any(d == w or d.endswith("." + w) for w in wl):
        ab2.append((r["employee_id"][:10], d[:32], r["c"], round((r["sz"] or 0) / 1048576)))
R["五2_白名单高量传输"] = ab2[:8] or "无异常"

# 3) 新增IPG占位
new_ipg = db.execute("""SELECT employee_id, MAX(occurred_at) mx FROM events WHERE employee_id LIKE 'IPG:%'
AND occurred_at>=datetime('now','+8 hours','-2 days') GROUP BY employee_id""").fetchall()
R["五3_活跃IPG占位"] = [(r["employee_id"], agtm.get(r["employee_id"][4:]) or "未匹配") for r in new_ipg[:8]]

print(json.dumps(R, ensure_ascii=False, indent=1))
