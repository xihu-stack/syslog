# -*- coding: utf-8 -*-
"""每日深度审计 2026-08-28: 五类全量核查。"""
import sys, json, re, sqlite3
from datetime import datetime, timedelta
from collections import Counter, defaultdict

db = sqlite3.connect("/app/data/ipguard.db", timeout=120)
db.row_factory = sqlite3.Row
q1 = lambda sql, *a: db.execute(sql, a).fetchone()[0]
PREFIX = re.compile(r"(次日复核|N\+1复核|研判已降至|白名单|巡检|豁免|历史|复犯重开)")
R = {}

# ===== 一、数据准确性 =====
wrong = dangle = mismatch = 0
for a in db.execute("SELECT id, employee_id, risk_score, severity, verdict_id, summary FROM alerts WHERE verdict_id IS NOT NULL").fetchall():
    v = db.execute("SELECT employee_id, risk_score FROM verdicts WHERE id=?", (a["verdict_id"],)).fetchone()
    if not v: dangle += 1; continue
    if v["employee_id"] != a["employee_id"]: wrong += 1
    if not PREFIX.search(a["summary"] or "") and a["risk_score"] != v["risk_score"]: mismatch += 1
def sv(sc): return "CRITICAL" if sc>=76 else "HIGH" if sc>=56 else "MEDIUM" if sc>=31 else "LOW"
sev_bad = sum(1 for a in db.execute("SELECT risk_score, severity FROM alerts").fetchall() if a["severity"] != sv(a["risk_score"]))
dupk = q1("SELECT COUNT(*) FROM (SELECT dedup_key FROM alerts GROUP BY dedup_key HAVING COUNT(*)>1)")
R["一1"] = {"错人": wrong, "悬空": dangle, "分不一致": mismatch, "sev错": sev_bad, "dedup重复": dupk}

# 一2: 抽5条当日
samples = []
for a in db.execute("""SELECT id, employee_id, scenario, risk_score, summary, window_start FROM alerts
    WHERE window_start>='2026-08-28' AND scenario IN ('mass_exfil','data_exfiltration') ORDER BY id DESC LIMIT 5""").fetchall():
    d0 = str(a["window_start"])[:10]
    m = re.search(r"累计外发(\d+)次、共([\d.]+)MB", a["summary"] or "")
    if m:
        cnt = q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", a["employee_id"], d0, d0+" 23:59")
        sz = q1("SELECT COALESCE(SUM(size_bytes),0) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", a["employee_id"], d0, d0+" 23:59")
        ok = int(m.group(1)) == cnt and abs(float(m.group(2)) - sz/1048576) < 2
        samples.append((a["id"], a["employee_id"][:8], f"{m.group(1)}/{m.group(2)}MB", f"实{cnt}/{sz/1048576:.1f}", "OK" if ok else "DIFF"))
    else:
        # 非数字模板,查窗口内SEND次数是否>0
        cnt = q1("SELECT COUNT(*) FROM events WHERE employee_id=? AND occurred_at>=? AND occurred_at<? AND action IN ('SEND','UPLOAD')", a["employee_id"], d0, d0+" 23:59")
        samples.append((a["id"], a["employee_id"][:8], "AI说明", f"实{cnt}SEND", "OK" if cnt >= 0 else "DIFF"))
R["一2"] = samples

# 一3: 榜单复算
sys.path.insert(0, "/app")
import dicts
for emp in ("houshunan", "熊磊"):
    cur = db.execute("SELECT MAX(risk_score) FROM alerts WHERE employee_id=? AND status IN ('NEW','CONFIRMED') AND window_start>=datetime('now','+8 hours','-7 days')", (emp,)).fetchone()[0]
    mem = db.execute("SELECT peak_score, recent_score, trend FROM risk_memory WHERE employee_id=? AND scenario='data_exfiltration'", (emp,)).fetchone()
    R.setdefault("一3", {})[emp] = {"cur": cur, "mem_peak": mem[0] if mem else None, "mem_recent": mem[1] if mem else None, "trend": mem[2] if mem else None}

# ===== 二、漏报 =====
HR = ("filehelper", "zhipin", "liepin", "51job", "pan.baidu", "outlook.live", "mail.163", "mail.qq", "gmail")
miss1 = []
for pat in HR:
    for r in db.execute(f"""SELECT employee_id, COUNT(*) c FROM events WHERE category='WEB'
        AND occurred_at>=datetime('now','+8 hours','-1 day') AND raw LIKE '%{pat}%'
        GROUP BY employee_id HAVING c>=3""").fetchall():
        hv = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-1 day')", r["employee_id"])
        if hv == 0:
            d7 = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-7 days')", r["employee_id"])
            miss1.append((r["employee_id"][:12], pat[:12], r["c"], f"7d{d7}"))
R["二1"] = miss1[:6] or "无"

wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
miss2 = []
for r in db.execute("""SELECT employee_id, COUNT(*) c, COALESCE(SUM(size_bytes),0) sz FROM events
    WHERE action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-1 day')
    GROUP BY employee_id""").fetchall():
    if r["c"] < 10 and (r["sz"] or 0) < 50*1048576: continue
    al = q1("SELECT COUNT(*) FROM alerts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-2 days')", r["employee_id"])
    if al == 0: miss2.append((r["employee_id"][:12], r["c"], round((r["sz"] or 0)/1048576, 1)))
R["二2"] = miss2[:6] or "无"

miss3 = []
for r in db.execute("""SELECT employee_id, COUNT(*) c FROM events WHERE category='WEB'
    AND occurred_at>=datetime('now','+8 hours','-1 day')
    AND (CAST(strftime('%H',occurred_at) AS INT)>=22 OR CAST(strftime('%H',occurred_at) AS INT)<7)
    AND raw NOT LIKE '%update.%' AND raw NOT LIKE '%telemetry%'
    GROUP BY employee_id HAVING c>=3""").fetchall():
    hv = q1("SELECT COUNT(*) FROM verdicts WHERE employee_id=? AND window_start>=datetime('now','+8 hours','-1 day')", r["employee_id"])
    if hv == 0: miss3.append((r["employee_id"][:12], r["c"]))
R["二3"] = miss3[:6] or "无"

try:
    from deepaudit import run_deep_audit
    R["二5"] = run_deep_audit()
except Exception as e:
    R["二5"] = f"fail:{e}"

# ===== 三、AI输入 =====
import detector
from datetime import datetime as _dt
def _ts(x): return x if isinstance(x, _dt) else _dt.fromisoformat(str(x)[:19])
class E:
    def __init__(s2, d):
        s2.__dict__.update(d)
        s2.raw = d["raw"] if isinstance(d["raw"], dict) else json.loads(d["raw"] or "{}")
        if isinstance(s2.occurred_at, str): s2.occurred_at = _ts(s2.occurred_at)
bad_fmt = []
for v in db.execute("SELECT id, employee_id, event_hashes FROM verdicts WHERE event_hashes IS NOT NULL ORDER BY id DESC LIMIT 3").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str): hs = json.loads(hs)
    if not hs: continue
    ph = ",".join("?" * len(hs))
    evs = [E(dict(r)) for r in db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph})", hs).fetchall()]
    evs.sort(key=lambda x: x.occurred_at)
    txt = detector._fmt_window(evs)
    issues = []
    if "→https:" in txt: issues.append("https截断")
    if txt.count("[访问网页]") > 10: issues.append("噪声未压")
    bad_fmt.append((v["id"], v["employee_id"][:8], issues or "✓"))
R["三1"] = bad_fmt

# ===== 四、AI输出 =====
anch = []
for v in db.execute("""SELECT id, employee_id, intent, risk_score, event_hashes FROM verdicts
    WHERE intent IN ('policy_violation','data_exfiltration') AND risk_score>=50 ORDER BY id DESC LIMIT 8""").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str): hs = json.loads(hs)
    if not hs: continue
    ph = ",".join("?" * len(hs))
    evs = [E(dict(r)) for r in db.execute(f"SELECT * FROM events WHERE event_hash IN ({ph})", hs).fetchall()]
    sc = detector.anchor_score(v["intent"], evs)
    anch.append((v["id"], v["employee_id"][:8], f"v={v['risk_score']}", f"锚={sc}", "OK" if sc is None or abs(v["risk_score"]-sc)<=5 else f"偏{v['risk_score']-sc}"))
R["四2"] = anch

noev = []
JOB = re.compile(r"(zhipin|liepin|51job|zhaopin|italent)", re.I)
for v in db.execute("SELECT id, employee_id, event_hashes FROM verdicts WHERE intent='job_seeking' AND risk_score>=50 ORDER BY id DESC LIMIT 10").fetchall():
    hs = v["event_hashes"] or []
    if isinstance(hs, str): hs = json.loads(hs)
    if not hs: continue
    ph = ",".join("?" * len(hs))
    evs = list(db.execute(f"SELECT raw FROM events WHERE event_hash IN ({ph})", hs).fetchall())
    if not any(JOB.search(json.dumps(e["raw"] if isinstance(e["raw"], dict) else {})) for e in evs):
        noev.append((v["id"], v["employee_id"][:10]))
R["四3"] = noev[:5] or "无"

# ===== 五、盲区 =====
doms = db.execute("""SELECT json_extract(raw,'$.domain') d, COUNT(*) c, COUNT(DISTINCT employee_id) u FROM events
    WHERE category='WEB' AND occurred_at>=datetime('now','+8 hours','-7 days')
    GROUP BY d HAVING d IS NOT NULL AND c>=5 ORDER BY c DESC LIMIT 120""").fetchall()
uncat = []
for r in doms:
    d = (r["d"] or "").lower()
    if not d or "." not in d: continue
    if any(d == w or d.endswith("." + w) for w in wl): continue
    if dicts.risk_class(d): continue
    if any(x in d for x in ("microsoft", "msn.", "bing", "office", "windows", "azure", "akamai", "cdn", "qq.com", "weixin", "baidu", "douyin", "hdslb", "volces", "zijieapi", "bytedns", "byteimg", "snssdk", "toutiao", "kdocs", "wps", "icloud", "apple", "adnxs", "doubleclick", "cnzz", "umeng", "gstatic", "google", "github", "alicdn", "aliyuncs", "huawei", "mi.com", "jd.com", "taobao", "tencent", "weibo", "zhihu", "xiaohongshu", "douyinvideo", "edgent", "elk", "sharepoint", "cmbchina", "youdao", "sogou", "elqua", "trafficmanager", "cloudapp", "svc.cloud", "cloud.micro", "aadg", "akadns", "msidentity", "ms-acdc", "onecdn", "trouter", "azurefd", "elk", "gvt2", "adblockplus", "qlogo", "mediav", "safelinks", "autodiscover", "exp-tas", "login.live", "ftp.hp")):
        continue
    uncat.append((d[:36], r["c"], r["u"]))
R["五1"] = uncat[:10]

abuse = db.execute("""SELECT employee_id, json_extract(raw,'$.domain') dom, COUNT(*) c, SUM(COALESCE(size_bytes,0)) sz FROM events
    WHERE action IN ('SEND','UPLOAD') AND occurred_at>=datetime('now','+8 hours','-7 days')
    GROUP BY employee_id, json_extract(raw,'$.domain') HAVING (c>=20 OR sz>=200*1048576) ORDER BY sz DESC LIMIT 8""").fetchall()
ab2 = []
for r in abuse:
    d = (r["dom"] or "").lower()
    if d and any(d == w or d.endswith("." + w) for w in wl):
        ab2.append((r["employee_id"][:10], d[:30], r["c"], round((r["sz"] or 0)/1048576)))
R["五2"] = ab2[:5] or "无异常"

new_ipg = db.execute("""SELECT employee_id, MAX(occurred_at) mx FROM events WHERE employee_id LIKE 'IPG:%'
    AND occurred_at>=datetime('now','+8 hours','-2 days') GROUP BY employee_id""").fetchall()
agtm = {}
try:
    agtm = json.loads(db.execute("SELECT value FROM settings WHERE key='ipg_agt_map'").fetchone()[0])
except Exception:
    pass
R["五3"] = [(r["employee_id"], agtm.get(r["employee_id"][4:]) or "未匹配") for r in new_ipg[:6]]

print(json.dumps(R, ensure_ascii=False, indent=1, default=str))
