# -*- coding: utf-8 -*-
"""优化4: 告警分层(优先级字段+webhook门控+前端只看重点)。"""
import io

# ============ api.py: /api/alerts 加 priority ============
p = "backend/api.py"
s = io.open(p, encoding="utf-8").read()

old = '''    s = Session()
    try:
        q = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at))
        if severity:
            q = q.filter(AlertRow.severity == severity)
        if status == "NEW":
            q = q.filter(AlertRow.status == "NEW")
        elif status == "handled":          # CONFIRMED / FP / CLOSED 等一切非 NEW
            q = q.filter(AlertRow.status != "NEW")'''
new = '''    s = Session()
    try:
        # 优先级分层(2026-08-26): 复合信号(同人多场景NEW)≥2类 / ≥85分 /
        # 聚合与模式类(mass_*/archive/rename) / 敏感文件类 → 优先;单次截图/邮箱类 → 常规
        _sig_cnt = {}
        for r2 in s.query(AlertRow.employee_id, AlertRow.scenario).filter(AlertRow.status == "NEW").all():
            _sig_cnt.setdefault(r2[0], set()).add(r2[1])
        q = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at))
        if severity:
            q = q.filter(AlertRow.severity == severity)
        if status == "NEW":
            q = q.filter(AlertRow.status == "NEW")
        elif status == "handled":          # CONFIRMED / FP / CLOSED 等一切非 NEW
            q = q.filter(AlertRow.status != "NEW")'''
assert s.count(old) == 1, "api-prio-pre"
s = s.replace(old, new)

old2 = '''        return [{
            "id": r.id, "employee": r.employee_id, "scenario": r.scenario,
            "severity": r.severity, "risk_score": r.risk_score, "summary": r.summary,
            "status": r.status,
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "verdict_id": r.verdict_id,
        } for r in q.limit(limit).all()]'''
new2 = '''        def _prio(r):
            if r.risk_score >= 85 or r.scenario in ("mass_delete", "mass_exfil", "archive_exfil", "rename_exfil", "trend_spike"):
                return "优先"
            if len(_sig_cnt.get(r.employee_id, ())) >= 2:
                return "优先"
            return "常规"

        return [{
            "id": r.id, "employee": r.employee_id, "scenario": r.scenario,
            "severity": r.severity, "risk_score": r.risk_score, "summary": r.summary,
            "status": r.status, "priority": _prio(r),
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "verdict_id": r.verdict_id,
        } for r in q.limit(limit).all()]'''
assert s.count(old2) == 1, "api-prio-field"
s = s.replace(old2, new2)
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("api priority ✓")

# ============ pipeline.py: webhook 优先门控 ============
p2 = "backend/pipeline.py"
s2 = io.open(p2, encoding="utf-8").read()
old3 = '''                                if v.get("risk_score", 0) >= 75:
                                    _notify_webhook(emp, v.get("risk_score", 0), v.get("explanation", ""))'''
new3 = '''                                # 推送门控(2026-08-26): 单次低价值不推,只推复合/高分/大体量——
                                # 否则单张截图也轰炸webhook
                                _mb2 = sum((e.size_bytes or 0) for e in w
                                           if e.category == "DOC" and e.action in ("SEND", "UPLOAD")) / 1048576
                                if (v.get("risk_score", 0) >= 85
                                        or (v.get("risk_score", 0) >= 75 and _mb2 >= 5)
                                        or v.get("file_sensitivity") == "high"):
                                    _notify_webhook(emp, v.get("risk_score", 0), v.get("explanation", ""))'''
assert s2.count(old3) == 1, "webhook1"
s2 = s2.replace(old3, new3)
old4 = '''                                    if v.get("risk_score", 0) >= 75:
                                        _notify_webhook(f"{emp}(复犯,原状态{_was})", v.get("risk_score", 0),
                                                        v.get("explanation", ""))'''
new4 = '''                                    if v.get("risk_score", 0) >= 85:
                                        _notify_webhook(f"{emp}(复犯,原状态{_was})", v.get("risk_score", 0),
                                                        v.get("explanation", ""))'''
assert s2.count(old4) == 1, "webhook2"
s2 = s2.replace(old4, new4)
io.open(p2, "w", encoding="utf-8", newline="\n").write(s2)
print("webhook门控 ✓")

# ============ 前端: 告警页"只看重点"开关 ============
p3 = "backend/static/index.html"
s3 = io.open(p3, encoding="utf-8").read()

old5 = "  const [scenario,setScenario]=useState((filter&&filter.scenario)||'all');"
new5 = "  const [scenario,setScenario]=useState((filter&&filter.scenario)||'all');\n  const [focusOnly,setFocusOnly]=useState(false);  // 2026-08-26分层: 默认全看,可切只看优先"
assert s3.count(old5) == 1, "fe-state"
s3 = s3.replace(old5, new5)

# 过滤逻辑加focus
old6 = "const filtered=(rows||[]).filter(v=>{if(q&&!(v.employee||'').toLowerCase().includes(q.toLowerCase()))return false;"
new6 = ("const filtered=(rows||[]).filter(v=>{if(focusOnly&&v.priority!=='优先')return false;"
        "if(q&&!(v.employee||'').toLowerCase().includes(q.toLowerCase()))return false;")
assert s3.count(old6) == 1, "fe-filter"
s3 = s3.replace(old6, new6)

# 开关UI: 挂在场景Select旁(找Select结束锚)
old7 = "        {scenSet.length>1&&<Select value={scenario} style={{width:130}} onChange={setScenario}>\n          <Select.Option value=\"all\">全部场景</Select.Option>\n          {scenSet.map(s=><Select.Option key={s} value={s}>{INTENT[s]||s}</Select.Option>)}\n        </Select>}"
new7 = (old7 + "\n        <Tooltip title=\"优先=复合信号(≥2类风险)/高分/聚合模式类;常规=单次截图/邮箱等低价值,点击行仍可查看\">\n"
        "        <Switch checkedChildren=\"只看重点\" unCheckedChildren=\"全部\" checked={focusOnly} onChange={setFocusOnly} />\n        </Tooltip>")
assert s3.count(old7) == 1, "fe-switch"
s3 = s3.replace(old7, new7)

# 行标签: 用户列后加优先Tag(在告警表用户列render里追加)——找告警表用户列
old8 = "{title:<TH t=\"用户\" />,dataIndex:'employee',width:120,render:v=><a className=\"uname\" onClick={(e)=>{e.stopPropagation();goProfile(v);}}>{EMP_D(v)}</a>},"
new8 = ("{title:<TH t=\"用户\" />,dataIndex:'employee',width:150,render:(v,r)=><span>"
        "<a className=\"uname\" onClick={(e)=>{e.stopPropagation();goProfile(v);}}>{EMP_D(v)}</a>"
        "{r.priority==='优先'&&<Tag color=\"volcano\" style={{marginLeft:4,fontSize:10,lineHeight:'16px'}}>优先</Tag>}"
        "</span>},")
assert s3.count(old8) == 1, "fe-tag"
s3 = s3.replace(old8, new8)
io.open(p3, "w", encoding="utf-8", newline="\n").write(s3)
print("前端分层 ✓")
