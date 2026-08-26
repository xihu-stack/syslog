# -*- coding: utf-8 -*-
import io

p = "backend/api.py"
s = io.open(p, encoding="utf-8").read()

i = s.find('if action == "who_risk":')
j = s.find('if action == "attendance":', i)
assert 0 < i < j

new_seg = '''if action == "who_risk":
            # 2026-08-26重写: ①days参数(用户问"今天"时原30天口径冒充今日,黄春煜985次实为30天桶数);
            # ②排除ws./statistic.等心跳遥测桶(展佳的ws.zhipin.com心跳全计入);
            # ③豁免人员标注(HR等岗位需要,非求职风险,不再被建议关注)
            cat_map = {"远程控制": "远程控制", "网盘": "网盘", "邮箱": "个人邮箱", "招聘": "招聘", "文件助手": "微信文件助手"}
            key = next((k for k in cat_map if k in category), None)
            target = cat_map.get(key, category) if key else category
            try:
                days = max(1, min(30, int(days_arg or 30)))
            except Exception:
                days = 30
            rcnt = Counter()
            dom_expr = json_field(EventRow.raw, 'domain')
            _since = bj_now() - timedelta(days=days)
            rows = s.query(EventRow.employee_id, dom_expr).filter(
                EventRow.category == 'WEB', EventRow.occurred_at >= _since).all()
            _HEART = ("ws.", "wss.", "statistic.", "stat.", "log.", "telemetry.", "tm.", "abtest.", "sentry.")
            dom_cache = {}
            for emp_id, dom in rows:
                d = (dom or "").lower()
                if not d or d.startswith(_HEART):
                    continue
                rc = dom_cache.get(d)
                if rc is None:
                    rc = dicts.risk_class(d) or ""
                    dom_cache[d] = rc
                if rc and target and (target in rc or rc in target):
                    rcnt[emp_id] += 1
            if not rcnt:
                return f"近{days}天无人访问{target or '该类'}网站。"
            _sig_map = {"招聘": "job_seeking"}
            _exc_emps = {}
            if target in _sig_map:
                for x in s.query(ExceptionRow).filter(ExceptionRow.signal_type == _sig_map[target]).all():
                    _exc_emps[x.employee_id] = x.reason or "岗位需要"
            lines = []
            for emp, n in rcnt.most_common(20):
                tag = f"(已豁免:{_exc_emps[emp]},岗位需要非求职风险)" if emp in _exc_emps else ""
                lines.append(f"{emp} {n}个活跃时段{tag}")
            tail = "(次数=有活动的10分钟时段数,非请求次数)" if days <= 1 else ""
            return f"近{days}天访问{target}类网站的员工{tail}:" + "\\n" + "\\n".join(lines)
        '''

s = s[:i] + new_seg + s[j:]

# 其余三处(工具描述/提示词/签名/传参)
old1 = '"who_risk": "近30天谁访问了某类风险网站。args: {category: 远程控制|网盘|邮箱|招聘|文件助手}",'
new1 = '"who_risk": "近N天谁访问了某类风险网站(次数=有活动的10分钟时段数,已排除心跳/遥测,豁免人员会标注)。args: {category: 远程控制|网盘|邮箱|招聘|文件助手, days: 可选,默认30;问今天传1,近一周传7}",'
if s.count(old1) == 1:
    s = s.replace(old1, new1)

old2 = "用户可能用任何说法(『跑路』『挖人』『偷偷传文件』『投简历』),你按语义自行映射到对应 intent;"
new2 = ("问『今天/昨天/近一周』等时间范围时,who_risk工具传对应days参数(今天=1,近一周=7),回答里写清统计的是哪天/几天,严禁把30天总数说成今天;"
        "用户可能用任何说法(『跑路』『挖人』『偷偷传文件』『投简历』),你按语义自行映射到对应 intent;")
if s.count(old2) == 1:
    s = s.replace(old2, new2)

old4 = 'def _ask_query(action, employee, category=""):'
if s.count(old4) == 1:
    s = s.replace(old4, 'def _ask_query(action, employee, category="", days_arg=None):')

old5 = 'return _ask_query(name, str(emp), str(cat))'
if s.count(old5) == 1:
    s = s.replace(old5, 'return _ask_query(name, str(emp), str(cat), args.get("days"))')

io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("who_risk整段替换+4处配套 完成")
