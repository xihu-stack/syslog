"""FastAPI 后端：AI 判断/告警/事件/员工/导入/反馈 API + 托管前端静态页。

启动:  python api.py   然后浏览器打开 http://127.0.0.1:8000
"""
import os
import re
import shutil
import tempfile
import hashlib
import secrets
import time as _time

from fastapi import Body, FastAPI, File, HTTPException, UploadFile, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import desc, func

from db import (AlertRow, AskHistoryRow, EventRow, ExceptionRow, FeedbackRow, ProfileRow, RawLogRow, Session, VerdictRow, bj_now, init_db, json_field)
import llm_client
import pipeline
import profiles
import dicts
import syslog_recv

app = FastAPI(title="IP-Guard 员工行为分析")
init_db()

# ---------------- 管理员登录(单账号,密码哈希存 settings,token 内存会话) ----------------
ADMIN_USER = "admin"
INITIAL_PWD = os.environ.get("ADMIN_INITIAL_PWD", "admin123")  # 初始密码,首次登录后请在设置中修改
_TOKENS: dict = {}          # token -> {exp, user, name(显示名), id_token};服务重启需重新登录
_TOKEN_TTL = 7 * 86400
_SSO_STATES: dict = {}      # state -> 过期epoch(10分钟), 授权码流程防CSRF


def _re_cn(s: str) -> bool:
    return any('\u4e00' <= ch <= '\u9fff' for ch in (s or ""))


def _pwd_hash(pwd: str, salt: str) -> str:
    return hashlib.sha256((salt + pwd).encode("utf-8")).hexdigest()


def _ensure_admin():
    """首次启动:生成 salt 并写入初始密码哈希。
    用原生 sqlite INSERT OR IGNORE 保证只初始化、永不覆盖已有凭据
    (旧版"查空则写"在 DB 忙/锁时 get_setting 返回空,会把已改密码误重置)。"""
    import sqlite3 as _s
    import db as _db
    con = _s.connect(_db.DB_PATH, timeout=10)
    try:
        con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
        salt = secrets.token_hex(8)
        con.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('admin_salt', ?)", (salt,))
        real_salt = con.execute("SELECT value FROM settings WHERE key='admin_salt'").fetchone()[0]
        if con.execute("SELECT 1 FROM settings WHERE key='admin_pwd'").fetchone() is None:  # 仅真正首次初始化
            con.execute("INSERT INTO settings (key, value) VALUES ('admin_pwd', ?)",
                        (_pwd_hash(INITIAL_PWD, real_salt),))
            print("[auth] 首次启动:已初始化管理员 admin,初始密码见环境变量(请尽快修改)", flush=True)
        con.commit()
    finally:
        con.close()
        print(f"[auth] 已初始化管理员 {ADMIN_USER},初始密码: {INITIAL_PWD}(请尽快在系统设置中修改)")


_ensure_admin()


def _check_token(auth_header: str | None) -> bool:
    if not auth_header or not auth_header.startswith("Bearer "):
        return False
    t = auth_header[7:]
    rec = _TOKENS.get(t)
    if not rec or rec.get("exp", 0) < _time.time():
        _TOKENS.pop(t, None)
        return False
    return True


@app.middleware("http")
async def _nocache_html(request: Request, call_next):
    """HTML 页面禁用本地缓存(每次协商):部署新版后用户普通刷新即可生效,
    不再需要 ?cb=强刷玄学。静态资源(logo/js)仍走 ETag 协商。"""
    resp = await call_next(request)
    p = request.url.path
    if p == "/" or p.endswith(".html"):
        resp.headers["Cache-Control"] = "no-cache"
    return resp


@app.middleware("http")
async def _auth_guard(request: Request, call_next):
    """API 鉴权:/api/login 放行;其余 /api/* 需带有效 Bearer token;静态页面放行。"""
    p = request.url.path
    if p.startswith("/api") and p != "/api/login" and not p.startswith("/api/auth/"):
        if not _check_token(request.headers.get("authorization")):
            return JSONResponse({"detail": "未登录或会话过期"}, status_code=401)
    return await call_next(request)


_LOGIN_FAILS: dict = {}      # 用户名 -> {"n":连续失败数, "until":锁定截止epoch};防暴力破解


def _login_locked(u: str) -> bool:
    f = _LOGIN_FAILS.get(u)
    return bool(f and f.get("until", 0) > _time.time())


@app.post("/api/login")
def login(body: dict = Body(...)):
    u = (body.get("username") or "").strip()
    p = (body.get("password") or "").strip()
    if _login_locked(u):
        wait = int((_LOGIN_FAILS[u]["until"] - _time.time()) / 60) + 1
        raise HTTPException(429, f"失败次数过多，已锁定，请约 {wait} 分钟后再试")
    if u == ADMIN_USER and _pwd_hash(p, dicts.get_setting("admin_salt")) == dicts.get_setting("admin_pwd"):
        _LOGIN_FAILS.pop(u, None)
        token = secrets.token_hex(16)
        _TOKENS[token] = {"exp": _time.time() + _TOKEN_TTL, "user": u, "id_token": None}
        return {"ok": True, "token": token, "username": u}
    f = _LOGIN_FAILS.setdefault(u, {"n": 0, "until": 0})
    f["n"] += 1
    if f["n"] >= 5:
        f["until"] = _time.time() + 600
        f["n"] = 0
    raise HTTPException(401, "用户名或密码错误")


@app.post("/api/logout")
def logout(request: Request):
    """退出登录:销毁服务端会话 token。SSO会话附带认证中心登出地址(带id_token_hint)。"""
    h = request.headers.get("authorization", "")
    t = h[7:].strip() if h.lower().startswith("bearer ") else ""
    rec = _TOKENS.pop(t, None) if t else None
    out = {"ok": True}
    if rec and rec.get("id_token"):
        base = (dicts.get_setting("sso_base") or "").rstrip("/")
        if base:
            # 坑1: 不带 post_logout_redirect_uri(未登记会400),让门户显示自己的登出页
            out["sso_logout_url"] = f"{base}/connect/logout?id_token_hint={rec['id_token']}"
    return out


# ---------------- 统一身份认证 SSO(OAuth2授权码) ----------------
def _sso_cfg() -> dict:
    return {
        "enabled": dicts.get_setting("sso_enabled", "0") == "1",
        "base": (dicts.get_setting("sso_base") or "").rstrip("/"),
        "client_id": dicts.get_setting("sso_client_id") or "",
        "client_secret": dicts.get_setting("sso_client_secret") or "",
        "redirect_uri": dicts.get_setting("sso_redirect_uri") or "",
        "user_field": dicts.get_setting("sso_username_field") or "preferred_username",
        "whitelist": [x.strip() for x in (dicts.get_setting("sso_whitelist") or "").split(",") if x.strip()],
    }


@app.get("/api/auth/mode")
def auth_mode():
    """登录页公开探测: SSO是否启用(未鉴权,只暴露开关)。"""
    c = _sso_cfg()
    return {"sso_enabled": bool(c["enabled"] and c["base"] and c["client_id"])}


@app.get("/api/auth/sso/start")
def sso_start():
    """生成state并返回授权地址(前端跳转)。state 10分钟有效防CSRF。"""
    c = _sso_cfg()
    if not (c["enabled"] and c["base"] and c["client_id"]):
        raise HTTPException(400, "SSO 未启用或配置不全")
    import urllib.parse as _up0
    state = secrets.token_hex(12)
    _SSO_STATES[state] = _time.time() + 600
    for k in [k for k, v in _SSO_STATES.items() if v < _time.time()]:
        _SSO_STATES.pop(k, None)
    ru = c["redirect_uri"]
    url = (f"{c['base']}/oauth2/authorize?response_type=code&client_id={c['client_id']}"
           f"&redirect_uri={_up0.quote(ru, safe='')}&scope=openid%20profile%20email&state={state}")
    return {"url": url}


@app.get("/api/auth/callback")
def sso_callback(code: str = "", state: str = "", error: str = ""):
    """SSO授权回调: 校验state→换令牌→取用户→白名单→建会话→302回前端。
   坑位对策: id_token必须保留(登出要用,扔掉会返工);用户名字段可配置;
    域账号+姓名反哺用户名映射系统。"""
    import urllib.request as _urq
    import urllib.parse as _up
    import json as _j3  # api.py 无全局json,必须局部导入
    from fastapi.responses import RedirectResponse
    c = _sso_cfg()
    front = c["redirect_uri"].replace("/api/auth/callback", "") or "/"
    if error:
        return RedirectResponse(front + "?sso_error=" + _up.quote(error))
    if not code or not state or _SSO_STATES.pop(state, 0) < _time.time():
        return RedirectResponse(front + "?sso_error=" + _up.quote("state校验失败,请重新登录"))
    try:
        body = _up.urlencode({"grant_type": "authorization_code", "code": code,
                              "redirect_uri": c["redirect_uri"],
                              "client_id": c["client_id"], "client_secret": c["client_secret"]}).encode()
        req = _urq.Request(f"{c['base']}/oauth2/token", data=body,
                           headers={"Content-Type": "application/x-www-form-urlencoded"}, method="POST")
        tok = _j3.loads(_urq.urlopen(req, timeout=15).read().decode())
        at, idt = tok.get("access_token"), tok.get("id_token")
        if not at:
            raise RuntimeError("无access_token")
        req2 = _urq.Request(f"{c['base']}/userinfo", headers={"Authorization": f"Bearer {at}"})
        info = _j3.loads(_urq.urlopen(req2, timeout=15).read().decode())
        username = str(info.get(c["user_field"]) or info.get("preferred_username") or "").strip()
        if not username:
            raise RuntimeError("userinfo无可用户名字段")
        # 坑6第二层: 本系统白名单(防SSO侧配置疏忽全员涌入);域账号名恒放行
        wl = c["whitelist"] or []
        email = str(info.get("email") or "")
        ok_user = username in wl or username == ADMIN_USER
        ok_mail = any(email.endswith(x) for x in wl if x.startswith("@") or "." in x)
        if wl and not (ok_user or ok_mail):
            return RedirectResponse(front + "?sso_error=" + _up.quote(f"用户 {username} 不在访问白名单"))
        token = secrets.token_hex(16)
        # 显示名: 优先中文姓名(name/display_name/nickname),用于顶栏展示
        _disp = ""
        for _k in ("name", "display_name", "nickname"):
            _v = str(info.get(_k) or "").strip()
            if _v and _v != username:
                _disp = _v
                break
        _TOKENS[token] = {"exp": _time.time() + _TOKEN_TTL, "user": username,
                          "name": _disp or username, "id_token": idt}
        # 域账号+中文姓名 反哺用户映射(SSO官方权威对应;从显示名中只提取
        # 连续中文段,防"Chunyuan Zhou 周春远"这类英文名混入污染映射,2026-08-20)
        cname = "".join(__import__("re").findall(r"[一-鿿]+", _disp)) if _disp else ""
        if cname:
            try:
                conf = _alias_load("employee_alias")
                if conf.get(username) != cname:
                    conf[username] = cname
                    import json as _j2
                    dicts.set_setting("employee_alias", _j2.dumps(conf, ensure_ascii=False))
                    _alias_apply(username, cname)
            except Exception:
                pass
        return RedirectResponse(front + "?sso_token=" + token)
    except Exception as e:
        return RedirectResponse(front + "?sso_error=" + _up.quote(f"SSO登录失败: {e}")[:180])


@app.post("/api/auth/logout-notify")
def sso_logout_notify(body: dict = Body(...)):
    """门户反向登出通知(坑3): 门户退出时POST {username, logoutAt},吊销该用户全部本地会话。
    登记地址: {本系统}/api/auth/logout-notify 。"""
    return {"ok": True, "revoked": _revoke_user_tokens(str(body.get("username") or ""))}


def _revoke_user_tokens(username: str) -> int:
    if not username:
        return 0
    dead = [t for t, r in _TOKENS.items() if r.get("user") == username]
    for t in dead:
        _TOKENS.pop(t, None)
    return len(dead)


@app.get("/api/me")
def me(request: Request):
    h = request.headers.get("authorization", "")
    t = h[7:].strip() if h.lower().startswith("bearer ") else ""
    rec = _TOKENS.get(t) or {}
    return {"ok": True, "username": rec.get("user") or ADMIN_USER,
            "display": rec.get("name") or rec.get("user") or ADMIN_USER,
            "sso": bool(rec.get("id_token"))}


@app.post("/api/change_pwd")
def change_pwd(body: dict = Body(...)):
    """修改管理员密码(需已登录;中间件已挡未登录)。"""
    old = (body.get("old") or "").strip()
    new = (body.get("new") or "").strip()
    if len(new) < 6:
        raise HTTPException(400, "新密码至少 6 位")
    salt = dicts.get_setting("admin_salt")
    if _pwd_hash(old, salt) != dicts.get_setting("admin_pwd"):
        raise HTTPException(400, "旧密码不正确")
    # 换 salt 重哈希(改密即废所有旧哈希参照),并踢掉全部现有会话强制重登
    salt2 = secrets.token_hex(8)
    dicts.set_setting("admin_salt", salt2)
    dicts.set_setting("admin_pwd", _pwd_hash(new, salt2))
    _TOKENS.clear()
    return {"ok": True}


# 若上次启用了 syslog，自动恢复监听
_se = dicts.get_setting("syslog_enabled", "0")
print("[startup] syslog_enabled =", _se)
if _se == "1":
    try:
        syslog_recv.start(dicts.get_setting("syslog_host", "0.0.0.0"),
                          int(dicts.get_setting("syslog_port", "8514")))
        print("[startup] syslog 自启成功, enabled =", syslog_recv.status().get("enabled"))
    except Exception as e:
        print("[startup] syslog 自启失败:", e)
    syslog_recv.start_watchdog()  # 兜底: syslog停了自动重启(每60s检查)

FRONTEND_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


# ---------------- 工具 ----------------

# 员工枚举降噪：events.employee_id 里混着设备/网关标识(IP/MAC 地址，如 10.4.245.1)，
# 不是真人。统计"全员/上线/在岗"时必须排除，否则分母被设备撑大，还会把网关列成
# "今日无活动的人"。按 IP/MAC 形状判定为非人(纯事实降噪，留代码、不交给AI判断)。
_NON_PERSON = re.compile(
    r'^(?:'
    r'\d{1,3}(?:\.\d{1,3}){3}'                   # IPv4(设备/网关，如 10.4.245.1)
    r'|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}'     # MAC(冒号)
    r'|[0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5}'     # MAC(连字符)
    r')$')

def _is_person(emp_id) -> bool:
    """employee_id 是否代表真人(排除 IP/MAC 等设备标识)。"""
    return bool(emp_id) and not _NON_PERSON.match((emp_id or "").strip())


def _event_dict(e: EventRow) -> dict:
    return {
        "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
        "employee": e.employee_id, "device": e.device_id,
        "category": e.category, "action": e.action,
        "target_value": e.target_value, "size_bytes": e.size_bytes,
        "source": e.source or "",
        "channel": (e.raw or {}).get("channel"),
        "application": (e.raw or {}).get("application"),
    }


def _verdict_dict(s: Session, r: VerdictRow) -> dict:
    # 批量查事件(原逐 hash 单查=N+1,列表页100 verdicts × 10 hash = 1000 次查询)。一次 in_ 批查。
    hashes = r.event_hashes or []
    events = []
    if hashes:
        ev_map = {e.event_hash: e for e in
                  s.query(EventRow).filter(EventRow.event_hash.in_(hashes[:50])).all()}
        events = [_event_dict(ev_map[h]) for h in hashes if h in ev_map]
    return {
        "id": r.id, "employee": r.employee_id, "device": r.device,
        "window_start": r.window_start.isoformat() if r.window_start else None,
        "window_end": r.window_end.isoformat() if r.window_end else None,
        "intent": r.intent, "deviation": r.deviation, "risk_score": r.risk_score,
        "explanation": r.explanation, "channels": r.channels,
        "ai_participated": bool(r.ai_participated), "events": events,
    }


# ---------------- API ----------------

@app.get("/api/stats")
def stats():
    from datetime import datetime, timedelta
    s = Session()
    try:
        now = bj_now()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        return {
            "events": s.query(EventRow).count(),
            "events_today": s.query(EventRow).filter(EventRow.occurred_at >= today_start).count(),
            "verdicts": s.query(VerdictRow).count(),
            "alerts": s.query(AlertRow).count(),
            "alerts_open": s.query(AlertRow).filter(AlertRow.status != "CLOSED").count(),
            "employees": s.query(EventRow.employee_id).filter(EventRow.occurred_at >= today_start).distinct().count(),
            "employees_cn": sum(1 for r in s.query(EventRow.employee_id)
                                 .filter(EventRow.occurred_at >= today_start).distinct().all()
                                 if r[0] and any('\u4e00' <= c <= '\u9fff' for c in r[0])),
        }
    finally:
        s.close()


@app.get("/api/verdicts")
def list_verdicts(employee: str | None = None, limit: int = 100):
    s = Session()
    try:
        q = s.query(VerdictRow).order_by(desc(VerdictRow.window_start))
        if employee:
            q = q.filter(VerdictRow.employee_id == employee)
        return [_verdict_dict(s, r) for r in q.limit(limit).all()]
    finally:
        s.close()


@app.get("/api/alerts")
def list_alerts(severity: str | None = None, limit: int = 200, when: str | None = None, status: str | None = None):
    """告警列表。when(today/yesterday/week) 与 status(NEW/handled) 在 SQL 层过滤，
    避免按 risk 排序 + limit 时把今日/未处理告警截断（大屏人数与条数曾因此不一致）。"""
    from datetime import timedelta
    s = Session()
    try:
        q = s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at))
        if severity:
            q = q.filter(AlertRow.severity == severity)
        if status == "NEW":
            q = q.filter(AlertRow.status == "NEW")
        elif status == "handled":          # CONFIRMED / FP / CLOSED 等一切非 NEW
            q = q.filter(AlertRow.status != "NEW")
        if when in ("today", "yesterday", "week"):
            _n = bj_now()
            _today = _n - timedelta(hours=_n.hour, minutes=_n.minute, seconds=_n.second, microseconds=_n.microsecond)
            if when == "today":
                q = q.filter(AlertRow.window_start >= _today)
            elif when == "yesterday":
                q = q.filter(AlertRow.window_start >= _today - timedelta(days=1),
                             AlertRow.window_start < _today)
            else:                           # week 近7天
                q = q.filter(AlertRow.window_start >= _today - timedelta(days=7))
        return [{
            "id": r.id, "employee": r.employee_id, "scenario": r.scenario,
            "severity": r.severity, "risk_score": r.risk_score, "summary": r.summary,
            "status": r.status,
            "window_start": r.window_start.isoformat() if r.window_start else None,
            "verdict_id": r.verdict_id,
        } for r in q.limit(limit).all()]
    finally:
        s.close()


@app.get("/api/employees/{emp}")
def employee(emp: str):
    s = Session()
    try:
        p = s.query(ProfileRow).filter_by(employee_id=emp).first()
        evs = (s.query(EventRow).filter_by(employee_id=emp)
               .order_by(desc(EventRow.occurred_at)).limit(50).all())
        # 风险行为: 外发通道/招聘/远程控制域名访问 或 文档写/外发动作(最近300条里筛,取30)
        import detector
        # 风险行为:扫近期 WEB/DOC 事件筛 risk_class。
        # 用 event_hashes 反查更准——先从该员工的 verdicts(已研判过的可疑窗口)取
        # event_hashes,反查出真正被判定为风险的事件;不足再扫最近事件补齐。避免全表扫描,
        # 也避免 limit(300) 漏掉较早的风险访问(招聘/外发可能在几天前)。
        risk_evs = []
        v_hashes = set()
        for vr in s.query(VerdictRow).filter_by(employee_id=emp).order_by(desc(VerdictRow.window_start)).limit(60).all():
            v_hashes.update(vr.event_hashes or [])
        if v_hashes:  # 优先:研判命中的事件(就是 AI 判过的风险行为,最相关)
            for e in s.query(EventRow).filter(EventRow.event_hash.in_(list(v_hashes)[:400])).all():
                dom = (e.raw or {}).get("domain") or ""
                if (e.category == "WEB" and dicts.risk_class(dom)) or \
                   (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                    risk_evs.append(e)
                if len(risk_evs) >= 30:
                    break
        for e in (s.query(EventRow).filter_by(employee_id=emp)  # 补齐:近期事件再扫一轮
                  .order_by(desc(EventRow.occurred_at)).limit(300).all()):
            if len(risk_evs) >= 30:
                break
            dom = (e.raw or {}).get("domain") or ""
            if (e.category == "WEB" and dicts.risk_class(dom)) or \
               (e.category == "DOC" and e.action in detector.WRITE_ACTIONS):
                ev_hash = e.event_hash
                if not any(x.event_hash == ev_hash for x in risk_evs):
                    risk_evs.append(e)
        # 摸鱼会话(与效率榜同口径:工作时段 + 30min gap + 统一时长公式,见 _slack_segments)。
        # 取近14天(时间窗)而非"最近500条"(条数窗:办公事件多的人娱乐事件被挤出窗口→漏会话)。
        from datetime import timedelta as _td
        _since = bj_now() - _td(days=14)
        _se = []
        for e in (s.query(EventRow).filter_by(employee_id=emp)
                  .filter(EventRow.category == "WEB", EventRow.occurred_at >= _since).all()):
            dom = (e.raw or {}).get("domain") or ""
            lab = (e.raw or {}).get("category") or (e.raw or {}).get("app") or ""
            sc = dicts.slack_category(dom, lab)
            if sc and e.occurred_at and _is_work_hours(e.occurred_at):
                _se.append((e.occurred_at, dom, sc))
        _se.sort(key=lambda x: x[0])
        _meta = {}
        for occ, dom, sc in _se:
            _meta.setdefault(occ, []).append((dom, sc))
        sessions = []
        for s_, e_, _sec, stamps in _slack_segments([x[0] for x in _se]):
            _doms, _cats = {}, {}
            for t in stamps:
                for dom, sc in _meta.get(t, []):
                    _doms[dom] = _doms.get(dom, 0) + 1
                    _cats[sc] = _cats.get(sc, 0) + 1
            sessions.append({"start": s_, "end": e_, "duration": int(_sec / 60),
                             "cat": max(_cats, key=_cats.get) if _cats else "",
                             "domains": sorted(_doms, key=_doms.get, reverse=True),
                             "count": len(stamps),
                             # 单事件段=稀疏(碎片闪现/挂机心跳),提示数字为估算上限
                             "sparse": len(stamps) == 1})
        sessions.sort(key=lambda x: -x["duration"])
        vs = (s.query(VerdictRow).filter_by(employee_id=emp)
              .order_by(desc(VerdictRow.window_start)).limit(20).all())
        # 全量分类/来源统计(供画像事件分类/数据来源卡,不用50条样本)
        cat_counts = {c: n for c, n in s.query(EventRow.category, func.count(EventRow.id))
                      .filter(EventRow.employee_id == emp).group_by(EventRow.category).all()}
        src_counts = {src: n for src, n in s.query(EventRow.source, func.count(EventRow.id))
                      .filter(EventRow.employee_id == emp).group_by(EventRow.source).all()}
        # 全量研判统计(不受 vs limit 20 影响,供画像研判次数/最高风险)
        vd_total = s.query(func.count(VerdictRow.id)).filter(VerdictRow.employee_id == emp).scalar() or 0
        vd_max = s.query(func.max(VerdictRow.risk_score)).filter(VerdictRow.employee_id == emp).scalar()
        # 该员工的告警明细(与用户视图'告警N条'同源,供画像对齐展示)
        emp_alerts = s.query(AlertRow).filter(AlertRow.employee_id == emp).order_by(desc(AlertRow.risk_score)).all()
        return {
            "employee": emp,
            "category_counts": cat_counts,
            "source_counts": src_counts,
            "verdict_count": vd_total,
            "max_risk": vd_max,
            "alert_count": len(emp_alerts),
            "alerts": [{"scenario": a.scenario, "severity": a.severity, "risk_score": a.risk_score,
                        "status": a.status, "summary": a.summary,
                        "window_start": a.window_start.isoformat() if a.window_start else None} for a in emp_alerts],
            "profile": p.payload if p else None,
            "profile_summary": (profiles.summarize_for_llm(p.payload) if p else None) or "样本不足，按通用可疑度判断",
            "events": [_event_dict(e) for e in evs],
            "risk_events": [{
                "occurred_at": e.occurred_at.isoformat() if e.occurred_at else None,
                "category": e.category, "action": e.action, "target_value": e.target_value,
                "domain": (e.raw or {}).get("domain") or "",
                "risk_class": dicts.risk_class((e.raw or {}).get("domain") or ""),
                "source": e.source or "",
            } for e in risk_evs],
            "slack_sessions": [{
                "start": ss["start"].isoformat() if ss["start"] else None,
                "end": ss["end"].isoformat() if ss["end"] else None,
                "duration": ss["duration"], "cat": ss["cat"],
                "domains": ss["domains"][:3], "count": ss["count"],
            } for ss in sessions[:20]],
            "verdicts": [{"window_start": v.window_start.isoformat() if v.window_start else None,
                          "intent": v.intent, "risk_score": v.risk_score,
                          "explanation": v.explanation} for v in vs],
        }
    finally:
        s.close()


@app.get("/api/computers")
def computers():
    """用户视图: 按员工标识聚合事件/告警/风险。IP型标识(DHCP动态分配,同一IP不同时期
    可能是不同的人)不作为用户展示——绝不用IP汇聚员工日志(2026-08-19用户红线)。"""
    import re as _re
    from datetime import timedelta as _td_c
    _ip = _re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    s = Session()
    try:
        ev = (s.query(EventRow.employee_id, func.count(EventRow.id), func.max(EventRow.occurred_at))
              .group_by(EventRow.employee_id).all())
        _today = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
        _wk7 = bj_now() - _td_c(days=7)
        vr = {r[0]: r[1] for r in
              s.query(VerdictRow.employee_id, func.max(VerdictRow.risk_score))
              .filter(VerdictRow.window_start >= _wk7).group_by(VerdictRow.employee_id).all()}
        al = {r[0]: r[1] for r in
              s.query(AlertRow.employee_id, func.count(AlertRow.id))
              .filter(AlertRow.window_start >= _wk7).group_by(AlertRow.employee_id).all()}
        et = {r[0]: r[1] for r in
              s.query(EventRow.employee_id, func.count(EventRow.id))
              .filter(EventRow.occurred_at >= _today).group_by(EventRow.employee_id).all()}
        out = [{"computer": e, "event_count": c, "event_count_today": et.get(e, 0),
                "last_seen": (t.isoformat() if t else None),
                "max_risk": vr.get(e), "alert_count": al.get(e, 0)}
               for e, c, t in ev if not _ip.match(e or "")]
        out.sort(key=lambda x: -(x["max_risk"] or 0))
        return out
    finally:
        s.close()


@app.post("/api/ingest")
def ingest(file: UploadFile = File(...)):
    """上传 xlsx/csv → 批量导入 → 建画像 → 异步启动研判（立即返回，前端轮询进度）。
    用 def(非 async)：内部 shutil/ingest_file/build_profiles 都是同步阻塞 IO，async 会
    阻塞事件循环卡住其它请求；FastAPI 把 def 端点丢线程池跑，不阻塞主循环。"""
    suffix = os.path.splitext(file.filename or "")[1] or ".xlsx"
    fd, tmp = tempfile.mkstemp(suffix=suffix)  # 唯一名,避免并发上传互相覆盖
    os.close(fd)
    try:
        with open(tmp, "wb") as f:
            shutil.copyfileobj(file.file, f)
        n = pipeline.ingest_file(tmp)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    profiles.build_profiles()
    st = pipeline.start_detection()  # 单飞异步研判，不阻塞请求
    return {"imported": n, "detection": st}


@app.post("/api/run")
def run():
    """对库内已有事件异步启动研判（单飞）。"""
    profiles.build_profiles()
    return pipeline.start_detection()


@app.get("/api/detect/status")
def detect_status():
    """轮询研判进度。"""
    return pipeline.detection_status()


@app.get("/api/exceptions")
def list_exceptions():
    """查询豁免列表（已确认正常的用户行为）。"""
    from datetime import datetime
    s = Session()
    try:
        rows = s.query(ExceptionRow).filter(
            (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > datetime.utcnow())
        ).all()
        return [{"id": r.id, "employee": r.employee_id, "signal_type": r.signal_type,
                 "reason": r.reason, "expires_at": r.expires_at.isoformat() if r.expires_at else None}
                for r in rows]
    finally:
        s.close()


@app.delete("/api/exceptions/{eid}")
def delete_exception(eid: int):
    """删除豁免（恢复告警）。"""
    s = Session()
    try:
        r = s.get(ExceptionRow, eid)
        if r:
            s.delete(r)
            s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.get("/api/dayreview")
def dayreview_get():
    """N+1日复核结果(最近一轮)。"""
    import json as _js
    try:
        return {"reviews": _js.loads(dicts.get_setting("day_reviews") or "{}")}
    except Exception:
        return {"reviews": {}}


@app.post("/api/dayreview/run")
def dayreview_run():
    from dayreview import run_day_review
    return run_day_review()


@app.post("/api/weekly/gen")
def weekly_gen():
    from weekly import gen_weekly
    return gen_weekly()


@app.get("/api/weekly")
def weekly_get():
    import json as _js
    try:
        return {"report": _js.loads(dicts.get_setting("weekly_report") or "{}")}
    except Exception:
        return {"report": {}}


@app.get("/api/employees/{emp}/export")
def profile_export(emp: str):
    from weekly import export_profile_csv
    from fastapi.responses import Response
    csv_data = export_profile_csv(emp)
    return Response(content=csv_data, media_type="text/csv",
                    headers={"Content-Disposition": f"attachment; filename=profile_{emp}.csv"})


@app.get("/api/night-workers")
def night_workers_api():
    from weekly import night_worker_list
    return {"workers": night_worker_list()}


@app.get("/api/cross-files")
def cross_files_api():
    from weekly import cross_person_files
    return {"files": cross_person_files()}


@app.get("/api/risk-board")
def risk_board_api():
    """离职综合风险榜: 多信号组合→单人一分数(程序化,无LLM,秒出)。"""
    from riskboard import risk_board as _rb
    return {"board": _rb()}


@app.get("/api/employees/{emp}/timeline")
def employee_timeline_api(emp: str, days: int = 7):
    """行为时间线: WEB+DOC+SEARCH按时间混排(以人为中心的核心视图)。"""
    from timeline import employee_timeline
    return {"timeline": employee_timeline(emp, days=days)}


@app.get("/api/search")
def global_search(q: str = "", limit: int = 20):
    """全局搜索: 人名/域名/文件名。"""
    import re as _re_s
    from datetime import timedelta
    if not q.strip():
        return {"results": []}
    ql = q.strip().lower()
    s = Session()
    try:
        results = []
        # 搜人
        emps = {r[0] for r in s.query(EventRow.employee_id).distinct().all() if r[0] and ql in r[0].lower()}
        for e in sorted(emps)[:limit]:
            n = s.query(EventRow).filter(EventRow.employee_id == e,
                                          EventRow.occurred_at >= bj_now() - timedelta(days=7)).count()
            results.append({"type": "person", "value": e, "label": f"员工 · 近7天{n}条事件"})
        # 搜域名
        if "." in ql:
            doms = s.query(EventRow.raw).filter(
                EventRow.category == "WEB",
                EventRow.occurred_at >= bj_now() - timedelta(days=7)).limit(5000).all()
            dom_set = set()
            for (raw,) in doms:
                d = ((raw or {}).get("domain") or "").lower()
                if d and ql in d:
                    dom_set.add(d)
            for d in sorted(dom_set)[:limit]:
                rc = dicts.risk_class(d)
                results.append({"type": "domain", "value": d,
                                "label": f"域名 · {rc or '正常'}"})
        # 搜文件名
        if len(ql) >= 3:
            files = s.query(EventRow).filter(
                EventRow.category == "DOC",
                EventRow.occurred_at >= bj_now() - timedelta(days=7),
                EventRow.target_value.ilike(f"%{q.strip()}%")).limit(limit).all()
            for e in files[:limit]:
                results.append({"type": "file", "value": (e.target_value or "")[:60],
                                "label": f"文件 · {e.employee_id} {e.action} · {e.occurred_at.strftime('%m-%d %H:%M')}"})
        return {"results": results[:limit * 2]}
    finally:
        s.close()


@app.get("/api/stories")
def stories_get():
    """风险故事线(近30天,R1生成)。"""
    import json as _js
    try:
        return {"stories": _js.loads(dicts.get_setting("risk_stories") or "{}")}
    except Exception:
        return {"stories": {}}


@app.post("/api/stories/run")
def stories_run():
    from storyline import build_stories
    return build_stories()


@app.post("/api/massops")
def massops_run():
    """行为聚合扫描(大量删除=离职前兆),手动触发。"""
    from massops import scan_mass_deletes
    return scan_mass_deletes()


@app.post("/api/docscan")
def docscan_run():
    """IPG文档行为AI深扫(R1,手动触发;维护任务每周自动)。"""
    from docscan import run_doc_scan
    return run_doc_scan()


@app.post("/api/rejudge")
def rejudge():
    """清空旧研判 + 重置水位，全量重研判（修复模型/prompt 后重跑）。"""
    return pipeline.rejudge_all()


@app.post("/api/feedback")
def feedback(alert_id: int, label: str, reason: str = "", signal_type: str = "", expires_days: int = 0):
    """标记告警 TP/FP。FP 可带原因+信号类型创建豁免（下次同类不再告警）。"""
    if label not in ("TP", "FP"):
        raise HTTPException(400, "label 必须是 TP 或 FP")
    from datetime import datetime, timedelta
    from db import ExceptionRow
    s = Session()
    try:
        # 先校验告警存在再写 FeedbackRow，避免写出指向不存在 alert_id 的孤儿反馈
        a = s.get(AlertRow, alert_id)
        if not a:
            raise HTTPException(404, f"告警 {alert_id} 不存在")
        s.add(FeedbackRow(alert_id=alert_id, label=label, reason=reason))
        a.status = "CONFIRMED" if label == "TP" else "FP"
        if label == "FP" and signal_type:
            exp = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
            s.add(ExceptionRow(employee_id=a.employee_id, signal_type=signal_type,
                               reason=reason, expires_at=exp))
        s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.put("/api/alerts/{alert_id}/status")
def update_alert_status(alert_id: int, status: str = "TRIAGING"):
    """更新告警状态：NEW/TRIAGING/CONFIRMED/FP/CLOSED。"""
    if status not in ("NEW", "TRIAGING", "CONFIRMED", "FP", "CLOSED"):
        raise HTTPException(400, "无效状态")
    s = Session()
    try:
        a = s.get(AlertRow, alert_id)
        if not a:
            raise HTTPException(404, "告警不存在")
        a.status = status
        s.commit()
        return {"ok": True, "status": status}
    finally:
        s.close()


@app.post("/api/verdicts/{vid}/confirm")
def verdict_confirm(vid: int, reason: str = ""):
    """通过研判ID标记已知晓(自动找到对应alert);reason=备注(可空),留痕到feedback。
    已知晓=纯状态标记:不写豁免、不影响研判和复犯提醒(告警非事故,无需"确认"处置,
    2026-08-19用户语义:只有误报才影响系统)。"""
    s = Session()
    try:
        a = s.query(AlertRow).filter_by(verdict_id=vid).first()
        if not a:
            # verdict_id会随再犯指向最新研判,老研判找不到时按员工+意图兜底(2026-08-18自查)
            v0 = s.query(VerdictRow).get(vid)
            if v0:
                a = s.query(AlertRow).filter_by(employee_id=v0.employee_id, scenario=v0.intent).first()
        if not a:
            return {"ok": False, "error": "未找到对应告警"}
        a.status = "CONFIRMED"
        s.add(FeedbackRow(alert_id=a.id, label="TP", reason=reason or "已知晓"))
        s.commit()
        return {"ok": True}
    finally:
        s.close()


@app.post("/api/verdicts/{vid}/false_positive")
def verdict_false_positive(vid: int, reason: str = "误报", signal_type: str = "", expires_days: int = 0):
    """通过研判ID标记误报 + 创建豁免。"""
    from datetime import datetime, timedelta
    from db import ExceptionRow
    s = Session()
    try:
        a = s.query(AlertRow).filter_by(verdict_id=vid).first()
        if not a:
            v0 = s.query(VerdictRow).get(vid)
            if v0:
                a = s.query(AlertRow).filter_by(employee_id=v0.employee_id, scenario=v0.intent).first()
        if not a:
            return {"ok": False, "error": "未找到对应告警"}
        a.status = "FP"
        s.add(FeedbackRow(alert_id=a.id, label="FP", reason=reason))
        if signal_type:
            exp = datetime.utcnow() + timedelta(days=expires_days) if expires_days > 0 else None
            s.add(ExceptionRow(employee_id=a.employee_id, signal_type=signal_type,
                               reason=reason, expires_at=exp))
        s.commit()
        return {"ok": True}
    finally:
        s.close()


# ---------------- 字典配置（后台可增删改）----------------
@app.get("/api/dicts")
def get_dicts():
    return dicts.all_dicts()

@app.put("/api/dicts/{name}")
def update_dict(name: str, values: list = Body(...)):
    if name not in dicts.DEFAULTS:
        raise HTTPException(400, f"未知字典: {name}")
    dicts.set_dict(name, values)
    return {"ok": True, "name": name, "count": len(values)}


# ---------------- 应用配置（LLM / Syslog，后台在线修改）----------------
@app.get("/api/config")
def get_config():
    base = dicts.get_setting("llm_base_url") or os.environ.get("LLM_BASE_URL", "")

    def mask(k):
        return (k[:6] + "***" + k[-4:]) if k and len(k) > 12 else ("***" if k else "")

    qk = dicts.get_setting("llm_qwen_key") or os.environ.get("LLM_QWEN_KEY") or os.environ.get("LLM_API_KEY", "")
    dk = dicts.get_setting("llm_deepseek_key") or os.environ.get("LLM_DEEPSEEK_KEY", "")
    return {
        "llm_base_url": base,
        "llm_active": dicts.get_setting("llm_active", "qwen"),
        "qwen": {"model": dicts.get_setting("llm_qwen_model") or os.environ.get("LLM_QWEN_MODEL", "Qwen3-32B"),
                 "key_masked": mask(qk), "has_key": bool(qk)},
        "deepseek": {"model": dicts.get_setting("llm_deepseek_model") or os.environ.get("LLM_DEEPSEEK_MODEL", "deepseek"),
                     "base_url": dicts.get_setting("llm_deepseek_base_url") or "",
                     "key_masked": mask(dk), "has_key": bool(dk)},
        "syslog_enabled": dicts.get_setting("syslog_enabled", "0"),
        "syslog_host": dicts.get_setting("syslog_host", "0.0.0.0"),
        "syslog_port": dicts.get_setting("syslog_port", "8514"),
        "notify_webhook": dicts.get_setting("notify_webhook", ""),
        "retention_days": dicts.get_setting("retention_days", "90"),
        "raw_logs_retention_days": dicts.get_setting("raw_logs_retention_days", "7"),
        "llm_ask_model": dicts.get_setting("llm_ask_model", ""),
        "sso_enabled": dicts.get_setting("sso_enabled", "0"),
        "sso_base": dicts.get_setting("sso_base", ""),
        "sso_client_id": dicts.get_setting("sso_client_id", ""),
        "sso_redirect_uri": dicts.get_setting("sso_redirect_uri", ""),
        "sso_username_field": dicts.get_setting("sso_username_field", "preferred_username"),
        "sso_whitelist": dicts.get_setting("sso_whitelist", ""),
        "has_sso_secret": bool(dicts.get_setting("sso_client_secret")),
        "llm_smart_model": dicts.get_setting("llm_smart_model", ""),
    }


@app.put("/api/config")
def set_config(body: dict = Body(...)):
    for k in ("llm_base_url", "llm_active", "llm_qwen_model", "llm_deepseek_model",
              "llm_deepseek_base_url", "syslog_enabled", "syslog_host", "syslog_port", "notify_webhook",
              "retention_days", "raw_logs_retention_days", "llm_ask_model", "llm_smart_model",
              "sso_enabled", "sso_base", "sso_client_id", "sso_redirect_uri", "sso_username_field", "sso_whitelist"):
        if body.get(k) is not None:
            dicts.set_setting(k, str(body[k]))
    if body.get("sso_client_secret"):
        dicts.set_setting("sso_client_secret", body["sso_client_secret"])
    if body.get("qwen_key"):
        dicts.set_setting("llm_qwen_key", body["qwen_key"])
    if body.get("deepseek_key"):
        dicts.set_setting("llm_deepseek_key", body["deepseek_key"])
    return {"ok": True}


@app.post("/api/syslog/start")
def syslog_start():
    host = dicts.get_setting("syslog_host", "0.0.0.0")
    port = int(dicts.get_setting("syslog_port", "8514"))
    syslog_recv.start(host, port)
    dicts.set_setting("syslog_enabled", "1")
    return syslog_recv.status()


@app.post("/api/syslog/stop")
def syslog_stop():
    syslog_recv.stop()
    dicts.set_setting("syslog_enabled", "0")
    return syslog_recv.status()


@app.get("/api/syslog/status")
def syslog_status():
    return syslog_recv.status()


@app.get("/api/system/stats")
def system_stats():
    """系统运行状态：日志量/研判量/数据来源/告警状态/管线健康 + 空间/AI性能。"""
    from datetime import datetime, timedelta, timezone
    import shutil as _sh
    import db as _db
    # ---- 资源/AI 性能采集(系统健康页) ----
    health = {}
    try:
        _du = _sh.disk_usage(os.path.dirname(_db.DB_PATH) or "/")
        health["disk"] = {"total_gb": round(_du.total / 2**30, 1), "free_gb": round(_du.free / 2**30, 1),
                          "used_pct": round((_du.total - _du.free) / _du.total * 100, 1)}
    except Exception:
        pass
    try:
        with open("/proc/meminfo") as _f:
            _mi = {l.split(":")[0]: int(l.split()[1]) for l in _f if ":" in l}
        health["mem_avail_gb"] = round(_mi.get("MemAvailable", 0) / 1048576, 1)
        health["mem_total_gb"] = round(_mi.get("MemTotal", 0) / 1048576, 1)
        with open("/proc/loadavg") as _f:
            health["load1"] = float(_f.read().split()[0])
    except Exception:
        pass
    try:
        _wal = _db.DB_PATH + "-wal"
        health["db_total_mb"] = round((os.path.getsize(_db.DB_PATH) +
                                       (os.path.getsize(_wal) if os.path.exists(_wal) else 0)) / 1048576, 1)
    except Exception:
        pass
    health["ai"] = llm_client.stats()
    from datetime import datetime, timedelta, timezone
    from sqlalchemy import func as _f
    s = Session()
    try:
        now = bj_now()
        today_start = (now - timedelta(hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond))
        yesterday_start = today_start - timedelta(days=1)
        week_start = today_start - timedelta(days=7)

        # 按来源统计：今日/昨日/近7天/总量
        def src_count(since):
            # source=''（历史遗留未标来源，实为深信服上网日志）与 'sangfor' 合并为一组，
            # 否则 r[0] or "sangfor" 会让两者落到同一 dict key、后者覆盖前者，丢掉空来源那批数。
            src_expr = _f.coalesce(_f.nullif(EventRow.source, ""), "sangfor")
            rows = s.query(src_expr, _f.count(EventRow.id)).filter(
                EventRow.occurred_at >= since).group_by(src_expr).all()
            return {r[0]: r[1] for r in rows}

        src_today = src_count(today_start)
        src_yesterday = src_count(yesterday_start)
        src_week = src_count(week_start)
        src_total = src_count(datetime(2000, 1, 1))

        # 事件量
        ev_today = sum(src_today.values())
        ev_yesterday = sum(src_yesterday.values())
        ev_week = sum(src_week.values())
        ev_total = s.query(EventRow).count()

        # 研判量（今日/昨日/总量）—— "今日"按 window_start（行为时间）计，
        # 与告警同源、与研判页 isToday 过滤一致，避免 created_at（判定写入时间）跨天漂移。
        vd_today = s.query(VerdictRow).filter(VerdictRow.window_start >= today_start).count()
        vd_yesterday = s.query(VerdictRow).filter(
            VerdictRow.window_start >= yesterday_start,
            VerdictRow.window_start < today_start
        ).count()
        vd_total = s.query(VerdictRow).count()
        vd_ai = s.query(VerdictRow).filter(VerdictRow.ai_participated == 1).count()
        vd_fallback = s.query(VerdictRow).filter(VerdictRow.ai_participated == 0).count()

        # 告警（今日/昨日/总量）
        al_today = s.query(AlertRow).filter(AlertRow.window_start >= today_start).count()
        al_yesterday = s.query(AlertRow).filter(
            AlertRow.window_start >= yesterday_start,
            AlertRow.window_start < today_start
        ).count()
        al_total = s.query(AlertRow).count()
        st_rows = s.query(AlertRow.status, _f.count(AlertRow.id)).group_by(AlertRow.status).all()
        alert_status = {r[0]: r[1] for r in st_rows}
        # 今日告警涉及人数（distinct employee，window_start 今日）—— 与条数同源，
        # 供大屏"涉及 N 人"。不再由前端从有限(risk 排序 limit)列表推算，避免被截断。
        al_today_people = s.query(_f.count(_f.distinct(AlertRow.employee_id))).filter(
            AlertRow.window_start >= today_start).scalar() or 0
        # 今日严重告警(76+)条数——供大屏"今日严重告警"N 值。SQL 层计数，避免前端从
        # risk 排序 limit 的样本推算、超过样本量时漏算。
        al_today_critical = s.query(AlertRow).filter(
            AlertRow.window_start >= today_start, AlertRow.risk_score >= 76).count()
        # 告警按场景分布(全量 group_by，无 risk 排序截断)——供大屏饼图，避免前端用
        # risk 排序 limit 样本导致高风险场景被系统性放大。
        al_by_scenario = {r[0] or "未识别": r[1] for r in
            s.query(AlertRow.scenario, _f.count(AlertRow.id)).group_by(AlertRow.scenario).all()}

        # 豁免(expires_at 按 naive UTC 写入,这里同源比较;用 timezone-aware 再剥离 tz,
        # 避免 utcnow() 在 Py3.12 的 DeprecationWarning 刷日志)
        _utc_now = datetime.now(timezone.utc).replace(tzinfo=None)
        ex_count = s.query(ExceptionRow).filter(
            (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > _utc_now)
        ).count()
        # 事件保留期(天)——供前端"系统健康"卡展示真实配置，而非写死 90
        retention_days = int(dicts.get_setting("retention_days", "90"))

        # 数据库大小
        import os as _os
        db_path = _os.path.join(_os.path.dirname(__file__), "data", "ipguard.db")
        db_size = _os.path.getsize(db_path) if _os.path.exists(db_path) else 0

        # 去重/降噪统计（总事件中WEB事件比例，估算降噪效果）
        web_total = s.query(EventRow).filter(EventRow.category == "WEB").count()

        # 画像上次全量重建时间（as_of 存的是 utcnow naive UTC，转 epoch 供前端算"X分钟前"）
        _lp = s.query(_f.max(ProfileRow.as_of)).scalar()
        profile_updated_ts = int(_lp.replace(tzinfo=timezone.utc).timestamp()) if _lp else None

        # 告警日趋势(近7天 [date, count])
        _day = {}
        for _i in range(6, -1, -1):
            _dk = (bj_now() - timedelta(days=_i)).date().isoformat()
            _day[_dk] = 0
        # 过滤下界与上方 _day 的 key 对齐：key 是"今天自然日往前 6 天"，
        # 下界也用 today_start-6d（最老一天 00:00），否则最老一柱只有[此刻,23:59]的数据，系统性偏低。
        # 口径分两段(2026-08-19 与KPI对齐):
        # - 历史柱(昨天及以前): 按created_at(首次产生,不变)锁定——window_start会被再犯刷新,
        #   用它分组等于把历史告警搬到今天,昨天的柱子会掉数;
        # - 今天的柱: 按window_start(今日活跃,含再犯刷新)实时——与KPI'今日告警'完全一致,
        #   避免同屏'今日6 vs 趋势2'的自相矛盾(今天的态势本就还在变化中)。
        for _r in s.query(AlertRow).filter(AlertRow.created_at >= today_start - timedelta(days=6)).all():
            if _r.created_at:
                _k = _r.created_at.date().isoformat()
                if _k in _day:
                    _day[_k] += 1
        _today_key = today_start.date().isoformat()
        _day[_today_key] = s.query(AlertRow).filter(AlertRow.window_start >= today_start).count()  # 今日活跃=KPI口径
        alerts_by_day = list(_day.items())

        # TOP活跃风险(2026-08-20终版): 直接从未处理(NEW)告警派生,与告警页完全同源
        # ——此前从研判计算,告警已删的孤儿研判(叶珂祯等3人)带着空summary混进TOP;
        # 分数取该员工该场景最新告警级研判(告警分口径),同分按场景优先级: 求职>外发>其他
        _PRIO = {"job_seeking": 0, "data_exfiltration": 1}
        _a7 = bj_now() - timedelta(days=7)
        _new_alerts = s.query(AlertRow).filter(AlertRow.status == "NEW").all()
        _agg = {}
        for _a in _new_alerts:
            _ws = _a.window_start.isoformat() if _a.window_start else ''
            k = _a.employee_id
            if k not in _agg or _ws > _agg[k]['latest']:
                _agg[k] = {'employee': k, 'scenario': _a.scenario, 'risk_score': _a.risk_score,
                           'status': _a.status, 'latest': _ws, 'summary': _a.summary or ''}
        top_active = sorted(_agg.values(),
                            key=lambda x: (-(x['risk_score'] or 0), -len(x.get('signals') or set()), _PRIO.get(x['scenario'], 2)))[:10]
        return {
            "events": {
                "today": ev_today, "yesterday": ev_yesterday, "week": ev_week, "total": ev_total,
                "web_ratio": round(web_total / max(ev_total, 1) * 100, 1),
                "emp_yesterday": s.query(EventRow.employee_id).filter(
                    EventRow.occurred_at >= yesterday_start,
                    EventRow.occurred_at < today_start
                ).distinct().count(),
            },
            "sources": {
                "today": src_today, "yesterday": src_yesterday, "week": src_week, "total": src_total,
            },
            "verdicts": {
                "today": vd_today, "yesterday": vd_yesterday, "total": vd_total, "ai": vd_ai, "fallback": vd_fallback,
            },
            "alerts": {
                "today": al_today, "yesterday": al_yesterday, "total": al_total,
                "today_people": al_today_people,
                "today_new": s.query(AlertRow).filter(AlertRow.window_start >= today_start,
                                                       AlertRow.status == "NEW").count(),
                "crit_new_total": s.query(AlertRow).filter(
                    AlertRow.risk_score >= 76, AlertRow.status == "NEW").count(),
                "today_by_scenario": {r[0] or "未识别": r[1] for r in
                s.query(AlertRow.scenario, _f.count(AlertRow.id))
                .filter(AlertRow.window_start >= today_start)
                .group_by(AlertRow.scenario).all()},
            "today_status": {r[0]: r[1] for r in
                s.query(AlertRow.status, _f.count(AlertRow.id))
                .filter(AlertRow.window_start >= today_start)
                .group_by(AlertRow.status).all()}, "today_critical": al_today_critical,
                "by_scenario": al_by_scenario, "status": alert_status,
                "list": [{
                    "employee": r.employee_id, "scenario": r.scenario,
                    "risk_score": r.risk_score, "status": r.status, "summary": r.summary,
                    "window_start": r.window_start.isoformat() if r.window_start else None,
                } for r in s.query(AlertRow).order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(50).all()],
            },
            "exceptions": ex_count,
            "db_size_mb": round(db_size / 1024 / 1024, 1),
            "health": health,
            "employees": s.query(EventRow.employee_id).filter(EventRow.occurred_at >= today_start).distinct().count(),
            "employees_cn": sum(1 for r in s.query(EventRow.employee_id)
                                 .filter(EventRow.occurred_at >= today_start).distinct().all()
                                 if r[0] and any('\u4e00' <= c <= '\u9fff' for c in r[0])),
            "employees_total": s.query(EventRow.employee_id).distinct().count(),
            "retention_days": retention_days,
            "detect": pipeline.detection_status(),
            "syslog": syslog_recv.status(),
            "profile_updated_ts": profile_updated_ts,
            "alerts_by_day": alerts_by_day,
            "top_active": top_active,
        }
    finally:
        s.close()


_eff_cache = {"data": None, "ts": 0}
_eff_summary_cache = {"data": None, "ts": 0}

# ---------- 摸鱼口径(全站唯一实现,效率榜/画像页/AI问答/AI总结共用) ----------
def _is_work_hours(t) -> bool:
    """工作时段 9-12, 14-18(排除午休);摸鱼统计一律只算工作时段。"""
    return 9 <= t.hour < 12 or 14 <= t.hour < 18


def _slack_segments(stamps):
    """娱乐访问时间戳列表 → 摸鱼段 [(start, end, seconds, 段内时间戳列表)]。
    事件入库前已按 用户×域名×10分钟桶 聚合,行数≈访问桶数:
        段时长 = max(min(首末跨度, 桶数×10min), 5min)
      - 连续观看: 跨度≈桶数×10 → 取跨度
      - 碎片闪现(2次隔28min): 被桶数封顶为 2×10=20min,不再按跨度虚高
      - 单次访问(跨度0): 保底5min,不再算0分钟
    同天内 gap≤15min 连段;跨天独立。
    日封顶: 每天摸鱼总时长不超过420分钟(7小时工作制的物理上限,
    2026-08-21审计发现夏玮日均774分钟=184%占比,明显不可能)。"""
    from collections import defaultdict as _dd

    def _mk(s, e, ts):
        span = (e - s).total_seconds()
        return (s, e, max(min(span, len(ts) * 600), 300), ts)

    by_day = _dd(list)
    for t in stamps:
        by_day[t.date()].append(t)
    segs = []
    for _, ts in by_day.items():
        ts.sort()
        s = e = None
        bucket = []
        day_segs = []
        for t in ts:
            if e is not None and (t - e).total_seconds() <= 900:
                e = t
                bucket.append(t)
            else:
                if e is not None:
                    day_segs.append(_mk(s, e, bucket))
                s, e, bucket = t, t, [t]
        if e is not None:
            day_segs.append(_mk(s, e, bucket))
        # 日封顶: 每天摸鱼≤420分钟(7小时),超出截断
        day_total = sum(x[2] for x in day_segs)
        if day_total > 25200:  # 420min = 25200s
            ratio = 25200 / day_total
            day_segs = [(s2, e2, int(sec * ratio), ts2) for s2, e2, sec, ts2 in day_segs]
        segs.extend(day_segs)
    return segs


@app.get("/api/efficiency")
def efficiency():
    """工作效率统计: 每员工工作时段(9-12,14-18 排除午休)访问构成(摸鱼/工作)+在岗天数/时段。"""
    import time
    if _eff_cache["data"] is not None and time.time() - _eff_cache["ts"] < 60:
        return _eff_cache["data"]
    from collections import Counter
    from datetime import timedelta
    s = Session()
    try:
        # 只扫近 7 天(效率分析看近期,不必全量历史)。原全量 98 万行→约 30 万行,
        # 冷启动从 30s 降到数秒。性能:SQL 直接抽 domain(免 ORM 水合逐行 JSON 解析),
        # 域名分类按 distinct 域名缓存(数千个)。
        # 窗口=自然日口径(今天0点往前7个日历日,含今天),避免168h跨出8个日历日
        _n = bj_now()
        since = (_n - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)
        dom_expr = json_field(EventRow.raw, 'domain')
        lab_expr = func.coalesce(json_field(EventRow.raw, 'category'), json_field(EventRow.raw, 'app'), '')
        rows = s.query(EventRow.employee_id, EventRow.occurred_at, EventRow.count, dom_expr, lab_expr).filter(
            EventRow.category == "WEB", EventRow.occurred_at >= since).all()
        _ipre = __import__("re").compile(r"^\d{1,3}(\.\d{1,3}){3}$")
        emp = {}
        dom_cache = {}
        for emp_id, occ, cnt, dom, lab in rows:
            if _ipre.match(emp_id or ""):
                continue  # IP型标识(DHCP动态): 不作为员工进效率榜,防换租后把别人行为算到人头上
            r = emp.setdefault(emp_id, {"wh": 0, "slack": 0, "work": 0, "cats": Counter(),
                                        "days": set(), "hours": set(), "stimes": [], "cat_times": {}})
            if occ:
                r["hours"].add(occ.hour)
                if _is_work_hours(occ):          # 活跃天数只计工作时段在岗日,深夜/周末加班不稀释日均
                    r["days"].add(occ.date())
            d = dom or ""
            key = (d, lab or "")
            if key not in dom_cache:
                cat = dicts.slack_category(d, lab or "")
                dom_cache[key] = (cat, (not cat and not dicts.risk_class(d) and bool(dicts.work_category(d))))
            cat, is_work = dom_cache[key]
            # 只统计工作时段(9-12,14-18,排除午休)的访问构成;非工时事件仅计入在岗天数/时段
            if occ and (9 <= occ.hour < 12 or 14 <= occ.hour < 18):
                c = cnt or 1
                r["wh"] += c
                if cat:
                    r["slack"] += c; r["cats"][cat] += c; r["stimes"].append(occ)
                    r["cat_times"].setdefault(cat, []).append(occ)
                elif is_work:
                    r["work"] += c
        out = []
        for k, r in emp.items():
            hours = sorted(r["hours"])
            # 统一摸鱼时长口径(见 _slack_segments):桶数封顶防碎片虚高,保底5min防单次=0
            segs = _slack_segments(r["stimes"])
            total_min = sum(x[2] for x in segs) / 60.0
            # 各娱乐类别也按时长口径(分钟)——次数口径会系统性低估视频类(开一页挂几小时,请求少)
            cat_mins = {cat: round(sum(x[2] for x in _slack_segments(ts)) / 60.0)
                        for cat, ts in r["cat_times"].items()}
            # 碎片度: 单事件段占比高(≥70%且段数≥8)=稀疏上报模式(碎片闪现/挂机心跳),
            # 时长是保底值堆出来的估算上限,前端标记提示复核(防线:心跳污染自动预警)
            single = sum(1 for x in segs if len(x[3]) == 1)
            sparse = len(segs) >= 8 and single / len(segs) >= 0.7
            day_tot = {}
            for s_, _, sec, _ in segs:
                day_tot[s_.date()] = day_tot.get(s_.date(), 0) + sec
            mx = max(day_tot.values(), default=0.0)  # 单日摸鱼累计
            active_days = len(r["days"]) or 1
            slack_avg = round(total_min / active_days)  # 日均摸鱼分钟(total_min已是分钟)
            wh = r["wh"]
            # 摸鱼占比=时长口径: 摸鱼总时长 ÷ (工作日在岗天数×7小时工时)。
            # 旧次数口径(slack/wh)对视频类严重失真(看一天视频占比1-2%,与日均时长自相矛盾)
            pct = round(min(total_min / (active_days * 420) * 100, 100), 1)
            out.append({"employee": k, "total": wh, "slack": r["slack"],
                        "pct": pct,
                        "cats": cat_mins, "active_days": len(r["days"]),
                        "hour_min": hours[0] if hours else None, "hour_max": hours[-1] if hours else None,
                        "slack_avg": slack_avg, "max_span": round(mx / 60), "work": r["work"],
                        "sparse": sparse,
                        "work_pct": round(r["work"] / wh * 100, 1) if wh else 0,
                        "classified": r["slack"] + r["work"]})
        out.sort(key=lambda x: -(x.get("slack_avg") or 0))
        _eff_cache["data"] = out; _eff_cache["ts"] = time.time()
        return out
    finally:
        s.close()


@app.get("/api/efficiency/summary")
def efficiency_summary():
    """近7天工作时段摸鱼 → AI 按人总结(谁什么时候干了什么影响效率)。结果缓存10分钟。"""
    import time as _time, json as _json, re as _re
    import llm_client
    if _eff_summary_cache["data"] is not None and _time.time() - _eff_summary_cache["ts"] < 600:
        return {"items": _eff_summary_cache["data"], "cached": True}
    from collections import defaultdict, Counter
    from datetime import timedelta
    s = Session()
    try:
        _n2 = bj_now()
        since = (_n2 - timedelta(days=6)).replace(hour=0, minute=0, second=0, microsecond=0)  # 自然日口径(7个日历日含今天)
        dom_expr = json_field(EventRow.raw, 'domain')
        lab_expr = func.coalesce(json_field(EventRow.raw, 'category'), json_field(EventRow.raw, 'app'), '')
        rows = s.query(EventRow.employee_id, EventRow.occurred_at, EventRow.count, dom_expr, lab_expr).filter(
            EventRow.category == "WEB", EventRow.occurred_at >= since).all()
        emp_slack = defaultdict(list)
        for emp_id, occ, cnt, dom, lab in rows:
            if not occ or (emp_id or "").isdigit():  # 跳过无时间 + 访客(纯数字ID)
                continue
            cat = dicts.slack_category(dom or "", lab or "")
            if cat and (9 <= occ.hour < 12 or 14 <= occ.hour < 18):
                emp_slack[emp_id].append((occ, cat, cnt or 1))
        # 预筛(≥3次)控成本;按天×类别压缩成文本喂 AI
        lines = []
        for emp, evs in emp_slack.items():
            if len(evs) < 3:
                continue
            by_day = defaultdict(Counter)
            for occ, cat, cnt in evs:
                by_day[occ.strftime("%m-%d")][cat] += cnt
            parts = ["%s %s" % (d, "、".join("%s%d次" % (c, n) for c, n in cats.most_common()))
                     for d, cats in sorted(by_day.items())]
            segs = _slack_segments([occ for occ, _, _ in evs])
            tot = int(sum(x[2] for x in segs) / 60)
            lines.append("%s: 近7天估摸鱼共约%d分钟; %s" % (emp, tot, "; ".join(parts)))
        if not lines:
            return {"items": [], "msg": "近7天工作时段无明显摸鱼行为"}
        ctx = "\n".join(lines[:60])
        prompt = ("你是企业员工效率分析助手。基于下面员工近7天【工作时段(9-12,14-18)】的摸鱼(娱乐访问)数据,"
                  "挑出真正影响工作效率的行为,按人用一句话总结:谁、什么时段、干了什么(网站类别)、大概多久或几次。"
                  "只挑值得说的(重度/反复),忽略零星1-2次。不编造数据外的内容。"
                  "只输出 JSON 数组 [{\"employee\",\"summary\"}],summary 是一句中文。\n\n数据:\n" + ctx)
        try:
            raw = llm_client.chat([{"role": "system", "content": prompt}, {"role": "user", "content": "请输出 JSON。"}],
                                  max_tokens=4000, timeout=240, model=llm_client.smart_model())  # 深度模型think耗token,预算必须给足
        except Exception as e:
            return {"items": [], "msg": "AI 总结失败: %s" % e}
        # 深度模型输出含思考块(strip_think兼容本地R1的半残标签),剥离后再提取数组
        clean = llm_client.strip_think(raw)
        clean = _re.sub(r"```(?:json)?|```", "", clean)
        m = _re.search(r"\[.*\]", clean, _re.S)
        items = []
        if m:
            try:
                items = _json.loads(m.group(0))
            except Exception:
                items = []
        items = [{"employee": str(it.get("employee", "")).strip(), "summary": str(it.get("summary", "")).strip()}
                 for it in items if it.get("employee") and it.get("summary")]
        if items:  # 空结果不缓存(可能因限流/解析失败,下次重试;真空也无妨重查)
            _eff_summary_cache["data"] = items; _eff_summary_cache["ts"] = _time.time()
        return {"items": items}
    finally:
        s.close()


@app.get("/api/category_stats")
def category_stats():
    """今日/昨日网站分类（深信服 app 字段）分布。"""
    from datetime import datetime, timedelta
    s = Session()
    try:
        now = bj_now()
        today_start = (now - timedelta(hours=now.hour, minutes=now.minute, seconds=now.second, microseconds=now.microsecond))
        yesterday_start = today_start - timedelta(days=1)

        def cat_count(since, until=None):
            app = json_field(EventRow.raw, 'app')
            q = s.query(app, func.count(EventRow.id)).filter(
                EventRow.category == 'WEB', EventRow.occurred_at >= since)
            if until:
                q = q.filter(EventRow.occurred_at < until)
            rows = q.group_by(app).all()
            # 原写法 `if r[0]` 把 app 为空的事件整组丢弃，使 "未识别" 分支永远走不到——
            # 意图(给空 app 归"未识别")与实现矛盾。去掉过滤，让空 app 正确归入"未识别"。
            return {(r[0] or "未识别"): r[1] for r in rows}

        today = cat_count(today_start)
        yesterday = cat_count(yesterday_start, today_start)
        return {"today": today, "yesterday": yesterday}
    finally:
        s.close()


@app.get("/api/export/alerts")
def export_alerts():
    """导出告警为CSV（安全运营报告用）。"""
    import csv as _csv
    import io as _io
    from fastapi.responses import StreamingResponse
    s = Session()
    try:
        rows = s.query(AlertRow).order_by(desc(AlertRow.risk_score)).all()
        output = _io.StringIO()
        output.write("﻿")
        w = _csv.writer(output)
        w.writerow(["用户", "场景", "严重度", "风险分", "状态", "时间", "说明"])
        SCN = {"job_seeking":"求职离职","data_exfiltration":"数据外发","baseline_deviation":"行为偏离","policy_violation":"违规"}
        for r in rows:
            w.writerow([r.employee_id, SCN.get(r.scenario, r.scenario or ""), r.severity,
                        r.risk_score, r.status, r.window_start.isoformat() if r.window_start else "", r.summary])
        output.seek(0)
        return StreamingResponse(iter([output.getvalue()]), media_type="text/csv",
                                headers={"Content-Disposition": "attachment; filename=alerts.csv"})
    finally:
        s.close()


# ---------------- AI 问答（LLM 路由 → 查真数据 → LLM 总结）----------------
_ASK_TOOLS = {
    "employee_risk": "查某个员工的风险行为/研判记录/画像。args: {employee: 员工姓名}",
    "alerts": "告警榜(全时段top10+今日清单)。args: {intent: 可选,按场景过滤: job_seeking(离职求职)|data_exfiltration(数据外发)|policy_violation(违规)|baseline_deviation(基线偏离)}",
    "slack": "摸鱼榜top10(近7天日均摸鱼时长)。args: {}",
    "attendance": "在岗情况(今日活跃/无活动名单/异常时段)。args: {}",
    "who_risk": "近30天谁访问了某类风险网站。args: {category: 远程控制|网盘|邮箱|招聘|文件助手}",
    "trend": "近14天每日告警数与研判数(趋势/环比对比类问题用)。args: {}",
    "sys_stats": "今日系统概览(研判数/告警数/活跃人数/事件量)。args: {}",
    "help": "系统的规则/风险分口径/摸鱼口径说明。args: {}",
}


def _ask_parse_objs(text: str) -> list:
    r"""从 LLM 输出提取 JSON 对象列表(支持嵌套 args、多个连续 JSON、<think>块)。
    正则 \{[^{}]*\} 不支持嵌套,必须用括号配平扫描。"""
    import re as _re
    import json as _json  # api.py 顶部无全局 import json,必须局部导入(此前 NameError 被 except 吞掉导致解析恒为空)
    clean = llm_client.strip_think(text)
    clean = _re.sub(r"```(?:json)?|```", "", clean)
    objs, i, n = [], 0, len(clean)
    while i < n:
        if clean[i] == "{":
            depth, j = 0, i
            while j < n:
                if clean[j] == "{":
                    depth += 1
                elif clean[j] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                j += 1
            if j < n:
                try:
                    objs.append(_json.loads(clean[i:j + 1]))
                except Exception:
                    pass
                i = j + 1
                continue
        i += 1
    return objs


def _ask_tool_run(name: str, args: dict) -> str:
    """执行一个查询工具,返回文本数据(复用 _ask_query 各分支 + 新增 trend/sys_stats)。"""
    args = args or {}
    if name not in ("trend", "sys_stats"):
        emp = args.get("employee") or args.get("name") or args.get("emp") or ""
        cat = args.get("category") or args.get("cat") or args.get("type") or args.get("intent") or ""
        return _ask_query(name, str(emp), str(cat))
    if name == "trend":
        from sqlalchemy import func as _f
        s = Session()
        try:
            _t0 = bj_now() - __import__("datetime").timedelta(days=14)
            # 按created_at(首次产生)统计,与页面趋势图同口径——window_start会被再犯刷新,不能用于历史趋势
            al = {str(d): n for d, n in s.query(_f.date(AlertRow.created_at), _f.count(AlertRow.id))
                  .filter(AlertRow.created_at >= _t0).group_by(_f.date(AlertRow.created_at)).all()}
            vd = {str(d): n for d, n in s.query(_f.date(VerdictRow.window_start), _f.count(VerdictRow.id))
                  .filter(VerdictRow.window_start >= _t0).group_by(_f.date(VerdictRow.window_start)).all()}
            days = sorted(set(al) | set(vd))
            if not days:
                return "近14天无告警/研判数据。"
            return "近14天每日(告警数/研判数):\n" + "\n".join(f"{d} 告警{al.get(d,0)} 研判{vd.get(d,0)}" for d in days)
        finally:
            s.close()
    if name == "sys_stats":
        from sqlalchemy import func as _f
        s = Session()
        try:
            _t0 = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
            al = s.query(_f.count(AlertRow.id)).filter(AlertRow.window_start >= _t0).scalar() or 0
            vd = s.query(_f.count(VerdictRow.id)).filter(VerdictRow.window_start >= _t0).scalar() or 0
            ev = s.query(_f.count(EventRow.id)).filter(EventRow.occurred_at >= _t0).scalar() or 0
            em = s.query(_f.count(_f.distinct(EventRow.employee_id))).filter(EventRow.occurred_at >= _t0).scalar() or 0
            return (f"今日概览(北京时间0点起): 活跃员工{em}人, 事件{ev}条(降噪后), "
                    f"AI研判{vd}次, 告警{al}条(风险≥50)。模型 {_lc_model()}")
        finally:
            s.close()
    return _ask_query(name, (args or {}).get("employee", ""), (args or {}).get("category", ""))


def _lc_model():
    import llm_client
    return getattr(llm_client, "LAST_MODEL", "") or "qwen"


@app.post("/api/ask")
def ask(body: dict = Body(...)):
    """自然语言问答(工具循环版): AI 自主决定调用哪些查询工具、可连续多次,
    全部结果到齐后再综合回答——支持复合/对比/多条件问题与多轮追问。"""
    import llm_client
    question = (body.get("question") or "").strip()
    if not question:
        return {"answer": "请输入问题。", "action": "empty"}
    history = [h for h in (body.get("history") or []) if isinstance(h, dict) and (h.get("q") or h.get("a"))][-3:]
    tools_txt = "\n".join(f"- {k}: {v}" for k, v in _ASK_TOOLS.items())
    sys_p = ("你是『员工行为分析系统』的智能助手,服务对象是系统管理员(安全运营人员)。你可以调用查询工具获取真实数据。\n\n"
             "每次回复【只输出一个 JSON】,两种格式选一(不要输出其他文字,不要一次输出多个JSON):\n"
             "{\"tool\": \"工具名\", \"args\": {参数}}  —— 调用一个工具继续查(要查多个就等结果回来再调下一个)\n"
             "{\"final\": \"给用户的最终回答\"}        —— 结束查询,直接回答\n\n"
             f"可用工具:\n{tools_txt}\n\n"
             "规则:\n"
             "1. 涉及数据的问题【必须】先调工具再回答,不得编造数字;对比/多条件/多人问题自行拆成多次工具调用(最多4次)。\n"
             "2. 结合最近对话理解追问(『他/它/昨天/再详细』),延续上轮员工与话题;路由到 employee_risk 时从对话中解析姓名。\n"
             "3. 【场景语义——自主路由,不抠字面】alerts 工具的 intent 参数按语义选择:"
             "job_seeking=离职求职迹象(招聘网站反复访问/跳槽/简历);"
             "data_exfiltration=数据外发(传文件/文件助手/网盘上传/邮箱发送/泄密);"
             "policy_violation=违反公司禁令(个人邮箱/禁止网盘或应用);"
             "baseline_deviation=行为异常(AI过度依赖/远程控制/异常时段)。\n"
             "用户可能用任何说法(『跑路』『挖人』『偷偷传文件』『投简历』),你按语义自行映射到对应 intent;"
             "问某类风险时必须带 intent 过滤、严禁拿其他场景数据答非所问;该场景无告警就如实说明;"
             "问总体风险/可疑行为时不带 intent。问具体某员工用 employee_risk。\n"
             "4. 不需要数据的问题(闲聊/概念解释)直接 final;查不到数据就在 final 里说明并建议问法。\n"
             "5. 告警状态语义: NEW=待处理; CONFIRMED=已知晓(管理员已看到,不代表风险解除,复犯会再提醒);"
             "FP=误报(系统判错,已豁免);CLOSED=已关闭。回答时用这些中文名称,不要说'已确认'。\n"
             "6. 【数字精度铁律——最高优先级】final回答中的所有数字必须原样引用工具返回的数据:"
             "工具返回'告警8条'你写'告警 8 条',不得写'约8条'/'多条'/'不少';"
             "工具返回'日均62分钟'你写'日均 62 分钟'不得四舍五入;"
             "工具返回'共5人'你写'5 人'不得写'几个人'。"
             "如果工具数据与你的常识冲突,以工具数据为准并注明'(数据来源:XX工具)'。"
             "禁止编造工具未返回的数字。\n"
             "7. final 回答要求:结论先行,枚举用短列表,口径如实(告警=风险≥50研判;摸鱼=10分钟桶估算上限),"
             "结尾可给一句下一步建议,中文,像资深安全运营同事的口吻。")
    msgs = [{"role": "system", "content": sys_p}]
    for h in history:
        if h.get("q"):
            msgs.append({"role": "user", "content": str(h["q"])[:150]})
        if h.get("a"):
            msgs.append({"role": "assistant", "content": str(h["a"])[:200]})
    msgs.append({"role": "user", "content": f"当前问题: {question}"})
    ans = ""
    used = []
    _ask_model = dicts.get_setting("llm_ask_model") or None  # 问答专用模型(如 glm-5);空=用活动模型
    try:
        for _step in range(6):
            out = llm_client.chat(msgs, max_tokens=1500, timeout=120, temperature=0.3, model=_ask_model)
            objs = _ask_parse_objs(out)
            final = next((o.get("final") for o in objs if o.get("final")), None)
            if final:
                ans = str(final)
                break
            tools = [o for o in objs if o.get("tool") in _ASK_TOOLS]
            if tools and len(used) < 4:
                results = []
                for o in tools[:3]:
                    if len(used) >= 4:
                        break
                    used.append(o["tool"])
                    try:
                        results.append(f"[{o['tool']}]\n{_ask_tool_run(o['tool'], o.get('args') or {})}")
                    except Exception as ee:
                        results.append(f"[{o['tool']}] 执行失败: {ee}")
                msgs.append({"role": "assistant", "content": "已调用: " + ", ".join(used[-len(results):])})
                msgs.append({"role": "user", "content": "工具结果:\n" + "\n\n".join(r[:2400] for r in results) +
                             "\n\n(数据已到齐则输出 {\"final\": ...} 回答;还缺数据可再调工具;每次只输出一个JSON)"})
                continue
            ans = out  # 解析不出结构:把原文当回答兜底
            break
        if not ans:
            ans = "查询轮次已达上限,请换个更具体的问题。"
    except Exception as e:
        ans = f"AI 回答失败: {e}"
    # 历史落库(失败不影响回答)+ 自动裁剪:只保留最近500条
    # (问答历史价值随时间衰减,无限增长无意义;500条够前端展示与回溯)
    try:
        s2 = Session()
        try:
            s2.add(AskHistoryRow(question=question, answer=ans))
            s2.commit()
            _maxid = s2.query(func.max(AskHistoryRow.id)).scalar() or 0
            if _maxid > 500:
                s2.query(AskHistoryRow).filter(AskHistoryRow.id <= _maxid - 500)\
                    .delete(synchronize_session=False)
                s2.commit()
        finally:
            s2.close()
    except Exception:
        pass
    return {"answer": ans, "action": "+".join(used) or "chat"}
    return {"answer": ans, "action": action}


@app.get("/api/ask/history")
def ask_history(limit: int = 60):
    """AI问答历史(最近N条,服务端保存,换浏览器不丢)。"""
    s = Session()
    try:
        rows = s.query(AskHistoryRow).order_by(desc(AskHistoryRow.id)).limit(min(limit, 200)).all()
        return {"items": [{"id": r.id, "question": r.question, "answer": r.answer,
                           "ts": r.created_at.isoformat() if r.created_at else None} for r in reversed(rows)]}
    finally:
        s.close()


@app.delete("/api/ask/history")
def ask_history_clear():
    s = Session()
    try:
        n = s.query(AskHistoryRow).delete()
        s.commit()
        return {"ok": True, "deleted": n}
    finally:
        s.close()


def _ask_query(action, employee, category=""):
    """按 action 复用现有查询逻辑,返回文本上下文喂总结 LLM。"""
    import detector
    from collections import Counter, defaultdict
    from datetime import timedelta
    s = Session()
    try:
        if action == "employee_risk" and employee:
            p = s.query(ProfileRow).filter_by(employee_id=employee).first()
            vs_total = s.query(VerdictRow).filter_by(employee_id=employee).count()
            vs = s.query(VerdictRow).filter_by(employee_id=employee).order_by(desc(VerdictRow.window_start)).limit(12).all()
            # 优先用 verdicts 的 explanation 喂 AI——研判时 AI 已经在 explanation 里写明了
            # 具体域名+次数+意图(如"访问猎聘网 bdfe.liepin.com 1次"),这比扫事件更准更快。
            # 旧版扫该员工【全部】事件做 risk_class,事件多的员工会拖到几十秒超时,导致 AI 答不出。
            lines = [f"员工 {employee}:",
                     f"画像: {profiles.summarize_for_llm(p.payload) if p else '无画像'}",
                     f"研判记录 {vs_total} 条(这是该员工被AI判定过的风险行为,最近 {min(vs_total,12)} 条):"]
            for v in vs:
                lines.append(f"  {v.window_start} | {v.intent} | 风险{v.risk_score} | {v.explanation}")
            # 补充:从这些研判反查具体事件域名(若 AI 问"具体哪些网站",域名比 explanation 更结构化)
            v_hashes = []
            for v in vs:
                v_hashes.extend(v.event_hashes or [])
            if v_hashes:
                dom_cnt = Counter()
                for e in s.query(EventRow).filter(EventRow.event_hash.in_(v_hashes[:400])).all():
                    d = ((e.raw or {}).get("domain") or "").lower()
                    rc = dicts.risk_class(d)
                    if rc and d:
                        dom_cnt[f"{rc}:{d}"] += 1
                if dom_cnt:
                    lines.append("风险域名明细(类别:域名 出现次数): " + ", ".join(f"{k}×{v}" for k, v in dom_cnt.most_common(15)))
            return "\n".join(lines)
        if action == "alerts":
            # 场景过滤:intent 只认标准枚举,语义映射由问答LLM自主完成
            # (2026-08-19: 不做中文关键词字典——'跑路''挖人''传文件'等任意说法
            # 由LLM按语义表路由,枚举关键词永远覆盖不全)
            _CN_INTENT = {"job_seeking": "离职求职", "data_exfiltration": "数据外发",
                          "policy_violation": "违反禁令", "baseline_deviation": "基线偏离"}
            _intent = (category or "").strip()
            if _intent and _intent not in _CN_INTENT:
                return (f"intent 参数必须是 {', '.join(f'{k}({v})' for k, v in _CN_INTENT.items())} 之一;"
                        f"请按用户问题的语义重新选择后再调用。")
            _base = s.query(AlertRow)
            if _intent:
                _base = _base.filter(AlertRow.scenario == _intent)
            rows = _base.order_by(desc(AlertRow.risk_score), desc(AlertRow.created_at)).limit(10).all()
            _today = bj_now().replace(hour=0, minute=0, second=0, microsecond=0)
            if not rows:
                # 该场景无告警时补研判层线索(低分研判也是趋势信号),让AI能如实分层回答
                # 剔除豁免员工: HR等豁免人员的高分研判不该出现在"离职风险最高"回答里(2026-08-20展佳案例)
                _exc2 = {x.employee_id for x in s.query(ExceptionRow).filter(
                    ExceptionRow.signal_type == _intent,
                    (ExceptionRow.expires_at.is_(None)) | (ExceptionRow.expires_at > datetime.utcnow())).all()}
                _vq = [x for x in s.query(VerdictRow).filter(VerdictRow.intent == _intent,
                                                 VerdictRow.window_start >= _today - timedelta(days=30)) \
                    .order_by(desc(VerdictRow.risk_score)).limit(15).all()
                    if x.employee_id not in _exc2][:5] if _intent else []
                if _intent and _vq:
                    return (f"当前无{_CN_INTENT[_intent]}({_intent})场景告警。但近30天该场景研判(未达告警级50分或已处理)最高:\n" +
                            "\n".join(f"  {v.employee_id} | 风险{v.risk_score} | {v.window_start} | {v.explanation}" for v in _vq) +
                            "\n注意:这些未构成告警,回答时必须如实说明。")
                return f"当前无{'该场景' if _intent else ''}告警。"
            # 条数单独 count（原用 len(limit15 列表) 当总数，>15 条时喂给 AI 的数是错的）
            _td_q = s.query(AlertRow).filter(AlertRow.window_start >= _today)
            if _intent:
                _td_q = _td_q.filter(AlertRow.scenario == _intent)
            _td_count = _td_q.count()
            _td = _td_q.order_by(desc(AlertRow.risk_score)).limit(15).all()
            _label = f"(场景={_intent}/{_CN_INTENT[_intent]}) " if _intent else ""
            lines = [f"告警 top10(全时段,按风险){_label}:"] + \
                [f"  {a.employee_id} | {a.scenario}({_CN_INTENT.get(a.scenario, a.scenario)}) | R{a.risk_score}" for a in rows]
            lines += ["", f"今日告警 {_td_count} 条(按行为时间){_label}:"] + [f"  {a.employee_id} | {a.scenario}({_CN_INTENT.get(a.scenario, a.scenario)}) | R{a.risk_score} | {a.summary}" for a in _td] if _td else ["", f"今日告警: {_td_count} 条"]
            return "\n".join(lines)
        if action == "slack":
            eff = efficiency()  # 与效率监控页完全同源同口径(近7天工作时段,日均摸鱼时长)
            top = [r for r in eff if (r.get("slack_avg") or 0) > 0][:10]
            if not top:
                return "无摸鱼数据。"
            return ("摸鱼榜 top10(近7天工作时段日均摸鱼时长,与效率监控页同口径):\n" +
                    "\n".join(f"{r['employee']} 日均{r['slack_avg']}分钟 · 娱乐占上班上网{r['pct']}%" for r in top))
        if action == "who_risk":
            # category(远程控制/网盘/邮箱/招聘/文件助手) → risk_class 标签模糊匹配
            cat_map = {"远程控制": "远程控制", "网盘": "网盘", "邮箱": "个人邮箱", "招聘": "招聘", "文件助手": "微信文件助手"}
            key = next((k for k in cat_map if k in category), None)
            target = cat_map.get(key, category) if key else category
            # 优化:SQL 只取 (employee,domain),Python 先对 distinct 域名算 risk_class(几千个),
            # 再聚合——避免对 98 万行逐行调 risk_class 导致超时。
            rcnt = Counter()
            dom_expr = json_field(EventRow.raw, 'domain')
            _since = bj_now() - timedelta(days=30)  # 问答看近期即可,避免全表扫描
            rows = s.query(EventRow.employee_id, dom_expr).filter(
                EventRow.category == 'WEB', EventRow.occurred_at >= _since).all()
            dom_cache = {}
            for emp_id, dom in rows:
                d = (dom or "").lower()
                if not d:
                    continue
                rc = dom_cache.get(d)
                if rc is None:
                    rc = dicts.risk_class(d) or ""
                    dom_cache[d] = rc
                if rc and target and (target in rc or rc in target):
                    rcnt[emp_id] += 1
            if not rcnt:
                return f"近期无人访问{target or '该类'}网站。"
            return f"访问{target}类网站的员工(访问次数):\n" + "\n".join(f"{emp} {n}次" for emp, n in rcnt.most_common(20))
        if action == "attendance":
            # 优化:SQL 取 distinct (employee, date(occurred_at), hour) 聚合,避免逐行遍历98万事件。
            today = bj_now().date().isoformat()
            today_active = set(); eh = defaultdict(set)
            _since = bj_now() - timedelta(days=30)  # 看近30天,避免全表扫描
            rows = s.query(EventRow.employee_id, EventRow.occurred_at).filter(
                EventRow.occurred_at.isnot(None), EventRow.occurred_at >= _since).all()
            for emp_id, occ in rows:
                if not _is_person(emp_id):  # 排除 IP/MAC 等设备标识，否则被当成"未上线的人"拉低上线比例
                    continue
                try:
                    d = occ.date().isoformat(); h = occ.hour
                    eh[emp_id].add((d, h))
                    if d == today:
                        today_active.add(emp_id)
                except Exception:
                    pass
            all_emps = set(eh.keys())
            not_today = sorted(all_emps - today_active)
            lines = [f"今日({today})有活动 {len(today_active)}人 / 全员 {len(all_emps)}人, 今日无活动 {len(not_today)}人(可能不在岗/未用电脑)。"]
            if not_today:
                lines.append("今日无活动: " + ", ".join(not_today[:20]))
            abnormal = []
            for emp_id in all_emps:
                days = {d for d, h in eh[emp_id]}; hours = sorted({h for d, h in eh[emp_id]})
                if hours and (len(days) <= 1 or hours[0] < 7):
                    mark = "活跃≤1天" if len(days) <= 1 else f"凌晨{hours[0]}点活动"
                    abnormal.append(f"{emp_id}({mark})")
            if abnormal:
                lines.append("异常: " + ", ".join(abnormal[:15]))
            return "\n".join(lines)
        if action == "help":
            return ("系统能力: 安全告警(邮箱/网盘/文件助手/远程控制/招聘)、效率监控(视频/社交/购物/资讯/音乐摸鱼)、画像(风险行为/基线)。\n"
                    "规则: 个人邮箱/网盘公司禁止→访问即违规; 微信文件助手=外发; 远程控制降权; 招聘=求职意图。\n"
                    "可问: 某员工风险行为 / 告警榜 / 摸鱼榜 / 在岗情况 / 谁访问了网盘·邮箱·招聘·文件助手·远程控制。")
        return ""
    finally:
        s.close()


# ---------------- AI 规则建议（建议 + 人工确认）----------------
def _rules_scan_core() -> dict:
    """AI 扫未分类高频域名,建议加到风险/摸鱼词库(只返回建议,不写库)。
    手动扫描(端点)与每周自动扫描共用本核心。"""
    import llm_client, json as _json, re as _re
    from collections import Counter
    s = Session()
    try:
        # 优化:SQL 先按域名 group by + count(98万行→几千唯一域名),Python 只对
        # distinct 域名调一次分类函数。旧版逐行调3个分类函数,98万×3次字典遍历,极慢。
        unclass = Counter(); lab_of = {}; kw_hits = set()
        # 含这些关键词的未分类域名即使低频也要扫,避免漏掉新风险/新应用
        RISK_KW = ("job", "zhaopin", "recruit", "resume", "hr", "hire", "cv", "mail",
                   "pan", "disk", "cloud", "drive", "upload", "video", "shop", "mall",
                   "weibo", "zhihu", "douban", "game", "novel", "comic",
                   # 新增:覆盖新风险线索
                   "send", "transfer", "share", "sync", "backup", "export",  # 外发/同步
                   "chat", "ai", "gpt", "llm", "prompt",  # AI助手
                   "wiki", "notion", "confluence", "figma",  # 协作/设计平台(数据外发)
                   "pastebin", "github", "gist", "codepen",  # 代码粘贴/外发
                   "tunnel", "ngrok", "frp", "proxy",  # 内网穿透/代理
                   "telegram", "whatsapp", "signal",  # 即时通讯(外发)
                   "weibo", "zhihu", "douban", "game", "novel", "comic")
        dom_expr = json_field(EventRow.raw, 'domain')
        # SQLite: 直接 group by json 提取的 domain 字段(+深信服分类标签,喂AI提升判断质量)
        from sqlalchemy import func as _f
        lab_expr = _f.coalesce(json_field(EventRow.raw, 'category'), json_field(EventRow.raw, 'app'), '')
        rows = s.query(dom_expr, lab_expr, _f.count(EventRow.id)).filter(
            EventRow.category == "WEB", dom_expr.isnot(None)
        ).group_by(dom_expr, lab_expr).all()
        cls_cache = {}
        for d, lab, n in rows:
            d = (d or "").strip()
            if not d:
                continue
            lab_of.setdefault(d, lab or "")
            cls = cls_cache.get(d)
            if cls is None:
                cls = "risk" if dicts.risk_class(d) else ("slack" if dicts.slack_category(d, lab_of.get(d) or "") else ("work" if dicts.work_category(d) else "unclass"))
                cls_cache[d] = cls
            if cls == "unclass":
                unclass[d] += n
                if any(k in d.lower() for k in RISK_KW):
                    kw_hits.add(d)
        top = unclass.most_common(60)
        for d in kw_hits:  # 补充含风险关键词的域名(低频但疑似风险/摸鱼),确保被AI扫到
            if d not in dict(top):
                top.append((d, unclass[d]))
        # ---- 维度2: 传输动作域名(URL含upload/send/file/attach)——外发通道的真实信号。
        # 不限频次(italent上传7次/yeasen6次这类低频传输,高频榜根本扫不到,2026-08-18漏判审查结论),
        # 人数≤10(排除92人都在用的基础设施),SQL端LIKE预筛控成本。
        # 独立保底名额(追加在top尾部会被[:N]截断,2026-08-18实测italent被砍)。 ----
        _act_top = []
        try:
            from datetime import timedelta as _td3
            _tv = EventRow.target_value
            _act_rows = s.query(EventRow.employee_id, dom_expr).filter(
                EventRow.category == "WEB", EventRow.occurred_at >= bj_now() - _td3(days=30),
                _tv.like("%upload%") | _tv.like("%send%") | _tv.like("%/file%") | _tv.like("%attach%")
            ).all()
            _act_cnt = Counter()
            from collections import defaultdict as _dd2
            _au = _dd2(set)
            for emp2, d2 in _act_rows:
                d2 = (d2 or "").strip().lower()
                if d2:
                    _act_cnt[d2] += 1
                    _au[d2].add(emp2)
        except Exception as _e2:
            print(f"[scan] 传输动作维度失败: {_e2}", flush=True)

        # 预过滤明显的云服务/CDN/SDK 噪音子域(微软云/CDN/统计/证书等长串子域),
        # 这些喂给AI无价值且占名额。长度限90(阿里云日志等长业务域名曾被48误杀;微软长串噪音由NOISE_HINT具体词兜住)。
        NOISE_HINT = ("office.net", "office.com", "sharepoint", "microsoft", "akamai",
                      "cloudfront", "ic3-edf", "trouter", "svc.ms", "1cdn", "office365",
                      "skype", "aria.microsoft", "events.data", "telemetry",
                      "in.applicationinsights", "blob.core", "trouser", "msn.cn", "bing.net",
                      "volces.com")

        def _ok(d):
            return len(d) < 90 and not any(x in d.lower() for x in NOISE_HINT)

        _main = [(d, n) for d, n in top if _ok(d)][:20]
        # _seen 只含"确定进主榜"的域名——若以原始top计算,kw补充段的低频传输域名会被
        # _seen误挡(又进不了被截断的主榜,两头落空,2026-08-18 zhihu-upload案例)
        _seen = {d for d, _ in _main}
        # 排序:人数少者优先(个人向外部传内容最可疑),同人数按次数降序;多人共用(>10人)的接口不算
        for d2 in sorted((d for d in _act_cnt if _act_cnt[d] >= 3 and len(_au[d]) <= 10),
                         key=lambda d: (len(_au[d]), -_act_cnt[d])):
            if len(_act_top) >= 10:
                break
            if d2 not in _seen:
                _act_top.append((d2, _act_cnt[d2]))
                lab_of.setdefault(d2, f"含传输动作(upload/send),{_act_cnt[d2]}次/{len(_au[d2])}人")
        top = _main + _act_top
        if not top:
            return {"suggestions": [], "msg": "无未分类高频域名"}
        sys_p = ("你是企业数据安全助手。分析这些【未分类】的域名,判断是否需要纳入风险监控。\n"
                 "对每个域名输出 JSON: {domain, target, cat, reason}\n"
                 "target 取值:\n"
                 "- 已知风险类(纳入对应字典): netdisk_domains(网盘云盘) / personal_email_domains(个人邮箱) / recruitment_sites(招聘求职) / remote_control_domains(远程控制) / code_repo_domains(代码仓库) / wechat_file_domains(微信文件助手) / ai_assistant_domains(AI助手chatgpt/deepseek等,往AI塞数据) / slack_domains(摸鱼娱乐)  (注: 翻墙VPN经业务确认不算风险,勿建议)\n"
                 "- **suspect_new(疑似新风险)**: 不属于上述任何类,但像数据外发/泄露/规避监控的可疑行为(如未知网盘、匿名传输、临时邮箱、屏幕共享、代码粘贴pastebin、内网穿透ngrok/frp、加密货币、敏感数据爬取等)。这类即使无法精确归类也要标出,供人工审核。\n"
                 "【传输动作特别规则】标注了'含传输动作(upload/send)'的域名=有员工在向上传内容:个人向社交平台/图床/外部云/招聘平台传文件属外发嫌疑,默认 suspect_new 或归入对应风险类,不要因'知名网站的子域'就判 ignore(如知乎图片上传、招聘系统传简历)。\n"
                 "- ignore: 明确的正常办公/厂商后台/CDN/SDK/系统更新/认证服务\n"
                 "cat: 仅 target=slack_domains 时填 视频/社交/购物/资讯/音乐 之一,否则空字符串。\n"
                 "reason: 一句中文,说明判断依据。\n"
                 "原则:宁可多标 suspect_new 让人工复核,也不要漏掉可疑域名。只输出 JSON 数组。")
        user = "域名列表(域名 出现次数 深信服分类):\n" + "\n".join(f"{d} {n} {lab_of.get(d,'') or '-'}" for d, n in top)
        raw = llm_client.chat([{"role": "system", "content": sys_p}, {"role": "user", "content": user}],
                              max_tokens=7000, timeout=400, model=llm_client.smart_model())  # 扫描质量决定开集发现效果,深度模型think预算给足
        _rc = llm_client.strip_think(raw)  # 剥离深度模型思考块
        _rc = _re.sub(r"```(?:json)?|```", "", _rc)
        m = _re.search(r"\[.*\]", _rc, _re.S)
        suggestions = []
        if m:
            try:
                suggestions = _json.loads(m.group(0))
            except Exception:
                pass
        hit_map = dict(top)
        # ---- 心跳域名检测(纯规则,不走LLM): 娱乐域名呈"规律稀疏上报"→建议排除 ----
        # 特征: 同员工同天 ≥5 次访问、平均间隔 ≥15 分钟(真实摸鱼是密集成块的)。
        # 防客户端挂后台心跳被算成摸鱼时长(2026-08-17 张云淘宝案例),每周扫描自动发现新心跳域名。
        try:
            from datetime import timedelta as _td
            since2 = bj_now() - _td(days=7)
            rows2 = s.query(EventRow.occurred_at, dom_expr, EventRow.employee_id).filter(
                EventRow.category == "WEB", EventRow.occurred_at >= since2).all()
            from collections import defaultdict as _dd
            by_dom = _dd(list)
            _sc_cache = {}
            for occ2, d2, emp2 in rows2:
                d2 = (d2 or "").strip()
                if not occ2 or not d2:
                    continue
                if d2 not in _sc_cache:
                    _sc_cache[d2] = dicts.slack_category(d2, lab_of.get(d2, ""))
                if _sc_cache[d2]:
                    by_dom[d2].append((emp2, occ2))
            hb_cands = []
            for d2, evs in by_dom.items():
                if len(evs) < 15:
                    continue
                byg = _dd(list)
                for emp2, occ2 in evs:
                    byg[(emp2, occ2.date().isoformat())].append(occ2)
                groups = [v for v in byg.values() if len(v) >= 5]
                if len(groups) < 2:
                    continue
                hb = 0
                for v in groups:
                    v.sort()
                    span_min = (v[-1] - v[0]).total_seconds() / 60
                    if span_min / len(v) >= 15:  # 平均间隔≥15min=稀疏规律上报
                        hb += 1
                if hb >= max(2, len(groups) // 2):
                    hb_cands.append((d2, len(groups), hb))
            for d2, ng, hb in sorted(hb_cands, key=lambda x: -x[1])[:8]:
                suggestions.append({"domain": d2, "target": "slack_sdk_domains", "cat": "",
                                    "reason": f"{ng} 个员工×天呈规律稀疏上报({hb} 组平均间隔≥15分钟),疑似客户端挂后台心跳,建议排除(其余娱乐域名不受影响)"})
        except Exception as e:
            print(f"[scan] 心跳检测失败: {e}", flush=True)
        for it in suggestions:
            it["hits"] = hit_map.get((it.get("domain") or "").lower(), 0)
        return {"suggestions": suggestions}
    finally:
        s.close()


@app.post("/api/rules/suggest")
def rules_suggest():
    """手动触发 AI 规则扫描(前端"开始扫描"按钮)。"""
    return _rules_scan_core()


def auto_rules_scan():
    """每周自动开集扫描(由 syslog 维护循环触发):结果存 settings 供前端展示,
    发现 suspect_new/风险类建议时推 webhook 提醒人工审核。永不自动写字典。"""
    import json as _json
    try:
        r = _rules_scan_core()
        sugs = r.get("suggestions") or []
        dicts.set_setting("auto_rules_suggestions", _json.dumps(sugs, ensure_ascii=False)[:200000])
        dicts.set_setting("auto_rules_last_run", bj_now().isoformat())
        hot = [x for x in sugs if x.get("target") == "suspect_new"]
        risk = [x for x in sugs if x.get("target") and x.get("target") != "ignore"
                and x.get("target") != "slack_domains" and x.get("target") != "suspect_new"]
        print(f"[auto-scan] 开集扫描完成: {len(sugs)}条建议, 疑似新风险{len(hot)}, 风险类{len(risk)}", flush=True)
        if hot or risk:
            import pipeline as _pl
            names = ", ".join((x.get("domain") or "?") for x in (hot + risk)[:8])
            _pl._notify_webhook("AI规则扫描", 0,
                                f"本周自动扫描发现 {len(hot)} 条疑似新风险 / {len(risk)} 条风险类建议: {names} …"
                                f"请到 系统设置→字典&AI规则 审核(仅人工采纳后生效)")
    except Exception as e:
        print(f"[auto-scan] 失败: {e}", flush=True)


@app.get("/api/rules/auto")
def rules_auto_status():
    """自动扫描状态: 上次时间+待审建议(前端展示);也供维护循环判断是否到期。"""
    import json as _json
    last = dicts.get_setting("auto_rules_last_run") or ""
    sugs = []
    try:
        sugs = _json.loads(dicts.get_setting("auto_rules_suggestions") or "[]")
    except Exception:
        pass
    return {"last_run": last, "suggestions": sugs}


@app.post("/api/rules/apply")
def rules_apply(body: dict = Body(...)):
    """采纳建议: 把 domain 加到 target_dict(slack_domains 时加到 cat 列表)。"""
    domain = (body.get("domain") or "").lower().strip()
    target = body.get("target_dict") or body.get("target") or ""
    cat = body.get("cat") or ""
    if not domain or target not in dicts.DEFAULTS:
        raise HTTPException(400, "无效 target 或 domain")
    if target == "slack_domains":
        cur = dicts.get("slack_domains")
        if not isinstance(cur, dict):
            cur = {}
        if cat:
            cur[cat] = list(cur.get(cat) or [])
            if domain not in cur[cat]:
                cur[cat].append(domain)
        dicts.set_dict("slack_domains", cur)
    else:
        cur = list(dicts.get(target) or [])
        if domain not in cur:
            cur.append(domain)
        dicts.set_dict(target, cur)
    return {"ok": True, "target": target, "domain": domain, "cat": cat}


# ---------------- 原始日志查看 ----------------
@app.get("/api/raw_logs")
def raw_logs(start: str | None = None, end: str | None = None, log_type: str | None = None,
             user: str | None = None, kw: str | None = None, limit: int = 500):
    """原始 syslog 报文查询(按时间/log_type/user/关键词筛选),返回total+items。"""
    s = Session()
    try:
        q = s.query(RawLogRow)
        if start:
            q = q.filter(RawLogRow.received_at >= start)
        if end:
            q = q.filter(RawLogRow.received_at <= end)
        if log_type:
            q = q.filter(RawLogRow.log_type == log_type)
        if user:
            q = q.filter(RawLogRow.user.contains(user))
        if kw:
            q = q.filter(RawLogRow.msg.contains(kw))
        total = q.count()
        rows = q.order_by(desc(RawLogRow.received_at)).limit(min(limit, 5000)).all()
        return {"total": total, "items": [{"id": r.id, "received_at": r.received_at.isoformat() if r.received_at else None,
                 "log_type": r.log_type, "user": r.user, "app": r.app, "msg": r.msg} for r in rows]}
    finally:
        s.close()


# ---------------- 用户名映射(账号/IP标识 -> 中文名统一) ----------------
def _alias_load(key):
    import json as _j
    try:
        return _j.loads(dicts.get_setting(key) or "{}")
    except Exception:
        return {}


def _alias_apply(account: str, name: str) -> int:
    """把确认的映射应用到历史数据: 各表 employee_id 替换 + 告警dedup_key重建。返回更新行数。"""
    from sqlalchemy import func as _f2
    n = 0
    s = Session()
    try:
        # profiles 每人一行(unique): 账号行与中文名行并存时,丢弃账号行(画像随后台任务重建)
        pa = s.query(ProfileRow).filter_by(employee_id=account).first()
        if pa:
            if s.query(ProfileRow).filter_by(employee_id=name).first():
                s.delete(pa)
                s.commit()
        for tbl in (EventRow, VerdictRow, AlertRow, ProfileRow, ExceptionRow):
            r = s.query(tbl).filter(getattr(tbl, "employee_id") == account)                .update({getattr(tbl, "employee_id"): name}, synchronize_session=False)
            n += r or 0
        # alerts.dedup_key = f"{emp}|{intent}" —— 重算
        for a in s.query(AlertRow).filter(AlertRow.employee_id == name).all():
            if a.dedup_key and a.dedup_key.startswith(account + "|"):
                a.dedup_key = f"{name}|{a.scenario}"
        # 同员工同意图的老/新告警可能因映射产生重复行——保留分数高的那条
        dup = s.query(AlertRow.dedup_key, _f2.count(AlertRow.id)).filter(AlertRow.employee_id == name)            .group_by(AlertRow.dedup_key).having(_f2.count(AlertRow.id) > 1).all()
        for key, _cnt in dup:
            rows = s.query(AlertRow).filter(AlertRow.dedup_key == key).order_by(desc(AlertRow.risk_score)).all()
            for extra in rows[1:]:
                s.delete(extra)
        s.commit()
    finally:
        s.close()
    return n


def _alias_discover():
    """自动发现用户名映射(每小时维护跑):
    1) 拼音精确唯一命中 → 自动生效并清洗历史;
    2) 其余非中文标识全部进待确认清单(2026-08-19用户口径: 不是中文的都提取出来),
       等人工填写中文名。
    注意: 不做同IP推测——办公网IP是DHCP动态分配,换租后同一IP是不同的人,
    任何基于IP的员工关联都会张冠李戴(2026-08-19用户红线)。"""
    import json as _j
    import re as _re
    from pypinyin import lazy_pinyin
    from datetime import timedelta
    try:
        s = Session()
        try:
            emps = set()
            for tbl in (EventRow, VerdictRow, AlertRow):
                emps |= {r[0] for r in s.query(tbl.employee_id).filter(tbl.employee_id.isnot(None)).distinct().all()}
            cn = _re.compile(r"[一-鿿]")
            cn_names = sorted({e for e in emps if e and cn.search(e)})
            accts = sorted({e for e in emps if e and not cn.search(e)})
            cn_py = {n: "".join(lazy_pinyin(n)) for n in cn_names}
            conf = _alias_load("employee_alias")
            ign = _alias_load("employee_alias_ignored")
            # 活跃度(近30天): 事件数+最近出现,辅助人工判断值不值得映射
            from sqlalchemy import func as _f
            since = bj_now() - timedelta(days=30)
            act = {eid: (c, mx) for eid, c, mx in
                   s.query(EventRow.employee_id, _f.count(EventRow.id), _f.max(EventRow.occurred_at))
                   .filter(EventRow.occurred_at >= since).group_by(EventRow.employee_id).all()}
            changed = []
            new_pend = {}
            for a in accts:
                if a in conf or a in ign:
                    continue
                a2 = a.lower().replace(".", "").replace("_", "").replace("-", "")
                a2 = _re.sub(r"\d+$", "", a2)  # 剥离尾部编号(zhangsan01 → zhangsan)
                is_ip = bool(_re.match(r"^\d{1,3}(\.\d{1,3}){3}$", a))
                hits = [] if is_ip or not a2 else [n for n, p in cn_py.items() if p == a2]
                if len(hits) == 1:
                    conf[a] = hits[0]
                    changed.append((a, hits[0]))
                    continue
                _c, _mx = act.get(a, (0, None))
                entry = {"guess": "", "candidates": [], "reason": "",
                         "count": _c, "last_seen": str(_mx or "")[:16]}
                if len(hits) > 1:
                    entry["reason"] = "拼音匹配多人,请选择"
                    entry["candidates"] = hits
                elif is_ip:
                    entry["reason"] = "IP型标识(DHCP动态分配,无法关联到员工,建议忽略)"
                else:
                    entry["reason"] = "未推测到,请人工填写"
                new_pend[a] = entry
            # 前缀型中文名标识归一: "HLX-SZ-万亮"→"万亮"——与现有员工名精确匹配才
            # 自动生效(2026-08-19全员审计: 7个HLX前缀标识与裸名并存致视图重复计数)
            _pf = _re.compile(r"^[A-Za-z]{2,6}(?:-[A-Za-z]{2,6})+-")
            for a in emps:
                if a in conf or a in ign or not cn.search(a or "") or not _pf.match(a):
                    continue
                core = _pf.sub("", a).strip()
                if core and core in cn_names and core != a:
                    conf[a] = core
                    changed.append((a, core))
            dicts.set_setting("employee_alias", _j.dumps(conf, ensure_ascii=False))
            dicts.set_setting("employee_alias_pending", _j.dumps(new_pend, ensure_ascii=False))
            if changed:
                for a, n in changed:
                    _alias_apply(a, n)
                print(f"[alias] 拼音自动统一 {len(changed)} 个; 待确认 {len(new_pend)} 个", flush=True)
            elif new_pend:
                print(f"[alias] 待确认 {len(new_pend)} 个", flush=True)
        finally:
            s.close()
    except Exception as e:
        print(f"[alias] 发现失败: {e}", flush=True)


@app.get("/api/alias")
def alias_list():
    return {"confirmed": _alias_load("employee_alias"),
            "pending": _alias_load("employee_alias_pending"),
            "ignored": list(_alias_load("employee_alias_ignored").keys())}


@app.post("/api/alias/ignore")
def alias_ignore(body: dict = Body(...)):
    """忽略待确认标识(数字访客ID等不需要映射的) / undo=1 恢复。"""
    import json as _j
    account = (body.get("account") or "").strip()
    if not account:
        raise HTTPException(400, "account 不能为空")
    ign = _alias_load("employee_alias_ignored")
    pend = _alias_load("employee_alias_pending")
    if body.get("undo"):
        ign.pop(account, None)
    else:
        ign[account] = 1
        pend.pop(account, None)
    dicts.set_setting("employee_alias_ignored", _j.dumps(ign, ensure_ascii=False))
    dicts.set_setting("employee_alias_pending", _j.dumps(pend, ensure_ascii=False))
    return {"ok": True}


@app.post("/api/alias/confirm")
def alias_confirm(body: dict = Body(...)):
    """确认候选映射(或直接添加): 立即写入生效映射并清洗该账号历史数据。"""
    import json as _j
    account = (body.get("account") or "").strip()
    name = (body.get("name") or "").strip()
    if not account or not name:
        raise HTTPException(400, "account/name 不能为空")
    conf = _alias_load("employee_alias")
    pend = _alias_load("employee_alias_pending")
    old = conf.get(account)
    conf[account] = name
    pend.pop(account, None)
    dicts.set_setting("employee_alias", _j.dumps(conf, ensure_ascii=False))
    dicts.set_setting("employee_alias_pending", _j.dumps(pend, ensure_ascii=False))
    n = 0
    if old != name:
        n = _alias_apply(account, name)
    return {"ok": True, "updated_rows": n}


@app.delete("/api/alias/{account}")
def alias_delete(account: str):
    import json as _j
    conf = _alias_load("employee_alias")
    if account in conf:
        del conf[account]
        dicts.set_setting("employee_alias", _j.dumps(conf, ensure_ascii=False))
    return {"ok": True}


# ---------------- 托管前端（放最后，避免拦截 /api）----------------
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
