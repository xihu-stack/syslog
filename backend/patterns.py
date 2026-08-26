"""行为模式检测(2026-08-21): 压缩→外发组合 / 改名掩盖 / 环比突变 / 深夜模式。

挂载在 massops 的10分钟扫描周期里,与大量删除/外发量聚合同频。
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
import re

from db import Session, EventRow, AlertRow, ProfileRow, bj_now
import dicts
import llm_client


# ---------- 3) 压缩→外发组合 ----------
def scan_archive_then_send(s) -> int:
    """同一天内先 ARCHIVE 再 SEND/UPLOAD 到非白名单 → 蓄意打包带走。"""
    by_emp = defaultdict(list)
    for e in s.query(EventRow).filter(
            EventRow.source == "ipguard",
            EventRow.occurred_at >= bj_now() - timedelta(days=1)).all():
        if e.category == "DOC":
            by_emp[e.employee_id].append(e)
    _webs = _webs_by_emp(s, bj_now() - timedelta(days=1))
    created = 0
    for emp, evs in by_emp.items():
        archives = [e for e in evs if e.action == "ARCHIVE"]
        sends = [e for e in evs if e.action in ("SEND", "UPLOAD")
                 and not _is_whitelisted_dest(e, _webs.get(emp))]
        if not archives or not sends:
            continue
        # 压缩文件名与外发文件名有关联(同名/包含关系)
        arch_names = {(e.target_value or "").lower() for e in archives}
        for send in sends:
            sn = (send.target_value or "").lower()
            base = re.sub(r"\.(zip|rar|7z|tar|gz)$", "", sn)
            if any(an in sn or base in an or sn in an for an in arch_names):
                day = send.occurred_at.strftime("%Y-%m-%d")
                key = f"{emp}|archive_send|{day}"
                if s.query(AlertRow).filter_by(dedup_key=key).first():
                    break
                dest = ((send.raw or {}).get("dest_path") or "").strip()
                if dest.startswith(("http:", "https:")):
                    _p = dest.split("/")
                    dest = _p[2] if len(_p) > 2 else dest
                else:
                    dest = dest.split("/")[0]
                if not dest:  # 空目的地: 邻近域名样例
                    _near = [d for t, d in _webs.get(emp, [])
                             if abs((t - send.occurred_at).total_seconds()) <= 180][:2]
                    dest = ("同期浏览:" + "/".join(_near)) if _near else "未识别目的地(网页上传)"
                _app = (send.raw or {}).get("app") or ""
                s.add(AlertRow(employee_id=emp, scenario="archive_exfil",
                               severity="CRITICAL", risk_score=85,
                               summary=(f"{emp}在{day}先压缩『{(archives[0].target_value or '')[:30]}』"
                                        f"再经{_app or '网络'}外发『{sn[:30]}』至{dest[:40]},属打包后蓄意带走模式"),
                               dedup_key=key,
                               window_start=send.occurred_at, created_at=bj_now(), status="NEW"))
                created += 1
                print(f"[pattern] {emp} 压缩→外发 -> 85分", flush=True)
                break
    return created


# ---------- 4) 改名掩盖检测 ----------
def scan_rename_disguise(s) -> int:
    """RENAME 后文件名显著变短/失去语义 → 再外发 = 掩盖。"""
    created = 0
    for emp in {r[0] for r in s.query(EventRow.employee_id).filter(
            EventRow.source == "ipguard",
            EventRow.occurred_at >= bj_now() - timedelta(days=1)).distinct().all()}:
        evs = [e for e in s.query(EventRow).filter(
            EventRow.employee_id == emp,
            EventRow.occurred_at >= bj_now() - timedelta(days=1),
            EventRow.category == "DOC").all()]
        renames = [e for e in evs if e.action == "RENAME"]
        sends = [e for e in evs if e.action in ("SEND", "UPLOAD")
                 and not _is_whitelisted_dest(e)]
        if not renames or not sends:
            continue
        for rn in renames:
            src = ((rn.raw or {}).get("src_path") or rn.target_value or "").split("\\")[-1].lower()
            dest_name = ((rn.raw or {}).get("dest_path") or "").split("\\")[-1].lower()
            if not src or not dest_name:
                continue
            # 判定"掩盖": 改名后长度不到原名一半,且不含中文/项目编号特征
            if len(dest_name) < len(src) * 0.5 and not re.search(r"[一-鿿]|[A-Z]{2,}[-_]\d", dest_name):
                # 该改名后的文件被外发
                for send in sends:
                    if dest_name in (send.target_value or "").lower():
                        day = rn.occurred_at.strftime("%m-%d")
                        key = f"{emp}|rename_exfil|{day}"
                        if s.query(AlertRow).filter_by(dedup_key=key).first():
                            break
                        s.add(AlertRow(employee_id=emp, scenario="rename_exfil",
                                       severity="CRITICAL", risk_score=80,
                                       summary=(f"{emp}在{day}将『{src[:30]}』改名为『{dest_name[:20]}』后外发,"
                                                f"属改名掩盖行为"),
                                       dedup_key=key,
                                       window_start=send.occurred_at, created_at=bj_now(), status="NEW"))
                        created += 1
                        print(f"[pattern] {emp} 改名掩盖({src[:15]}→{dest_name[:10]}) -> 80分", flush=True)
                        break
    return created


# ---------- 5) 行为环比突变 ----------
def scan_trend_spike(s) -> int:
    """本周 vs 上周: 外发次数/摸鱼时长/深夜天数 突增≥2倍 → 告警。"""
    created = 0
    now = bj_now()
    this_week = now - timedelta(days=7)
    last_week = now - timedelta(days=14)
    for emp in {r[0] for r in s.query(EventRow.employee_id).filter(
            EventRow.source == "ipguard",
            EventRow.occurred_at >= last_week).distinct().all()}:
        cur = [e for e in s.query(EventRow).filter(
            EventRow.employee_id == emp,
            EventRow.occurred_at >= this_week,
            EventRow.action.in_(("SEND", "UPLOAD"))).all()]
        cur_send = sum(1 for e in cur if not _is_whitelisted_dest(e))
        prev = [e for e in s.query(EventRow).filter(
            EventRow.employee_id == emp,
            EventRow.occurred_at >= last_week,
            EventRow.occurred_at < this_week,
            EventRow.action.in_(("SEND", "UPLOAD"))).all()]
        prev_send = sum(1 for e in prev if not _is_whitelisted_dest(e))
        # 外发次数突增: 上周≥3次,本周≥3倍
        if prev_send >= 3 and cur_send >= prev_send * 3:
            day = now.strftime("%m-%d")
            key = f"{emp}|trend_exfil|{day}"
            if not s.query(AlertRow).filter_by(dedup_key=key).first():
                s.add(AlertRow(employee_id=emp, scenario="trend_spike",
                               severity="HIGH", risk_score=75,
                               summary=(f"{emp}本周外发{cur_send}次(上周{prev_send}次),"
                                        f"环比增长{cur_send/max(prev_send,1):.0f}倍,属外发量突增"),
                               dedup_key=key,
                               window_start=now, created_at=bj_now(), status="NEW"))
                created += 1
                print(f"[pattern] {emp} 外发环比{cur_send}vs{prev_send} -> 75分", flush=True)
    return created


# ---------- 9) 深夜工作模式(画像级,供profile展示) ----------
def night_workers(s) -> list:
    """经常22-7点活跃的人(≥3天/周)。"""
    out = []
    for p in s.query(ProfileRow).all():
        rh = (p.payload or {}).get("rhythm") if isinstance(p.payload, dict) else None
        if rh and (rh.get("late_night_days") or 0) >= 3:
            out.append({"employee": p.employee_id,
                        "late_night_days": rh["late_night_days"],
                        "start_median": rh.get("start_median"),
                        "end_median": rh.get("end_median")})
    return sorted(out, key=lambda x: -x["late_night_days"])


# ---------- 10) 进程来源标注(喂给研判) ----------
def app_context(e) -> str:
    """从 URL_APP_NAME 提取进程来源上下文。"""
    app = ((e.raw or {}).get("app") or "").lower()
    if "weixin" in app or "wechat" in app:
        return "微信内点击"
    if "msedge" in app or "chrome" in app or "firefox" in app:
        return "浏览器主动访问"
    if "word" in app or "excel" in app or "powerpnt" in app:
        return "Office内操作"
    if "explorer" in app:
        return "文件管理器"
    return app or ""


def _is_whitelisted_dest(e, webs=None) -> bool:
    """外发目的地在公司白名单。2026-08-24: URL型目的地取主机名(原'https:'截断);
    空目的地(网页上传IPG不记域名)按±3分钟浏览域名推断(Teams/M365传附件不算外发)。"""
    dest = dicts.dest_host(e.raw or {})
    _wl = [w.lower() for w in (dicts.get("risk_whitelist_domains") or [])]
    if dest:
        return any(dest == w or dest.endswith("." + w) for w in _wl)
    if webs is None:
        return False
    ts = getattr(e, "occurred_at", None)
    for t, d in webs:
        if ts and abs((t - ts).total_seconds()) <= 180:
            if any(d == w or d.endswith("." + w) for w in _wl):
                return True
    return False


def _webs_by_emp(s, since):
    """各员工当日WEB事件(时间,域名),供空目的地邻近推断。"""
    from collections import defaultdict as _dd
    webs = _dd(list)
    for w in s.query(EventRow).filter(EventRow.category == "WEB",
                                       EventRow.occurred_at >= since).all():
        d = ((w.raw or {}).get("domain") or "").lower()
        if d:
            webs[w.employee_id].append((w.occurred_at, d))
    for k in webs:
        webs[k].sort()
    return webs


def run_all_patterns() -> dict:
    """全量跑(10分钟周期)。"""
    s = Session()
    try:
        n1 = scan_archive_then_send(s)
        n2 = scan_rename_disguise(s)
        n3 = scan_trend_spike(s)
        from db import write_lock as _wl
        with _wl:  # 铁律: 写经统一写锁串行(2026-08-26补)
            s.commit()
        return {"archive_send": n1, "rename_disguise": n2, "trend_spike": n3}
    finally:
        s.close()
