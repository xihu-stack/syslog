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
        # 压缩文件名与外发文件名有关联(同名/包含关系)。
        # 2026-09-01审计: 旧版any()命中后摘要展示archives[0]而非命中的那条(证据张冠
        # 李戴,压缩A却写成外发B的依据);且光杆日期名(如"20260825")子串命中一切带
        # 当日日期的外发名。改为: 命中哪条展示哪条;纯数字/日期弱名只许强匹配(相等)。
        _weak_name = re.compile(r"^[\d\s\-._]{4,}$")
        arch_names = {(e.target_value or "").lower() for e in archives}
        for send in sends:
            sn = (send.target_value or "").lower()
            base = re.sub(r"\.(zip|rar|7z|tar|gz)$", "", sn)
            hit = None
            for an in arch_names:
                if an == sn or an == base:
                    hit = an
                    break
                if not _weak_name.fullmatch(an) and (an in sn or base in an or sn in an):
                    hit = an
                    break
            if hit is not None:
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
                               summary=(f"{emp}在{day}先压缩『{hit[:30]}』"
                                        f"再经{_app or '网络'}外发『{sn[:30]}』至{dest[:40]},属打包后蓄意带走模式"),
                               dedup_key=key,
                               window_start=send.occurred_at, created_at=bj_now(), status="NEW"))
                created += 1
                print(f"[pattern] {emp} 压缩→外发 -> 85分", flush=True)
                break
    return created


# ---------- 4) 改名掩盖检测 ----------
# 2026-09-01审计: 旧规则只看"变短+新名无大写编号",两路误报——①下载件的哈希
# 临时名改回有义英文名,是命名不是掩盖;②"新建文件夹(2)"改日期,默认名本无语义
# 可掩。改为双侧语义判定: 原名真有语义且非默认名,新名真失去语义(默认名不算
# 语义),才谈得上"掩盖"。另原名/新名此处均已lower(),大写类永不命中是死码,
# 语义改用小写类(英文词/项目编号)匹配。
_DEFAULT_NAME = re.compile(r"^新建(文件夹|压缩文件夹|文本文档)( ?\(\d+\))?"
                           r"(\.[a-z0-9]{1,5})?$|^untitled", re.I)
_HAS_SEMANTIC = re.compile(r"[一-鿿]|[a-z]{4,}|[a-z]{2,}[-_]\d")


def _name_semantic(name: str) -> bool:
    """文件名携带可丢失的语义(非默认名,且有中文/英文词/项目编号)。"""
    return not _DEFAULT_NAME.match(name) and bool(_HAS_SEMANTIC.search(name))


def scan_rename_disguise(s) -> int:
    """原名有语义 → 改成显著更短且无语义的名字 → 再外发 = 掩盖。"""
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
            # 判定"掩盖": 原名有语义,新名失去语义,且长度不到原名一半
            if _name_semantic(src) and not _name_semantic(dest_name) \
                    and len(dest_name) < len(src) * 0.5:
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
            # 周键(2026-08-31): 比较本身是"本周vs上周"的周级事实,原按日键在趋势
            # 持续期间每天克隆一条75分NEW(当日审计: 同人4条并排且数字三天不变)。
            # 同一ISO周只留一行,周内数据变化才刷新;处置态不复活不重置(08-28口径)。
            iso = now.isocalendar()
            key = f"{emp}|trend_exfil|{iso[0]}-W{iso[1]:02d}"
            sm = (f"{emp}本周外发{cur_send}次(上周{prev_send}次),"
                  f"环比增长{cur_send/max(prev_send,1):.0f}倍,属外发量突增")
            existing = s.query(AlertRow).filter_by(dedup_key=key).first()
            if not existing:
                s.add(AlertRow(employee_id=emp, scenario="trend_spike",
                               severity="HIGH", risk_score=75,
                               summary=sm, dedup_key=key,
                               window_start=now, created_at=bj_now(), status="NEW"))
                created += 1
                print(f"[pattern] {emp} 外发环比{cur_send}vs{prev_send} -> 75分", flush=True)
            elif existing.status == "NEW" and (existing.summary or "") != sm:
                existing.summary = sm  # 数字有变才刷说明/窗口,不变不无谓续命(否则永不超龄)
                existing.window_start = now
        # 日更键时代的旧快照收编(无条件): 同一趋势的按日克隆行结构上已被周键
        # 取代,不收编则每人每天挂一条直到7天超龄,详情页并排数条同文案
        for old in s.query(AlertRow).filter(AlertRow.employee_id == emp,
                                            AlertRow.scenario == "trend_spike",
                                            AlertRow.status == "NEW").all():
            tail = (old.dedup_key or "").rsplit("|", 1)[-1]
            if "-W" in tail or (old.summary or "").startswith("["):
                continue  # 周键行/带标记的复核行不动
            old.status = "CLOSED"
            old.summary = "[周期合并:同一环比趋势已按周聚合,此日快照关闭] " + (old.summary or "")[:120]
            print(f"[pattern] {emp} trend日快照并周键 alert#{old.id}", flush=True)
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
