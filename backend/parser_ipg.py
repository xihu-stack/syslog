"""IP-Guard(OTransLog) syslog 解析器。

报文格式(RFC5424 + JSON载荷):
  <134>1 2026-08-20T17:32:41Z 10.4.128.9 OTransLog.exe 9208 url_log - BOM{"URL_...":...}
日志类型: url_log / doc_log / keyword_search_log

用户解析链(2026-08-20设计):
  1) doc_log 的 DOC_SRC_PATH 含 Windows 账号(C:\\Users\\<account>\\) → 建立
     AGT_ID→账号 映射(settings键 ipg_agt_map,节流持久化);
  2) url/keyword 日志按同 AGT_ID 反查账号;
  3) 账号(如 pannannan.huashen→pannannan)经 pipeline.ingest_events 的
     employee_alias 统一为中文名(拼音唯一命中自动生效,其余进待确认人工匹配);
  4) 无映射的用 IPG:<USR_ID> 占位 → 别名系统待确认清单人工处理。
  注意: AGT_ID 是 IPG 的机器/客户端编号(非DHCP IP),映射来源是文件路径里的
  真实登录账号——不做任何基于网络IP的员工推测(用户红线)。

DOC_SUBTYPE→动作(样例推断):
  1=打开 3=复制 4=重命名 6=删除 7=读取 8=修改 9=外发(微信/网页上传,DEST_DEV=5)
  10=下载(blob/web→本地) 23=压缩/解压
外发信号: SEND 动作 或 DEST_DEV=5(网络) → channel=NETWORK,驱动 data_exfiltration。
"""
from __future__ import annotations

import json
import re
import threading
from datetime import datetime

from models import CanonicalEvent

_RE_HEAD = re.compile(r"^<\d+>\d+\s+(\S+)\s+(\S+)\s+\S+\s+\d+\s+(\S+)\s+-\s+\ufeff?", re.S)
_RE_USER_PATH = re.compile(r"[Uu]sers[\\/]+([^\\/]+)[\\/]")

# IPG 设备代码(样例推断): 1=本地磁盘 5=网络/网页 0=无;USB等移动介质以实际推送为准归USB
_DEV_CH = {5: "NETWORK"}

_SUBTYPE_ACT = {"1": "OPEN", "3": "COPY", "4": "RENAME", "6": "DELETE", "7": "READ",
                "8": "MODIFY", "9": "SEND", "10": "DOWNLOAD", "23": "ARCHIVE"}

_CORP_SUFFIX = (".huashen", ".helixon", ".bio")   # 域账号后缀剥离

_agt_lock = threading.Lock()
_agt_map = None          # {str(agt_id): 账号} 机器级
_usr_map = None          # {str(usr_id): 账号} 人员级(优先)——doc路径反推,跨机器稳定
_agt_dirty = False
_last_persist = 0.0
_map_degraded = False    # settings加载失败→降级空映射(靠doc路径反推自愈),300s后重试
_map_retry_at = 0.0

# Windows系统级配置目录(非真实登录账号): C:\Users\Public|Default|All Users 是
# 程序写入路径,当账号会污染员工表(2026-08-26运行时已出现员工"public"的告警)
_SYS_PROFILES = {"public", "default", "default user", "all users"}


def _clean_account(a: str) -> str:
    a = (a or "").strip().lower()
    # 剥离域后缀+Windows配置文件编号(如 lingjiayi.huashen.000 → lingjiayi;
    # Windows域用户配置文件冲突时自动加.000/.001等后缀)
    import re as _re2
    a = _re2.sub(r"\.(huashen|helixon)\.\d+$", "", a)
    for suf in _CORP_SUFFIX:
        if a.endswith(suf):
            a = a[: -len(suf)]
    return a


def _load_map():
    global _agt_map, _usr_map, _map_degraded, _map_retry_at
    if not _map_degraded and _agt_map is not None:
        return
    import time as _time
    if _map_degraded and _time.time() < _map_retry_at:
        return  # 冷却期内: 继续用降级映射(doc路径反推在持续重建)
    try:
        import dicts
        raw = dicts.get_setting("ipg_agt_map") or "{}"
        am = json.loads(raw) if isinstance(raw, str) else dict(raw or {})
        raw2 = dicts.get_setting("ipg_usr_map") or "{}"
        um = json.loads(raw2) if isinstance(raw2, str) else dict(raw2 or {})
        # 合并不覆盖: 降级期间_remember新学的映射不能丢
        if _agt_map:
            am.update(_agt_map)
        if _usr_map:
            um.update(_usr_map)
        _agt_map, _usr_map = am, um
        _map_degraded = False
    except Exception as _e:
        # 2026-08-26修复: 旧版异常时_usr_map={}但_agt_map保持None→后续.agt上
        # AttributeError,所有IPG报文静默解析失败且无日志。降级为空dict+定时重试,
        # 身份先由doc路径反推(_remember)自愈重建
        _map_degraded = True
        _map_retry_at = _time.time() + 300
        _agt_map = _agt_map if _agt_map is not None else {}
        _usr_map = _usr_map if _usr_map is not None else {}
        print(f"[parser_ipg] 账号映射加载失败,降级空映射靠路径反推(300s后重试): {_e}", flush=True)


def _remember(agt_id, usr_id, account):
    """doc路径反推出 AGT→账号 + USR→账号(人员级,优先),节流持久化(60s一次)。"""
    global _agt_dirty, _last_persist
    import time
    acc = _clean_account(account)
    if not acc:
        return
    with _agt_lock:
        _load_map()
        changed = False
        if agt_id and _agt_map.get(str(agt_id)) != acc:
            _agt_map[str(agt_id)] = acc
            changed = True
        if usr_id and _usr_map.get(str(usr_id)) != acc:
            _usr_map[str(usr_id)] = acc
            changed = True
        _agt_dirty = _agt_dirty or changed
        now = time.time()
        if _agt_dirty and now - _last_persist > 60:
            try:
                import dicts
                dicts.set_setting("ipg_agt_map", json.dumps(_agt_map, ensure_ascii=False))
                dicts.set_setting("ipg_usr_map", json.dumps(_usr_map, ensure_ascii=False))
                _agt_dirty = False
                _last_persist = now
            except Exception:
                pass


def _resolve(agt_id, usr_id, account_hint=None):
    """身份解析(2026-08-20用户口径: AGT_ID=计算机ID,机器对应使用人):
    路径账号(最权威) > AGT计算机映射 > USR映射 > IPG:<AGT>占位(人工匹配)。"""
    if account_hint:
        return _clean_account(account_hint)
    with _agt_lock:
        _load_map()
        acc = _agt_map.get(str(agt_id)) if agt_id else None
        if not acc:
            acc = _usr_map.get(str(usr_id)) if usr_id else None
    if acc:
        return acc
    return f"IPG:{agt_id or usr_id}"


def parse_ipg_syslog(text: str):
    """IPG syslog → CanonicalEvent;非IPG报文返回None。"""
    if "OTransLog" not in (text or ""):
        return None
    m = _RE_HEAD.match(text or "")
    if not m:
        return None
    kind = m.group(3)
    i = text.find("{")
    if i < 0:
        return None
    try:
        d = json.loads(text[i:].lstrip("﻿"))
    except Exception:
        return None
    # 字段前缀映射(2026-08-21修复: keyword_search_log切分首段是keyword,
    # 拼KEYWORD_AGT_ID取不到→被无ID规则全量误杀,当天179条搜索词零入库)
    _PRE = {"url_log": "URL", "doc_log": "DOC", "keyword_search_log": "KS"}
    pre = _PRE.get(kind)
    if not pre:  # 未知类型: 按TIME字段探测前缀,探测不到才放弃
        for p in ("URL", "DOC", "KS", "APP", "PRINT", "USB", "MAIL", "PROC"):
            if f"{p}_TIME" in d or f"{p}_CLT_TIME" in d:
                pre = p
                break
    if not pre:
        return None
    tstr = d.get(f"{pre}_TIME") or d.get(f"{pre}_CLT_TIME")
    try:
        occ = datetime.strptime(tstr, "%Y-%m-%d %H:%M:%S")
    except Exception:
        occ = datetime.now()
    agt = d.get(f"{pre}_AGT_ID")
    usr = d.get(f"{pre}_USR_ID")
    if not agt and not usr:  # 无任何身份标识,无法归属——不产事件(原始报文仍留存)
        return None

    if kind == "url_log":
        dom = (d.get("URL_SITE") or "").lower() or (d.get("URL_URL") or "")
        return CanonicalEvent(
            occurred_at=occ, employee_id=_resolve(agt, usr), device_id=str(agt),
            category="WEB", action="VISIT", target_type="URL",
            target_value=d.get("URL_URL") or dom, size_bytes=0, count=1,
            source="ipguard",
            raw={"domain": dom, "url": d.get("URL_URL") or "", "app": d.get("URL_APP_NAME") or "",
                 "title": d.get("URL_APP_TITLE") or ""})

    if kind == "keyword_search_log":
        return CanonicalEvent(
            occurred_at=occ, employee_id=_resolve(agt, usr), device_id=str(agt),
            category="SEARCH", action="SEARCH", target_type="KEYWORD",
            target_value=d.get("KS_KEYWORD") or "", size_bytes=0, count=1,
            source="ipguard",
            raw={"domain": (d.get("KS_SITE") or "").lower(), "app": d.get("KS_APP_NAME") or "",
                 "title": d.get("KS_APP_TITLE") or ""})

    if kind == "doc_log":
        sub = str(d.get("DOC_SUBTYPE") or "")
        act = _SUBTYPE_ACT.get(sub, "OPEN")
        src_path = d.get("DOC_SRC_PATH") or ""
        hint = None
        mu = _RE_USER_PATH.search(src_path) or _RE_USER_PATH.search(d.get("DOC_DEST_PATH") or "")
        if mu:
            hint = mu.group(1)
            if hint.lower() in _SYS_PROFILES:
                hint = None  # 系统配置目录不是登录账号,不建映射也不当员工名
            else:
                _remember(agt, usr, hint)
        dev = d.get("DOC_DEST_DEVICE")
        ch = _DEV_CH.get(dev if isinstance(dev, int) else int(dev or 0), "LOCAL")
        if act == "SEND" and ch == "LOCAL":
            ch = "NETWORK"  # SEND语义即外发
        return CanonicalEvent(
            occurred_at=occ, employee_id=_resolve(agt, usr, hint), device_id=str(agt),
            category="DOC", action=act, target_type="FILE",
            target_value=d.get("DOC_SRC_NAME") or src_path,
            size_bytes=int(d.get("DOC_FILE_SIZE") or 0), count=1,
            source="ipguard",
            raw={"channel": ch, "src_path": src_path[:400],
                 "dest_path": (d.get("DOC_DEST_PATH") or "")[:400],
                 "app": d.get("DOC_APP_NAME") or "", "doc_subtype": sub})
    return None
