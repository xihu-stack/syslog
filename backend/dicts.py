"""字典与应用配置：DB 持久化，检测器/解析器运行时读取（可由后台界面增删改）。

字典：sensitive_keywords / recruitment_sites / netdisk_domains /
      personal_email_domains / job_search_terms / risk_search_terms
配置(key-value)：llm_base_url / llm_api_key / llm_model / syslog_* 等。
"""
from __future__ import annotations

from db import DictRow, Session, SettingRow, init_db

DEFAULTS = {
    "sensitive_keywords": [
        "客户", "名单", "合同", "报价", "标书", "财务", "源码", "设计图", "设计",
        "申报", "简历", "MSA", "秘书公司", "薪酬", "工资", "护照", "签证", "专利",
        "密码", "账套", "报表", "离职",
    ],
    "recruitment_sites": [
        "zhaopin.com", "51job.com", "51job.cn", "lagou.com", "zhipin.com", "liepin.com",
        "boss.com", "bosszhipin", "zhilian", "jobcn.com", "51zhaopin", "linkedin.com",
        "maimai.cn", "kanzhun.com",
    ],
    "netdisk_domains": [
        "pan.baidu.com", "eyun.baidu.com", "alipan.com", "aliyundrive.com", "weiyun.qq.com",
        "jianguoyun.com", "onedrive.live.com", "dropbox.com", "115.com", "lanzou.com",
        "lanzoux", "pan.xunlei.com", "cloud.189.cn", "yun.139.com", "pan.quark.cn",
    ],
    "personal_email_domains": [
        "mail.qq.com", "mail.163.com", "mail.126.com", "gmail.com", "outlook.live.com",
        "outlook.com", "mail.sina.com.cn", "mail.sohu.com", "mail.10086.cn", "mail.139.com",
        "mail.aliyun.com", "foxmail.com", "yahoo.com",
    ],
    "job_search_terms": [
        "简历", "招聘", "跳槽", "求职", "offer", "待遇", "工资", "薪酬", "猎头",
        "面试", "竞业", "竞对", "竞争对手",
    ],
    "risk_search_terms": [
        "网盘", "数据恢复", "匿名", "匿名邮箱", "临时邮箱", "绕过", "外发", "解密",
        "破解", "泄密", "u盘启动", "文件恢复", "截图", "窃取",
    ],
}

_inited = False
_cache: dict = {}


def _ensure():
    global _inited
    if _inited:
        return
    init_db()
    s = Session()
    try:
        for name, vals in DEFAULTS.items():
            if not s.query(DictRow).filter_by(name=name).first():
                s.add(DictRow(name=name, payload=list(vals)))
        s.commit()
        _inited = True
    finally:
        s.close()


def get(name: str) -> list:
    """取一个字典（带进程内缓存）。"""
    _ensure()
    if name in _cache:
        return _cache[name]
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        vals = d.payload if d else DEFAULTS.get(name, [])
        _cache[name] = vals
        return vals
    finally:
        s.close()


def set_dict(name: str, vals: list) -> None:
    _ensure()
    s = Session()
    try:
        d = s.query(DictRow).filter_by(name=name).first()
        if d:
            d.payload = list(vals)
        else:
            s.add(DictRow(name=name, payload=list(vals)))
        s.commit()
    finally:
        s.close()
    _cache.pop(name, None)  # 失效缓存，下次 get 重新读


def all_dicts() -> dict:
    _ensure()
    s = Session()
    try:
        out = {}
        for name in DEFAULTS:
            d = s.query(DictRow).filter_by(name=name).first()
            out[name] = d.payload if d else DEFAULTS[name]
        return out
    finally:
        s.close()


# ---------------- 应用配置（key-value）----------------

def get_setting(key: str, default=None):
    init_db()
    s = Session()
    try:
        r = s.query(SettingRow).filter_by(key=key).first()
        return r.value if r else default
    finally:
        s.close()


def set_setting(key: str, value):
    init_db()
    s = Session()
    try:
        r = s.query(SettingRow).filter_by(key=key).first()
        if r:
            r.value = value
        else:
            s.add(SettingRow(key=key, value=value))
        s.commit()
    finally:
        s.close()
