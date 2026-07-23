"""合成场景：证明网页浏览/关键字搜索的检测路径能抓到风险（真实数据是良性，故用合成验证）。"""
from datetime import datetime

from models import CanonicalEvent, Category
from parser_ipguard import domain_class, url_domain
from detector import detect


def web(t, emp, url):
    d = url_domain(url)
    return CanonicalEvent(datetime(2026, 7, 22, *t), emp, emp, Category.WEB.value,
                          "VISIT", "URL", url, raw={"domain": d, "domain_class": domain_class(d)})


def search(t, emp, kw, eng="www.baidu.com"):
    return CanonicalEvent(datetime(2026, 7, 22, *t), emp, emp, Category.SEARCH.value,
                          "SEARCH", "URL", kw, raw={"keyword": kw, "search_engine": eng})


def doc(t, emp, action, fn, channel="LOCAL"):
    return CanonicalEvent(datetime(2026, 7, 22, *t), emp, emp, Category.DOC.value,
                          action, "FILE", fn, raw={"channel": channel, "application": "EXCEL.EXE"})


events = [
    # 场景1：求职 —— 招聘网站 + 搜简历/待遇
    web((9, 10), "HLX-SZ-张三", "https://www.zhaopin.com/"),
    web((9, 25), "HLX-SZ-张三", "https://www.zhipin.com/"),
    search((9, 40), "HLX-SZ-张三", "简历模板"),
    search((10, 0), "HLX-SZ-张三", "Java工程师 待遇 猎头"),
    # 场景2：外发 —— 敏感文档 + 网盘 + 高危搜索
    doc((14, 0), "HLX-BJ-李四", "COPY", "客户名单.xlsx", "LOCAL"),
    web((14, 10), "HLX-BJ-李四", "https://pan.baidu.com/"),
    search((14, 15), "HLX-BJ-李四", "怎么把文件传到网盘不被发现"),
]

verdicts, alerts = detect(events, risk_threshold=50)
for it in verdicts:
    v = it["verdict"]
    print(f"[{it['window_start']:%H:%M}] {it['employee']}  风险={v.get('risk_score')}  "
          f"意图={v.get('intent')}  偏离={v.get('deviation')}")
    print("   ", v.get("explanation"))
    print("    通道:", v.get("channels"))
print(f"\n>>> 生成告警 {len(alerts)} 条（风险>=50）")
