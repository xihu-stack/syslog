"""命令行入口：解析一个 IP-Guard Excel 导出，打印标准事件 + 简要统计。

用法:
    python run_parse.py [xlsx路径]
不传路径则默认解析桌面上的 111.xlsx。
"""
import csv
import os
import sys
from collections import Counter

from parser_ipguard import parse_ipguard_excel


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\huxi\Desktop\111.xlsx"
    events = parse_ipguard_excel(path)

    print(f"=== 解析到 {len(events)} 条标准事件  (来源: {path}) ===\n")
    for e in events:
        print(
            f"[{e.occurred_at:%Y-%m-%d %H:%M:%S}] "
            f"{e.employee_id:<12} {e.category}/{e.action:<7} "
            f"{e.target_value:<40} {e.size_bytes:>9}B  "
            f"通道={e.raw.get('channel'):<7} 应用={e.raw.get('application')}"
        )

    # ---- 简要统计，便于"看效果" ----
    print("\n--- 统计 ---")
    print("操作类型分布:", dict(Counter(e.action for e in events)))
    print("涉及员工:", dict(Counter(e.employee_id for e in events)))
    print("通道分布:", dict(Counter(e.raw.get("channel") for e in events)))

    # ---- 导出 UTF-8(BOM) CSV，Excel 直接打开不乱码 ----
    out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(out_dir, exist_ok=True)
    out_csv = os.path.join(out_dir, "parsed_events.csv")
    with open(out_csv, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["occurred_at", "employee_id", "device_id", "category", "action",
                    "target_value", "size_bytes", "channel", "application", "path", "op_type"])
        for e in events:
            w.writerow([e.occurred_at, e.employee_id, e.device_id, e.category, e.action,
                        e.target_value, e.size_bytes, e.raw.get("channel"),
                        e.raw.get("application"), e.raw.get("path"), e.raw.get("op_type")])
    print(f"\n已导出 CSV（Excel 可直接打开）: {out_csv}")


if __name__ == "__main__":
    main()
