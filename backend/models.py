"""标准事件模型 (canonical event) —— 整个系统的通用数据契约。

无论是 IP-Guard 的 Excel 导出还是 Syslog 推送，最终都归一化成 CanonicalEvent。
后续检测器、画像、告警都只认这个结构。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib


class Category(str, Enum):
    """日志大类。"""
    DOC = "DOC"        # 文档操作
    WEB = "WEB"        # 网页浏览
    SEARCH = "SEARCH"  # 网页搜索


# IP-Guard「类型」列的中文操作 → 标准动作枚举
DOC_ACTION_MAP = {
    "复制": "COPY",
    "修改": "MODIFY",
    "创建": "CREATE",
    "新建": "CREATE",
    "删除": "DELETE",
    "访问": "ACCESS",
    "打开": "ACCESS",
    "重命名": "RENAME",
    "移动": "MOVE",
    "剪切": "CUT",
    "打印": "PRINT",
    "读": "READ",
    "写": "WRITE",
    "保存": "SAVE",
    "另存": "SAVE_AS",
    "另存为": "SAVE_AS",
    "上传": "UPLOAD",     # 浏览器/应用上传 —— 外发相关
    "下载": "DOWNLOAD",
    "外发": "SEND",
    "发送": "SEND",
    "刻录": "BURN",
}


@dataclass
class CanonicalEvent:
    """一条归一化后的标准事件。"""
    occurred_at: datetime          # 事件发生时间
    employee_id: str               # 员工标识（归一化后）
    device_id: str                 # 计算机名
    category: str                  # Category 枚举值
    action: str                    # 标准动作（COPY/MODIFY/...）
    target_type: str               # FILE / URL / DEVICE
    target_value: str              # 文件名 / URL / 设备名
    size_bytes: int = 0            # 字节数（批量量纲）
    count: int = 1                 # 数量（批量量纲）
    source: str = ""               # 数据来源：ipguard / sangfor
    raw: dict = field(default_factory=dict)  # 原始字段兜底（路径/磁盘/应用/标题等）

    def event_hash(self) -> str:
        """稳定哈希，用于入库幂等去重。"""
        h = hashlib.sha256()
        h.update(self.occurred_at.isoformat().encode("utf-8"))
        h.update(b"|")
        h.update(self.employee_id.encode("utf-8"))
        h.update(b"|")
        h.update(self.category.encode("utf-8"))
        h.update(b"|")
        h.update(self.action.encode("utf-8"))
        h.update(b"|")
        h.update(self.target_value.encode("utf-8"))
        return h.hexdigest()
