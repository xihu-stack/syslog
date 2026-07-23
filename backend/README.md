# IP-Guard 员工行为 AI 分析系统（v1）

用本地大模型（Qwen3-32B）分析 IP-Guard 日志，识别**数据泄露 / 求职离职 / 行为偏离**，近实时告警。

## 快速开始

```powershell
# 1. 装依赖（首次）
python -m pip install openpyxl sqlalchemy fastapi "uvicorn[standard]" python-multipart

# 2. （可选）清空旧数据，从头开始
Remove-Item "D:\代码\日志平台\backend\data\ipguard.db" -ErrorAction SilentlyContinue

# 3. 启动服务
python "D:\代码\日志平台\backend\api.py"
```
看到 `Uvicorn running on http://127.0.0.1:8000` 后，**浏览器打开 http://127.0.0.1:8000**：
- 点 **「导入日志」** 上传 IP-Guard 导出的 xlsx（可逐个上传：文档操作 / 网页浏览 / 关键字搜索）
- 系统自动解析 → 建画像 → AI 检测 → 落库
- 左侧看「全部 AI 判断」与「告警」，**点任意一条**看 AI 解释 + 证据时间线 + 该员工基线

## 支持的日志类型（按 sheet 名自动识别）

| 日志 | 关键列 | 标准大类 |
|---|---|---|
| 文档操作日志 | 类型/时间/计算机/用户/源文件/文件大小/路径/磁盘类型/应用程序 | DOC |
| 网页浏览日志 | 时间/计算机/用户/标题/网址 | WEB |
| 关键字搜索日志 | 时间/计算机/用户/搜索关键字/应用程序/域名 | SEARCH |

> 身份按**计算机名**识别（如 `HLX-BJ-孙翔宇`，内嵌姓名、稳定可读）。

## 检测能力（AI 判断意图 + 风险 + 偏离基线）

- **数据外发**：敏感文档 + U盘 / 网盘 / 个人邮箱 / 浏览器上传；规避行为（改名/压缩）
- **求职离职**：招聘网站 + 搜简历/跳槽/待遇
- **行为偏离**：时段 / 数量 / 通道 / 对象 偏离个人基线
- **高危搜索**：绕过DLP / 网盘 / 数据恢复 / 匿名邮箱 等
- LLM 不可用时自动**规则兜底**，闭环不断

## 配置（`backend/.env`，已 gitignore，勿提交）
```
LLM_BASE_URL=http://10.4.128.18:4000/v1
LLM_API_KEY=sk-...
LLM_MODEL=Qwen3-32B
```

## CLI 工具（不启服务也能用）
```powershell
python backend\run_parse.py   C:\Users\huxi\Desktop\111.xlsx   # 只解析，看标准事件
python backend\run_detect.py  C:\Users\huxi\Desktop\111.xlsx   # 解析 + AI 检测
python backend\pipeline.py    C:\Users\huxi\Desktop\111.xlsx   # 导入+画像+检测+落库
```

## 代码结构
| 文件 | 职责 |
|---|---|
| `models.py` | 标准事件 + 动作映射 |
| `parser_ipguard.py` | 三类 Excel 日志解析（自动识别表头/域名分类） |
| `llm_client.py` | 本地 LLM 客户端 + 鲁棒 JSON 解析 |
| `detector.py` | 攒窗口 → 触发门 → LLM 意图/偏离/风险 → 兜底 |
| `profiles.py` | 行为基线画像 |
| `db.py` | SQLAlchemy 持久化（SQLite） |
| `pipeline.py` | 导入→画像→检测→告警落库（带去重） |
| `api.py` | FastAPI 接口 + 托管前端 |
| `static/index.html` | 前端看板（无构建） |

## 升级路径
- **换 Postgres**：设环境变量 `DATABASE_URL=postgresql+psycopg2://user:pwd@host/db`（代码无需改）
- **换 React 前端**：`static/` 替换为 React 构建产物，API 不变
- **Syslog 实时接入**：在 `ingest` 之外加一个 syslog 接收器，复用 `parser` 的解析逻辑

## 说明
- 当前为 **v1 最小可用版**：纯靠日志、零外部数据依赖、SQLite + 单页前端，重在跑通"解析→AI意图→告警→看板"闭环。
- 真实日志若全是良性操作，0 告警是**正确**表现（不误报）；可用 `demo_badcase.py` / `demo_websearch_badcase.py` 验证抓取能力。
