# 部署指南

## 方式一：Docker 部署（推荐，服务器上一条命令）

### 前提
- 服务器已安装 Docker + Docker Compose
- 服务器内网能访问 LLM 代理（如 `10.4.128.18:4000`）

### 步骤
```bash
# 1. 克隆代码
git clone <repo-url> ipguard-ai
cd ipguard-ai

# 2. 配置模型密钥
cp .env.example backend/.env
vi backend/.env   # 填入实际的 LLM_BASE_URL / KEY / MODEL

# 3. 一键启动
docker-compose up -d --build

# 4. 验证
curl http://localhost:8000/api/stats
# 浏览器打开 http://<服务器IP>:8000
```

### 停止 / 更新
```bash
docker-compose down        # 停止
git pull && docker-compose up -d --build   # 更新
```

### 配置深信服 syslog 推送
- 深信服 AC → 日志设置 → Syslog 服务器：`<服务器内网IP>`，端口 `8514`，协议 UDP
- 系统自动接收 → 解析 → 降噪聚合 → AI 研判 → 告警

---

## 方式二：手动部署（无 Docker）

### 前提
- Python 3.11+
- pip

### 步骤
```bash
git clone <repo-url> ipguard-ai
cd ipguard-ai/backend

# 配置
cp ../.env.example .env
vi .env

# 装依赖
pip install -r requirements.txt

# 启动
python api.py
```

---

## 数据存储
- SQLite 文件：`backend/data/ipguard.db`
- Docker 部署：挂载在 `./backend/data/`，容器重建不丢数据

## 端口说明
| 端口 | 用途 |
|---|---|
| 8000 | Web 界面 + REST API |
| 8514/UDP | Syslog 接收（深信服推送） |

## 切换 PostgreSQL（可选）
```bash
# 在 backend/.env 加一行：
DATABASE_URL=postgresql+psycopg2://user:pwd@host/db
```
