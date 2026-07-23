# 部署指南（极简版）

## 一句话部署
```bash
git clone https://github.com/xihu-stack/syslog.git && cd syslog && docker compose up -d --build
```

## 完成！然后：
1. 浏览器打开 **`http://<服务器IP>:8000`**
2. 左侧菜单 → **「后台配置」**
3. 填入 **LLM 地址 + 密钥 + 模型名** → 点「保存」
4. 回「监控大屏」→ 点「导入日志」上传 IP-Guard / 深信服导出文件
5. 或在「后台配置」里启动 **Syslog 接收**，深信服 AC 推送到 `<服务器IP>:8514`

**不需要手动编辑任何配置文件。** LLM 地址/密钥/模型全部在浏览器后台页面设置。

---

## 没有 Docker？手动部署
```bash
git clone https://github.com/xihu-stack/syslog.git
cd syslog/backend
pip install -r requirements.txt
python api.py
```
然后同样浏览器打开 `http://<服务器IP>:8000` → 后台配置。

---

## 端口
| 端口 | 用途 |
|---|---|
| 8000 | Web 界面 + API |
| 8514/UDP | Syslog 接收 |

## 数据
- SQLite 自动创建在 `backend/data/ipguard.db`，Docker 挂载持久化
- 切 PostgreSQL：后台配置或环境变量 `DATABASE_URL=postgresql+psycopg2://...`
