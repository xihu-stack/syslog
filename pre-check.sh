#!/bin/bash
# IP-Guard AI 系统部署前环境检测（Rocky Linux）
# 用法: bash pre-check.sh

echo "======================================"
echo "  IP-Guard AI 系统部署前环境检测"
echo "======================================"
echo ""

# 1. OS
echo "【1】操作系统"
if [ -f /etc/rocky-release ]; then
    echo "  ✅ $(cat /etc/rocky-release)"
else
    echo "  ⚠️ $(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)"
fi
echo ""

# 2. Docker
echo "【2】Docker"
if command -v docker &>/dev/null; then
    echo "  ✅ $(docker --version)"
else
    echo "  ❌ 未安装 Docker"
    echo "     一键安装: curl -fsSL https://get.docker.com | sudo sh"
    echo "     启动: sudo systemctl enable --now docker"
fi
echo ""

# 3. Docker Compose
echo "【3】Docker Compose"
if docker compose version &>/dev/null 2>&1; then
    echo "  ✅ $(docker compose version 2>&1 | head -1)"
elif command -v docker-compose &>/dev/null; then
    echo "  ✅ $(docker-compose --version)"
else
    echo "  ❌ 未安装 Docker Compose（Docker 20.10+ 自带 compose 插件）"
fi
echo ""

# 4. Docker running
echo "【4】Docker 服务"
if systemctl is-active --quiet docker 2>/dev/null; then
    echo "  ✅ 运行中"
else
    echo "  ❌ 未运行 → sudo systemctl start docker"
fi
echo ""

# 5. LLM connectivity
echo "【5】LLM 代理连通 (10.4.128.18:4000)"
if curl -sf --connect-timeout 5 http://10.4.128.18:4000/v1/models &>/dev/null; then
    echo "  ✅ 可访问"
else
    echo "  ❌ 无法访问 — 检查网络/路由/防火墙"
fi
echo ""

# 6. Ports
echo "【6】端口占用"
for p in 8000 8514; do
    if ss -tuln 2>/dev/null | grep -q ":$p "; then
        echo "  ⚠️ 端口 $p 已占用"
    else
        echo "  ✅ 端口 $p 可用"
    fi
done
echo ""

# 7. Firewall
echo "【7】防火墙 (firewalld)"
if systemctl is-active --quiet firewalld 2>/dev/null; then
    echo "  ⚠️ firewalld 运行中，需开放端口："
    echo "     sudo firewall-cmd --permanent --add-port=8000/tcp"
    echo "     sudo firewall-cmd --permanent --add-port=8514/udp"
    echo "     sudo firewall-cmd --reload"
else
    echo "  ✅ firewalld 未运行"
fi
echo ""

# 8. SELinux
echo "【8】SELinux"
sel=$(getenforce 2>/dev/null || echo "Disabled")
if [ "$sel" = "Enforcing" ]; then
    echo "  ⚠️ SELinux Enforcing（Docker 可能受限）"
    echo "     临时关闭: sudo setenforce 0"
else
    echo "  ✅ SELinux $sel"
fi
echo ""

# 9. Disk
echo "【9】磁盘空间"
avail=$(df / 2>/dev/null | tail -1 | awk '{print $4}')
avail_gb=$((avail / 1024 / 1024))
echo "  根分区可用: ${avail_gb}GB $([ $avail_gb -ge 5 ] && echo '✅' || echo '⚠️ <5GB')"

# 10. Memory
echo "【10】内存"
mem=$(free -g 2>/dev/null | awk '/Mem:/{print $2}')
echo "  总内存: ${mem}GB $([ ${mem:-0} -ge 2 ] && echo '✅' || echo '⚠️ <2GB')"

echo ""
echo "======================================"
echo "  检测完成。❌ 的项需要先处理再部署。"
echo "======================================"
