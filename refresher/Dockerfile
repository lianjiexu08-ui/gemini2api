FROM mcr.microsoft.com/playwright/python:v1.44.0-jammy

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends fonts-wqy-zenhei curl procps \
    && rm -rf /var/lib/apt/lists/*

# 固定 requests 版本，保证镜像可复现构建（避免每次重建拉到不同版本）。
RUN pip install --no-cache-dir playwright==1.44.0 requests==2.32.3

COPY refresher.py .

# 非 root 运行：playwright 基础镜像自带 pwuser，用它降权（缩小被 Chromium 渗透后的影响面）。
# /app 归属 pwuser，挂载进来的 /app/data 在运行时由 compose 处理写权限。
RUN chown -R pwuser:pwuser /app
USER pwuser

# 进程级心跳健康检查：refresher 卡死/退出（如 Chromium 崩溃）时标记为 unhealthy，
# 便于编排层自动重启（plain docker run / compose 均生效）。
HEALTHCHECK --interval=60s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f refresher.py >/dev/null || exit 1

CMD ["sh", "-c", "Xvfb :99 -screen 0 1920x1080x24 -nolisten tcp & sleep 1; export DISPLAY=:99; exec python -u refresher.py"]
