FROM python:3.11-slim-bookworm

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Chromium 运行所需的最小系统库 + 基础工具
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Chromium/Playwright 运行库
    libasound2 libatk-bridge2.0-0 libatk1.0-0 libatspi2.0-0 \
    libdrm2 libgbm1 libglib2.0-0 libgtk-3-0 libnspr4 libnss3 \
    libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxdamage1 \
    libxext6 libxfixes3 libxkbcommon0 libxrandr2 libxss1 libxtst6 \
    # 证书与健康检查需要
    ca-certificates curl \
    fonts-liberation fonts-noto-color-emoji \
    && rm -rf /var/lib/apt/lists/*

# 安装 Python 依赖（包含 playwright）
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && rm -rf /root/.cache/pip

# 只安装 Chromium
RUN python -m playwright install chromium \
    && rm -rf /root/.cache/*

COPY playwright_api_server.py .

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -fsS http://localhost:8080/health || exit 1

CMD ["python", "playwright_api_server.py"]

