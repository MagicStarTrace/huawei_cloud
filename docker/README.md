# Huawei Location Bridge - 后端服务

基于 Playwright + FastAPI 的后端定位服务，负责与华为云空间通信，提供设备定位 API。

## 快速开始

### 环境配置

```bash
cp env.example .env
```

| 环境变量 | 说明 | 默认值 |
|----------|------|--------|
| `STORAGE_STATE_PATH` | 登录会话存储路径 | `/app/data/storage_state.json` |
| `DEBUG_MODE` | 调试模式（`1`=开启详细日志） | `0` |
| `PORT` | 服务监听端口 | `8080` |

> **什么时候需要 `.env` 文件？**
>
> 如果你使用默认配置（端口 8000、调试关闭），可以跳过 `.env`，直接运行下方命令即可。
> 如果需要改端口、开调试模式或自定义存储路径，请先 `cp env.example .env` 并修改，然后在 `docker run` 时加上 `--env-file .env`。

### 使用预构建镜像（推荐）

```bash
# 国内用户（阿里云镜像）
docker run -d \
  --name huawei-location-bridge \
  -p 8000:8080 \
  --restart unless-stopped \
  registry.cn-hangzhou.aliyuncs.com/magicstartrace/huawei-location-bridge:latest

# 海外用户（Docker Hub）
docker run -d \
  --name huawei-location-bridge \
  -p 8000:8080 \
  --restart unless-stopped \
  magicstartrace/huawei-location-bridge:latest

# 如需自定义配置，加上 --env-file：
docker run -d \
  --name huawei-location-bridge \
  -p 8000:8080 \
  --env-file .env \
  --restart unless-stopped \
  magicstartrace/huawei-location-bridge:latest
```

> **关于数据持久化（可选）**：加上 `-v $(pwd)/data:/app/data` 可以保留登录会话，容器重启后无需重新登录。不加也能正常使用，只是每次重启容器需要重新登录（约 30-60 秒）。

### 从源码构建

```bash
cd docker
docker build -t huawei-location-bridge .

docker run -d \
  --name huawei-location-bridge \
  -p 8000:8080 \
  --restart unless-stopped \
  huawei-location-bridge
```

### Docker Compose

> 在项目根目录下创建 `docker-compose.yml`：

```yaml
services:
  huawei-location-bridge:
    build: ./docker
    container_name: huawei-location-bridge
    ports:
      - "8000:8080"
    # volumes:                    # 可选：保留登录会话，容器重启后无需重新登录
    #   - ./data:/app/data
    # env_file:                   # 可选：自定义端口、调试模式等
    #   - ./docker/.env
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
```

## API 文档

所有 POST 请求均使用 JSON 格式。

### GET /health

健康检查。

**响应示例：**

```json
{"status": "ok", "version": "2.3.0-fast-login"}
```

---

### GET /status

查询服务状态。

**请求参数（可选）：** `?session_key=xxx`

**响应示例（无 session_key）：**

```json
{
  "version": "2.3.0-fast-login",
  "total_sessions": 1,
  "storage_dir": "/data"
}
```

**响应示例（带 session_key）：**

```json
{
  "logged_in": true,
  "need_reauth": false,
  "last_err_reason": null,
  "session_key": "abc123",
  "storage_exists": true,
  "version": "2.3.0-fast-login"
}
```

---

### POST /auth/ensure

确保登录状态，未登录时自动触发后台登录。

**请求体：**

```json
{
  "session_key": "用户唯一标识",
  "username": "华为账号",
  "password": "华为密码"
}
```

**响应示例：**

```json
{
  "ok": true,
  "status": "SESSION_VALID",
  "message": "会话有效",
  "session_key": "abc123"
}
```

`status` 取值：`SESSION_VALID`、`ALREADY_READY`、`IN_PROGRESS`、`LOGIN_TRIGGERED`

---

### POST /login

`/auth/ensure` 的兼容别名，参数和响应完全相同。

---

### POST /sync

快速同步设备位置（被动缓存，不触发主动定位）。

**请求体：**

```json
{
  "session_key": "用户唯一标识"
}
```

**响应示例：**

```json
{
  "code": 0,
  "ok": true,
  "need_reauth": false,
  "message": "获取到 2 个设备",
  "devices": [
    {
      "device_id": "xxx",
      "name": "HUAWEI Mate 40 Pro",
      "lat": 31.2304,
      "lng": 121.4737,
      "accuracy": 50,
      "battery": 85,
      "locate_time": 1707500000
    }
  ],
  "device_count": 2,
  "cost_ms": 1200,
  "session_key": "abc123"
}
```

---

### POST /locate

主动触发定位并等待结果（最多 15 秒），最小调用间隔 60 秒。

**请求体：**

```json
{
  "session_key": "用户唯一标识"
}
```

**响应示例：**

```json
{
  "ok": true,
  "code": 0,
  "message": "定位完成",
  "devices": [
    {
      "device_id": "xxx",
      "name": "HUAWEI Mate 40 Pro",
      "lat": 31.2304,
      "lng": 121.4737,
      "accuracy": 30,
      "battery": 85
    }
  ],
  "cost_ms": 5000,
  "session_key": "abc123"
}
```

> 限频保护：两次调用间隔不足 60 秒时返回 `code=-2`。

---

### POST /findDevice/locate

触发设备定位请求（不等待结果），需配合 `/findDevice/queryLocateResult` 获取坐标。

**请求体：**

```json
{
  "session_key": "用户唯一标识"
}
```

**响应示例：**

```json
{
  "code": 0,
  "ok": true,
  "message": "触发定位完成",
  "devices_triggered": 2,
  "devices_failed": 0,
  "results": [
    {
      "device_id": "xxx",
      "status": "triggered",
      "device_name": "HUAWEI Mate 40 Pro"
    }
  ],
  "cost_ms": 800,
  "session_key": "abc123"
}
```

---

### POST /findDevice/queryLocateResult

查询定位结果（单次查询，不轮询）。

**请求体：**

```json
{
  "session_key": "用户唯一标识"
}
```

**响应示例：**

```json
{
  "code": 0,
  "ok": true,
  "message": "查询完成",
  "devices": [
    {
      "device_id": "xxx",
      "name": "HUAWEI Mate 40 Pro",
      "latitude": 31.2304,
      "longitude": 121.4737,
      "battery": 85,
      "accuracy": 30,
      "ts": 1707500000,
      "locate_code": 0
    }
  ],
  "device_count": 2,
  "cost_ms": 600,
  "session_key": "abc123"
}
```

`locate_code`：`0` 或 `1` 表示定位成功，其他值表示未完成或失败。

---

## 错误码

| code | 说明 |
|------|------|
| `0` | 成功 |
| `-1` | 网络错误 / 异常 |
| `-2` | 限频（60 秒内重复调用） |
| `990` | 认证失败，需重新登录 |

## 坐标系说明

API 优先返回 **WGS-84** 坐标（全球 GPS 标准）。当 WGS-84 不可用时，自动将 GCJ-02（国测局坐标）转换为 WGS-84。
