# 无人机运行管理服务基础工程

这是面向无人机空域合规、机队运行和安全处置的 Python 服务基础工程，保留进程健康检查和运行配置，业务模块按实际审批、调度或追踪场景接入。

当前已接入 **远程识别登记与异常核查服务**：把设备注册、操作员、飞行授权、广播序列和接收站观测组织成可追溯关联，对重复身份、不可达速度、过期证书、位置跳变等异常建立人工复核案件。

## 运行

需要 Python 3.11 或更高版本。直接执行 `python src/index.py` 启动服务，默认监听 8000 端口；`python -m unittest discover` 执行基线测试，也可以使用 `docker compose up --build` 启动容器。

数据落盘位置由运行时配置指定：`RID_DB_PATH` 优先，其次 `DATA_DIR` 目录下的 `rid.db`，默认 `./.data/rid.db`。未结案件与复核时限以绝对时间落库，服务重启后照常推进。

## 角色与脱敏

请求头 `X-Role` 携带角色（中文名需 percent-encoding）：`放行员`、`机务人员`、`监管人员`、`调查员`、`只读用户`（缺省）。操作员的个人联系方式仅 `调查员` 可见，其余角色一律返回 `***`。`X-Actor` 可指定处置动作的署名。

## 主要接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 进程健康检查 |
| POST | `/operators` / `/devices` / `/devices/{id}/certificates` / `/authorizations` / `/receivers` | 登记操作员、设备、证书（可多张轮换）、飞行授权、接收站 |
| POST | `/observations` | 接入接收站观测（批量），自动去重并触发检测 |
| POST | `/detections/run` | 手动触发检测（幂等） |
| GET | `/identities` / `/identities/{remote_id}` | 监管检索：冲突时间段、关联依据、检测规则、处置进展 |
| GET | `/cases` / `/cases/{id}` | 案件检索（支持 `status`、`remote_id`、`overdue` 过滤） |
| POST | `/cases/{id}/events` | 追加证据事件：`comment`/`review`/`escalate`/`exclude`/`resolve`/`reopen`/`merge` |
| GET | `/findings?remote_id=` | 检测发现列表 |

### 观测接入示例

```json
POST /observations
{
  "receiver_id": "rx-01",
  "observations": [
    {"message": {"message_id": "m-1", "remote_id": "RID-001", "timestamp": "2026-09-20T12:00:00Z",
                 "lat": 31.2, "lon": 121.5, "alt": 120, "speed": 12, "heading": 90, "seq": 1},
     "received_at": "2026-09-20T12:00:01Z"}
  ]
}
```

## 检测与核查原则

- 报文按 `(remote_id, message_id)` 去重、按广播源时间排序后构建航迹，乱序或重复报文不会拼出虚假轨迹。
- 重复身份：同一时间窗内空间分离超过阈值（默认 60 秒 / 1000 米）；不可达速度：默认 75 m/s；位置跳变：默认 2 秒内 500 米。
- 证书轮换期间任一证书覆盖广播时间即保持身份连续；全部未覆盖才形成过期证书发现。
- 接收站时钟漂移只下调证据可信度，不直接形成定性；所有异常均进入人工复核案件。
- 案件的合并、排除、升级均以追加证据完成，事件流不可篡改。
