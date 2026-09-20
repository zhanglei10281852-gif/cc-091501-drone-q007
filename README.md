# 无人机远程识别登记与异常核查服务

面向城市低空监管的 Python 服务（纯标准库，Python 3.11+）：登记设备、操作员、
证书与飞行授权，接入接收站的 Remote ID 广播观测，检测重复身份、不可达速度、
位置跳变和过期证书，并建立人工复核案件。监管人员检索一个广播身份时，可以看到
冲突发生的时间段、各项关联依据、采用的检测规则和当前处置进展。

## 运行

需要 Python 3.11 或更高版本。直接执行 `python src/index.py` 启动服务，默认监听
8000 端口，数据落盘到 `DATA_DIR`（默认 `.data/`）下的 SQLite 文件，重启后未结
案件与复核时限照常推进。`python -m unittest discover` 执行全部测试，也可以使用
`docker compose up --build` 启动容器（数据卷 `rid-data` 持久化）。

## 接口

所有写接口需要请求头 `X-Actor-Role`（`regulator` / `investigator` / `system`），
检索接口缺省为只读角色；`X-Actor-Id` 记录操作者并写入案件时间线。

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 进程健康检查 |
| POST | `/v1/operators` | 登记操作员（联系方式仅调查员可见） |
| POST | `/v1/devices` | 登记设备 |
| POST | `/v1/devices/{id}/certificates` | 登记/轮换证书，`replaces_cert_id` 维持身份连续 |
| POST | `/v1/authorizations` | 登记飞行授权 |
| POST | `/v1/receivers` | 登记接收站（含时钟不确定度） |
| POST | `/v1/observations` | 批量摄入广播观测（幂等去重） |
| GET | `/v1/remote-ids/{id}` | 检索广播身份：冲突时段、关联依据、规则、进展 |
| GET | `/v1/cases` | 案件列表，支持 `status` / `overdue` 过滤 |
| GET | `/v1/cases/{id}` | 案件详情：证据链与时间线 |
| POST | `/v1/cases/{id}/evidence` | 追加证据或备注 |
| POST | `/v1/cases/{id}/dispositions` | 处置：`triage` / `escalate` / `exclude` / `resolve` / `merge` |

## 检测规则

- `duplicate_identity`：同一广播身份在同一时段出现在物理上不可同时到达的两地
  （各自连续的轨迹簇时间重叠且显著分离）。
- `unreachable_speed`：相邻轨迹点隐含速度超过运行上限。
- `position_jump`：相邻轨迹点隐含速度超过物理硬极限的位置跳变。
- `expired_certificate`：广播时间不在证书有效期内。

乱序或重复报文不会拼出虚假轨迹：轨迹只按机载时间排序、按内容去重重建。接收站
时钟漂移只降低证据置信度，不直接形成定性；所有检测结论都进入人工复核案件。
