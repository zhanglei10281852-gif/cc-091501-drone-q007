# 无人机运行管理服务基础工程

这是面向无人机空域合规、机队运行和安全处置的 Python 服务基础工程，保留进程健康检查和运行配置，业务模块按实际审批、调度或追踪场景接入。

## 运行

需要 Python 3.11 或更高版本。直接执行 `python src/index.py` 启动服务，默认监听 8000 端口；`python -m unittest discover` 执行基线测试，也可以使用 `docker compose up --build` 启动容器。
