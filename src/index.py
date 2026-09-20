from app import create_server


if __name__ == "__main__":
    server = create_server()
    print("无人机远程识别登记与异常核查服务已启动", flush=True)
    try:
        server.serve_forever()
    finally:
        server.service.close()
