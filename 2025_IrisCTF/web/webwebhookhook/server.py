import socket

# 서버 설정
HOST = '0.0.0.0'
PORT = 80

# 소켓 생성
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
    server_socket.bind((HOST, PORT))
    server_socket.listen()
    print(f"Listening on {HOST}:{PORT} ...")

    while True:
        conn, addr = server_socket.accept()
        with conn:
            print(f"Connection established with {addr}")
            while True:
                data = conn.recv(0x1000)  # 4096 bytes
                if not data:
                    break

                # HTTP 응답 구성
                response_body = "<html><body><h1>Received!</h1></body></html>"
                response_headers = (
                    "HTTP/1.1 200 OK\r\n"
                    f"Content-Length: {len(response_body)}\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
                )
                response = response_headers + response_body

                conn.sendall(response.encode('utf-8'))