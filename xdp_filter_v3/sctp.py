import socket

# SCTP 서버 주소와 포트 설정
server_address = ("127.0.0.1", 12345)

# SCTP 소켓 생성
with socket.socket(socket.AF_INET, socket.SOCK_SEQPACKET, socket.IPPROTO_SCTP) as sctp_socket:
    # 서버로 연결 시도
    sctp_socket.connect(server_address)
    
    # SCTP 메시지 전송
    message = "Hello, SCTP server!"
    sctp_socket.sendall(message.encode('utf-8'))
    print(f"Sent message to {server_address}: {message}")

    # 서버로부터 응답 수신
    response = sctp_socket.recv(1024)
    print(f"Received response from server: {response.decode('utf-8')}")