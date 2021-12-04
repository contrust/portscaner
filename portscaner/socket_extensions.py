import socket


def tcp_send_recv(domain: str, port: int,
                  request: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect((domain, port))
        s.sendall(request)
        response = s.recv(4096)
        return response


def udp_send_recv(domain: str, port: int,
                  request: bytes, timeout: float) -> bytes:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        s.sendto(request, (domain, port))
        response, _ = s.recvfrom(4096)
        return response
