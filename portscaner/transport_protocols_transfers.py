import socket
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1


def tcp_send_syn_and_recv_ack(domain: str, port: int, timeout: float):
    ack_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="S"),
                     verbose=False, timeout=timeout)
    return ack_packet


def tcp_send_rst(domain: str, port: int, timeout: float):
    ack_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="R"),
                     verbose=False, timeout=timeout)
    return ack_packet


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
