from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1


def send_tcp_syn_and_recv_ack(domain: str, port: int, timeout: float):
    ack_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="S"),
                     verbose=False, timeout=timeout)
    return ack_packet


def send_tcp_rst(domain: str, port: int, timeout: float):
    ack_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="R"),
                     verbose=False, timeout=timeout)
    return ack_packet
