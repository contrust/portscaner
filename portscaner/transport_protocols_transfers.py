import socket
from scapy.packet import Packet
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import sr1


def tcp_send_syn_and_recv_ack(domain: str, port: int, timeout: float) -> Packet:
    """
    Send a SYN packet to the domain and port and receive an ACK packet.

    Args:
        domain (str): The domain to send the SYN packet to.
        port (int): The port to send the SYN packet to.
        timeout (float): The timeout for the SYN packet.

    Returns:
        Packet: The SYN packet.
    """
    ret_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="S"),
                     verbose=False, timeout=timeout)
    return ret_packet


def tcp_send_rst(domain: str, port: int, timeout: float) -> Packet:
    """
    Send a RST packet to the domain and port and receive an ACK packet.

    Args:
        domain (str): The domain to send the RST packet to.
        port (int): The port to send the RST packet to.
        timeout (float): The timeout for the RST packet.

    Returns:
        Packet: The RST packet.
    """
    ret_packet = sr1(IP(dst=domain) / TCP(dport=port, flags="R"),
                     verbose=False, timeout=timeout)
    return ret_packet


def tcp_send_recv(domain: str, port: int,
                  request: bytes, timeout: float) -> bytes:
    """
    Send a request to the domain and port and receive a TCP response.

    Args:
        domain (str): The domain to send the request to.
        port (int): The port to send the request to.
        request (bytes): The request to send.
        timeout (float): The timeout for the request.

    Returns:
        bytes: The response or None if the request or response timed out.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            s.connect((domain, port))
            s.sendall(request)
            response = s.recv(4096)
            return response
        except socket.timeout:
            return None


def udp_send_recv(domain: str, port: int,
                  request: bytes, timeout: float) -> bytes:
    """
    Send a request to the domain and port and receive a UDP response.

    Args:
        domain (str): The domain to send the request to.
        port (int): The port to send the request to.
        request (bytes): The request to send.
        timeout (float): The timeout for the request.

    Returns:
        bytes: The response or None if the request or response timed out.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(timeout)
        try:
            s.sendto(request, (domain, port))
            response, _ = s.recvfrom(4096)
            return response
        except socket.timeout:
            return None
