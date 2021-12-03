import socket
from ipaddress import IPv4Address
from typing import Optional

from portscaner.application_protocol_response_validator import ResponseValidator
from portscaner.application_protocols import ApplicationProtocols
from portscaner.socket_extensions import tcp_send_recv, udp_send_recv
from portscaner.transport_protocols import TransportProtocols
from portscaner.protocols_probes import APPLICATION_PROTOCOL_PROBES


class ServiceProtocolDetector:
    @staticmethod
    def get_service_application_protocol(domain: str,
                                         port: int,
                                         transport_protocol: TransportProtocols) -> Optional[ApplicationProtocols]:
        for application_protocol in ApplicationProtocols:
            for probe in APPLICATION_PROTOCOL_PROBES[transport_protocol.value][application_protocol.value]:
                try:
                    if transport_protocol.value == TransportProtocols.TCP.value:
                        response = tcp_send_recv(domain, port, probe, 1)
                    else:
                        response = udp_send_recv(domain, port, probe, 1)
                except socket.error:
                    break
                if not ResponseValidator.validate_response(probe, response, application_protocol):
                    break
            else:
                return application_protocol
        return None
