import socket
from typing import Optional

from portscaner.application_protocol_identification import \
    get_application_protocol_by_response
from portscaner.application_protocols import ApplicationProtocols
from portscaner.protocols_probes import APPLICATION_PROTOCOL_PROBES
from portscaner.transport_protocols_transfers import \
    tcp_send_recv, udp_send_recv
from portscaner.transport_protocols import TransportProtocols


def get_service_application_protocol(domain: str,
                                     port: int,
                                     transport_protocol: TransportProtocols,
                                     timeout: float) -> \
        Optional[ApplicationProtocols]:
    for application_protocol in ApplicationProtocols:
        for probe in (APPLICATION_PROTOCOL_PROBES[transport_protocol.value]
                      [application_protocol.value]):
            try:
                if transport_protocol.value == TransportProtocols.TCP.value:
                    response = tcp_send_recv(domain, port, probe, timeout)
                else:
                    response = udp_send_recv(domain, port, probe, timeout)
            except socket.error:
                continue
            application_protocol = \
                get_application_protocol_by_response(probe, response)
            return application_protocol
    return None
