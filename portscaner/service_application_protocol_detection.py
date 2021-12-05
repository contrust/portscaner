import socket
from typing import Optional

from portscaner.application_protocol_identification import \
    get_application_protocol_by_response
from portscaner.application_protocols import ApplicationProtocols
from portscaner.protocols_probes import APPLICATION_PROTOCOL_PROBES
from portscaner.transport_protocols import TransportProtocols
from portscaner.transport_protocols_transfers import \
    tcp_send_recv, udp_send_recv


def get_service_application_protocol(domain: str,
                                     port: int,
                                     transport_protocol: TransportProtocols,
                                     timeout: float) -> \
        Optional[ApplicationProtocols]:
    str_transport_protocol = transport_protocol.value
    for str_application_protocol in (APPLICATION_PROTOCOL_PROBES
                                     [str_transport_protocol]):
        for probe in (APPLICATION_PROTOCOL_PROBES[str_transport_protocol]
                      [str_application_protocol]):
            try:
                if str_transport_protocol == TransportProtocols.TCP.value:
                    response = tcp_send_recv(domain, port, probe, timeout)
                else:
                    response = udp_send_recv(domain, port, probe, timeout)
            except socket.error:
                continue
            application_protocol = \
                get_application_protocol_by_response(probe, response)
            return application_protocol
    return None
