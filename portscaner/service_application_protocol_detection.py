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
    """
    Get the service application protocol by sending predefined probes to the port.

    Args:
        domain (str): The domain to send the probes to.
        port (int): The port to send the probes to.
        transport_protocol (TransportProtocols): The transport protocol to send the probes with.
        timeout (float): The timeout for the probes.

    Returns:
        Optional[ApplicationProtocols]: The service application protocol.
    """
    str_transport_protocol = transport_protocol.value
    application_protocol = None 
    for str_application_protocol in (APPLICATION_PROTOCOL_PROBES
                                     [str_transport_protocol]):
        for probe in (APPLICATION_PROTOCOL_PROBES[str_transport_protocol]
                      [str_application_protocol]):
            if str_transport_protocol == TransportProtocols.TCP.value:
                response = tcp_send_recv(domain, port, probe, timeout)
            else:
                response = udp_send_recv(domain, port, probe, timeout)
            if response is None:
                continue
            application_protocol = \
                get_application_protocol_by_response(probe, response)
            if application_protocol != ApplicationProtocols.UNKNOWN:
                return application_protocol
    return application_protocol
