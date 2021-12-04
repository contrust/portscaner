from typing import Optional

from portscaner.application_protocols import ApplicationProtocols


def get_application_protocol_by_response(request: bytes, response: bytes) \
        -> Optional[ApplicationProtocols]:
    if response.startswith(b'HTTP'):
        return ApplicationProtocols.HTTP
    elif b"\x06google\x03com" in response:
        return ApplicationProtocols.DNS
    elif request == response:
        return ApplicationProtocols.ECHO
    elif response.startswith(b'SSH'):
        return ApplicationProtocols.SSH
    return ApplicationProtocols.UNKNOWN
