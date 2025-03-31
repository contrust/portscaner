from typing import Optional

from portscaner.application_protocols import ApplicationProtocols


def get_application_protocol_by_response(request: bytes, response: bytes) \
        -> Optional[ApplicationProtocols]:
    if response.startswith(b'HTTP'):
        return ApplicationProtocols.HTTP
    elif b'\x50\x74' in response:
        return ApplicationProtocols.DNS
    elif request == response:
        return ApplicationProtocols.ECHO
    elif response.startswith(b'SSH'):
        return ApplicationProtocols.SSH
    elif response.startswith(b"2"):
        return ApplicationProtocols.SMTP
    elif response.startswith(b"+OK") or response.startswith(b"-ERR"):
        return ApplicationProtocols.POP3
    elif len(response) == 48:
        return ApplicationProtocols.SNTP
    return ApplicationProtocols.UNKNOWN
