from application_protocols import ApplicationProtocols


class ResponseValidator:
    @staticmethod
    def validate_response(request: bytes, response: bytes, application_protocol: ApplicationProtocols) -> bool:
        if application_protocol.value == ApplicationProtocols.HTTP.value:
            return response.startswith(b'\x15\x03\x01\x00\x02\x02F') or response.startswith(b'HTTP/')
        elif application_protocol.value == ApplicationProtocols.DNS.value:
            return b"\x06google\x03com" in response
        elif application_protocol.value == ApplicationProtocols.ECHO.value:
            return request == response
        return False
