from enum import Enum


class ApplicationProtocols(Enum):
    HTTP = 'HTTP'
    DNS = 'DNS'
    ECHO = 'ECHO'
    SSH = 'SSH'
    SMTP = 'SMTP'
    POP3 = 'POP3'
    SNTP = 'SNTP'
    UNKNOWN = 'UNKNOWN'
