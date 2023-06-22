import socket
import ipaddress
import struct
import requests


class IP:
    def __init__(self,buffer=None):
        header = struct.unpack('<BBHHHBBH4s4s',buffer)
        self.sourceIP = header[8]
        self.destinationIP = header[9]
        self.sourceAddress = ipaddress.ip_address(self.sourceIP)
        self.destinationAddress = ipaddress.ip_address(self.destinationIP)

host = '0.0.0.0' #Insert Host IP
s = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_IP)
s.bind((host,0))
while True:
    ip_frame = IP(s.recvfrom(65535)[0][0:20])
    print(f'{ip_frame.sourceAddress} -> {ip_frame.destinationAddress}')
    source = requests.get(f'http://ip-api.com/json/{ip_frame.sourceAddress}')
    locat = requests.get(f'http://ip-api.com/json/{ip_frame.destinationAddress}')
    print(source.content)
    print(locat.content)
