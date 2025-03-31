# VLESS

author : SafaSafari

What do you know about VLESS?

Flag format: `FMCTF{DestinationIP_UUID}`

# 풀이

## Protocol Construction

VLESS는 중국의 한 네트워크 프로토콜 프로젝트 Project X에서 제공하는 암호화하지 않는 Stateless 프로토콜이다.

3-way handshake 이후 [PSH, ACK]와 메시지를 같이 보내는데, 맨 처음은 연결을 위해 아래 정보를 포함한 패킷을 전송한다.

https://xtls.github.io/en/development/protocols/vless.html

|1 byte|16 bytes|1 byte|M bytes|1 byte|2 bytes|1 byte|S bytes|X bytes|
|------|--------|------|-------|------|-------|------|-------|-------|
|Protocol Version|Equivalent UUID|Additional Information Length M|Additional Information ProtoBuf|Instruction|Port|Address Type|Address|Request Data|

## Address

Address 필드는 domain name, IPv4, IPv6로 표현될 수 있는데, 일단 IPv4에 4 bytes를 할당받을 것으로 추측하고 분석 진행했다.

https://xtls.github.io/en/config/outbounds/vless.html

## Equivalent UUID

User ID를 16 bytes UUID로 한다.

# flag

정리하면 `FMCTF{127.13.37.1_875aa716-c9aa-43ee-bea0-9dbcbe87256d}`