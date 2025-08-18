# block-cipher

## How to solve

1. 문제 파일은 마인크래프트 월드 파일 형태로, `%appdata% -> .minecraft -> save` 폴더에 넣어서 싱글 플레이로 실행 할 수 있다.

2. 월드에 인게임으로 들어가 보면 레드스톤 회로가 상자 속 암호문을 복호화 하는 것을 볼 수 있다, 회로가 복잡하지 않은 것을 보아 xor으로 추정된다. 

3. 한 글자 복호화에 성공 시 성공 메세지를, 실패할 경우에는 실패 메세지를 보내기 때문에 키 값을 한 글자씩 맞춰보면서 유추 할 수 있다.

4. 초기 키 값은 0x00, 두번째 키 값은 0x11으로, 00 11 22 33 이런 패턴을 보임을 알 수 있다.

5. 박스 속 암호문을 코드로 옮겨 solve 코드를 작성한다.

```py
cipher_hex = "627256553f185719edfad8daaaa9b18d33677d51700a2123c9afd7"
cipher_bytes = bytes.fromhex(cipher_hex)

pattern = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]

key_stream = bytes(pattern[i % len(pattern)] for i in range(len(cipher_bytes)))


plain = bytes(b ^ key_stream[i] for i, b in enumerate(cipher_bytes))
print("Decrypted (ascii):", plain.decode('utf-8', errors='ignore'))
```

## Flag
bctf{M1necraft_r3v_b4_GTA6}