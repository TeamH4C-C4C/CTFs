# mid-prng 

## 풀이

### 코드 분석

```python
import bad_prng
import random

flag = ""

output = []
random = bad_prng.generate_seed()
for c in flag:
    random = bad_prng.rand_word()
    output.append(random ^ ord(c))

print(bytes(output).hex())
```

주어진 문제 코드를 분석하면, `bad_prng` 이라는 라이브러리를 불러와서 `generate_seed()` 함수와 `rand_word()` 함수를 이용해 랜덤한 값을 불러와서 flag의 각 글자와 xor 한 결과를 output 배열에 넣는다.

이 때 두 함수의 구현체가 공개되지 않아서, output의 결과만을 보고 규칙을 분석해 플래그를 획득해야 한다.

그래서 output의 결과를 여러 개 뽑아놓고 한 바이트마다 집중해서 보았는데, 규칙이 보였다.
output에서 한 바이트를 생성하기 위해, 한 바이트를 생성하기 위한 경로가 존재한다.

예를 들어 `\x7f`를 생성한다고 가정하면, `G -> \xd5 -> \x7f` 를 거쳐야하고, 그럼 `\xd5`도 `G`를 무조건 거쳐아하고, 그리고 `G`도 어떤 바이트를 무조건 거쳐야할 것이다.
이 때 우리는 이미 경로를 7글자 정도 알 수 있는데, 이는 플래그 포맷으로 만들 수 있다. (`bronco{`)

그래서 output을 최대한 많이 뽑을 수록 저 경로를 점점 늘려나가면서 바이트의 흐름을 얻을 수 있고, 플래그의 길이가 24바이트이므로 경로의 길이가 24가 될 때 까지 반복한다.
그리고 바이트 나열들과 암호화된 output을 xor하면 플래그가 나온다.

### 익스플로잇 코드
```python
from pwn import *

key = bytearray(b"bronco{")

io = remote("bad-prng.nc.broncoctf.xyz", 8000)
data = bytes.fromhex(io.recv().decode())
base_leak = b''
for x, y in zip(key, data):	
	base_leak += bytes([x^y])
io.close()

print(data)
ret = base_leak

for _ in range(2048):
	io = remote("bad-prng.nc.broncoctf.xyz", 8000)
	_data = bytes.fromhex(io.recv().decode())
	leak = b''
	for x, y in zip(key, _data):	
		leak += bytes([x^y])
	if ret[-1] in leak:
		ret = ret[:-1]+leak[leak.find(ret[-1]):]
	print(ret)
	if len(ret) >= 24:
		io.close()
		break
	io.close()	

flag = b''
print(ret)
for x, y in zip(ret, data):
	flag += bytes([x^y])

print(flag)
```

플래그 : `bronco{0k_1ts_n0t_gr34t}`