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