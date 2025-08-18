from pwn import *
from sage.all import *
import gmpy2
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

host = 'choose.chal.cyberjousting.com'
port = 1348
p = remote(host, port)

flag = p.recvuntil(b'...\n')
flag = bytes.fromhex(p.recvline().strip().decode())

p.sendlineafter(b'order.\n', b'2 3 6')

n = [0] * 3
c = [0] * 3
for i in range(3):
    p.recvuntil(f'n{i}='.encode())
    n[i] = int(p.recvline().strip().decode())
    p.recvuntil(f'c{i}='.encode())
    c[i] = int(p.recvline().strip().decode())

c[0] = pow(c[0], 3, n[0])
c[1] = pow(c[1], 2, n[1])

k6 = crt(c, n)

key = gmpy2.iroot(k6, 6)[0]
key = long_to_bytes(key)[:16]

cipher = AES.new(key, AES.MODE_ECB)
print(unpad(cipher.decrypt(flag), AES.block_size).decode())