from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA
import math

with open('ssh_host_rsa_key.pub') as f:
    rsa = RSA.importKey(f.read())
    N = rsa.n

sqrt_N = math.isqrt(N)
print(long_to_bytes(sqrt_N))