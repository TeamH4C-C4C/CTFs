from factordb.factordb import FactorDB
from output import *
from functools import reduce
from Crypto.Util.number import long_to_bytes, inverse

p = FactorDB(n)
p.connect()
p = p.get_factor_list()

phi = 1
i = 0
while i < len(p):
    prime = p[i]
    k = 0
    while i+1 < len(p) and p[i+1] == prime:
        i += 1
        k += 1
    phi *= (prime ** k) * (prime - 1)
    i += 1

d = inverse(e, phi)
flag = pow(flag, d, n)
print(long_to_bytes(flag).decode())