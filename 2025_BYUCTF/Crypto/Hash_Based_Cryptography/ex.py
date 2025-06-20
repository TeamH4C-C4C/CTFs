# flag = 40 bytes

from pwn import *

# host = 'hash.chal.cyberjousting.com'
# port = 1351
# r = remote(host, port)
r = process(['python3', 'server.py'])

context.log_level = 'error'

r.recvuntil(b'flag:\n')
flag = bytes.fromhex(r.recvline().strip().decode())

def extract_otp(n, r):
    prefix = bytes(n)
    otp = b''
    i = 1
    brute = 0
    try:
        while i <= 20:
            print('\n #' + str(i))
            suffix = bytes([a ^ b for a, b in zip(otp, [i] * (i - 1))])
            while brute < 256:
                try:
                    payload = prefix[:-i] + brute.to_bytes(1, 'big') + suffix
                    r.sendlineafter(b'> ', payload.hex().encode())
                    
                    resp = r.recvline().strip().decode()
                    print(brute, end=' ', flush=True)
                    if 'error' in resp:
                        brute += 1
                        continue
                    
                    otp = (brute ^ i).to_bytes(1, 'big') + otp
                    break
                except KeyboardInterrupt:
                    raise KeyboardInterrupt
                except:
                    # r = remote(host, port)
                    r.kill()
                    r = process(['python3', 'server.py'])
            if brute == 256:
                i -= 1
                brute = (otp[-i] ^ i) + 1
                otp = otp[1:]
                continue
            i += 1
            brute = 0
            print()
    except KeyboardInterrupt:
        exit(-1)
    return otp[-20:]

otp = extract_otp(20, r) + extract_otp(40, r)

print(bytes([a^b for a, b in zip(flag, otp)]))