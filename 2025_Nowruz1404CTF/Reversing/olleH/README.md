# analyze

간단한 xor 로 키 검증한다. 
전부 코드 안에 하드코딩되어있어서 gpt를 돌려 플래그를 얻어냈다. 

# solvecode by GPT
```py
# Define the key and the target byte array (as computed from the multi-character literals)
key = b"Nowruz"  # Key is "Nowruz"
target = bytes([
    0x08, 0x22, 0x34, 0x26, 0x33, 0x01, 0x06, 0x5C,
    0x1B, 0x1E, 0x45, 0x25, 0x3C, 0x5C, 0x01, 0x41,
    0x07, 0x09, 0x7D, 0x30, 0x44, 0x1C, 0x12, 0x25,
    0x7E, 0x17, 0x42, 0x45, 0x16, 0x07
])

# Decrypt by XORing each target byte with the corresponding key byte (repeating the key)
flag_bytes = bytes(b ^ key[i % len(key)] for i, b in enumerate(target))
flag = flag_bytes.decode('utf-8')

print("The flag is:", flag)

```

# flag
`FMCTF{H3ll0_r3v3rs3_3ng_0x57c}`
