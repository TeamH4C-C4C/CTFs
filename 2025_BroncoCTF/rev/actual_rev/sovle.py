#!/usr/bin/env python3
import sys

recipe_differences = []
with open("log.txt", "r") as log:
    total = log.readlines()
    diffs = total[1:-2]
    TRUTH = total[-1]
    print(TRUTH)
    # print(len(diffs))
    for i in diffs:
        d = int(i.split()[1])
        recipe_differences.append(d)
    
T = []
truth_bytes = TRUTH.encode("utf-8")
for byte_index, byte in enumerate(truth_bytes):
    for bit in range(8):
        if (byte >> bit) & 1:
            T.append(byte_index * 8 + bit)

# print(len(recipe_differences), len(T))

input_bit_positions = []
for n, d in enumerate(recipe_differences):
    k = T[n]  
    X = k - d
    input_bit_positions.append(X)

max_bit = input_bit_positions[-1]
num_bytes = (max_bit // 8) + 1
input_bits = [0] * (num_bytes * 8)  

for pos in input_bit_positions:
    input_bits[pos] = 1

input_bytes = bytearray(num_bytes)
for i in range(num_bytes):
    byte_val = 0
    for bit in range(8):
        byte_val |= input_bits[i*8 + bit] << bit
    input_bytes[i] = byte_val

recovered = input_bytes.decode("utf-8")

print("Reconstructed input:")
print(recovered)


# bronco{r3v3r5ed_3n0ugh?}