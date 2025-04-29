from z3 import *

flag = [BitVec(f"flag{i}", 16) for i in range(40)]
s = Solver()

for xi in flag:
    s.add(xi > 0)
    s.add(xi < 256)


s.add(flag[39] == (flag[0] + 55)) 

s.add(flag[0x26] == (flag[0] + 31)) 

s.add(flag[0x23] == (flag[2] + 30))  # 234


s.add(flag[4]*2 == (flag[20] + 29))

s.add((flag[17] - 25) == flag[0]) # 257

s.add((flag[0x20] + 7) == flag[0x27]) 

s.add((flag[0x1c] / 2) == (flag[0x10] - 54)) # 286

s.add(flag[9] == (flag[0x19]-10))

s.add((flag[10] + flag[1] - flag[20] )== (flag[36] - 31)) # 324
s.add((flag[10] + flag[1] - flag[20] )== (flag[36] - 31)) # 349

s.add((flag[0] + (flag[2] - flag[12])) == 42) # 368

s.add((flag[22] + flag[3] - flag[12] )== 104) # 387

s.add((flag[23] + (flag[4] - flag[12]) )== (flag[22] - 45)) # 412

s.add((flag[4] + flag[10] + flag[5] - flag[11] )== 184) # 437


s.add((flag[5] + flag[9] - flag[0]) == flag[3] + 76) # 462

s.add((flag[35] + flag[22] - flag[12] - flag[0] )== 47) # 487

s.add((flag[2] + flag[22] - flag[11] )== (flag[0] + 2)) # 512

s.add((flag[10] + flag[23] - flag[22] )== 81) # 531

s.add((flag[11] + flag[10] + flag[36] - flag[38] )== 208) # 556

s.add((flag[17] + flag[6] + flag[7] - flag[0] )== 237) # 581

s.add((flag[38] + flag[10] - flag[9])  == 95) # 600

s.add((flag[4] + flag[20] - flag[8]) == 70) # 619

s.add((flag[7] + (flag[38] + flag[11] - flag[22])) == (flag[21] + 101)) # 650

s.add((flag[0] + flag[21] + flag[33]) == 276) # 669

s.add((flag[39] + flag[32] + flag[33]) == (flag[8] + flag[10] + 128)) # 700

s.add((flag[17] + flag[12] + flag[19] - flag[38] )== 205) # 725

s.add((flag[0] + flag[36] + flag[18] - flag[22]) == 150) # 750

s.add((flag[16] + flag[22]) == (flag[20] + 115)) # 769

s.add((flag[13] + flag[22] - flag[32]) == (flag[9] - 5)) # 793


# xor

s.add((flag[24] ^ flag[22]) == 17) # 804

s.add(((flag[24] + flag[0]) ^ flag[23]) == 247) # 820

s.add((flag[10] ^ (flag[20] + flag[25])) == ((flag[24] ^ flag[22]) + 112)) # 845

s.add(((flag[0] + flag[1]) ^ (flag[26] + flag[27])) == 64)
s.add((flag[7] ^ flag[26]) == 6)
s.add((flag[16] + (flag[27] - flag[33])) == 109)
s.add((flag[22] + flag[28] - flag[10]) == 128)
s.add((flag[27] ^ flag[29]) == 58)
s.add((flag[15] + flag[30] - flag[20]) == 104)
s.add((flag[33] ^ flag[31]) == 14)
s.add((flag[13] + (flag[34] - flag[17])) == (flag[8] + 13))
s.add(((flag[29] + flag[37]) - (flag[39] ^ flag[9])) == 187)

s.add(flag[14] == ord('n'))
s.add(flag[15] == ord('t'))



if s.check() == sat:
    m = s.model()
    flag_bytes = [m.evaluate(xi, model_completion=True).as_long() for xi in flag]
    flag = "".join(chr(b) for b in flag_bytes)

    print(flag)
else:
    print("oh................")
