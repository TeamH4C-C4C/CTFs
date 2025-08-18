# analysis
- 주어진 what 바이너리 파일을 열어보면, 내부적으로 간단한 vm이 돌아가고 있음. 
- command 와 vm 코드를 추출해서 입력값을 알아낼 수 있음
- z3를 사용해서 플래그 추출 가능함

# python solver
```py
from z3 import *
import struct

commands = [
    "?WAWWHT?WAAWWAHHWAWAAAT?WAAHAAHHAAT?WHAAAHAHAWWHT?WHAAHHAHAWHT?WWHHWWHAAAHHWHT?WHHHHHHHAAT?WHHHHHHWWAHHT?WHAAA"
    "HAHAWHHHHHAAHT?WHHWHHAHHAAAHAAHHHT?WHHHAHWHHHAHHHAHAAT?WAAHHAHHHAHHWHHHHHT?WHHHHAHHAHAHWHHHHHT?WHHHHHHHWAHHAHH"
    "HHHT?WAWT?WHAAAAAAAWT?WHAAHAAAWAWWT?WAAAHAWAWHHT?WAAAHHHHAT?WAHHWHAHAHT?WAHHHHWWHWHAT?WAHWHHHWHHHT?WAHHAAAHHAA"
    "HHAHHT?WHHHAHWWHAHAHAWHHAAT?WAHWHHHWAAHHHWAHHHAWT?WAHHHHHAAHHHWHAHHT?WHHHHHAHHAHHHHHAT?WHHHHHHWWHAHWHHHAHHT?WH"
    "HHHHHWHHWHWHWHHHAHT?WAAWAAAAAT?WHAAAAAWWAT?WAWWHWWHAAAAT?WAAAAWWHHHWT?WHAHHAAHWT?WHWHWAHHAHT?WHAHHWWWHWHHT?WHH"
    "AHHHHAAAWHAAWAWT?WWAWHAHHHAHHAWHAAHT?WHHAHHHHWAAHAWHHAWT?WAHHAHWAHHWHHAHWHHT?WHAHHHHWHHAWHHHWAHT?WWHWAHHHHHHHA"
    "HHHHWT?WHHWWHHWHAHHHHHHHHT?WHWHHHHHAAHWAHHHHAAHAHWHAT?WAAAAAAT?WWAAWHAWAWAT?WAAAWAHWHT?WHAHWAHAWWT?WHHHHAAT?WW"
    "HAHHHHWWWT?WHHWAWAAAHAHAHHAT?WHAAHHAHAAHAHHT?WWAHHHHHAHHHAAAT?WAHAHHHWHHAHHHWWAT?WHHHHHAWHAHHHWAHT?WHHHHHAHAHH"
    "HHHT?WHHHWHHAHHHHHHHT?WHHAHHHWAHAHAWHHAHAAHHHWT?WHAHAHWHHWHAHAAHHHHWHWHAHT?WAAAWAAT?WAAAAHT!"
]

print(commands)


what = "WHAT"
solution = """0x4060 <solution>:      0x54    0x0f    0x00    0x00    0x00    0x00    0x00    0x00
0x4068 <solution+8>:    0x70    0x05    0x26    0x5e    0x4a    0x6f    0x01    0x00
0x4070 <solution+16>:   0x7c    0xc7    0x85    0x54    0xbd    0x09    0x00    0x00
0x4078 <solution+24>:   0x64    0x1c    0x92    0x3e    0x52    0x00    0x00    0x00
0x4080 <solution+32>:   0xad    0x73    0xa5    0x31    0x01    0x00    0x00    0x00
0x4088 <solution+40>:   0x6a    0x36    0xf0    0x08    0x00    0x00    0x00    0x00
0x4090 <solution+48>:   0x3c    0x92    0x31    0x00    0x00    0x00    0x00    0x00
0x4098 <solution+56>:   0x45    0x80    0x00    0x00    0x00"""

with open("what", "rb") as f:
    # f.seek(0x3040)
    # print(f.read(5))
    f.seek(0x3060)
    raw = f.read(8 * 61)
    solution = list(struct.unpack("<61q", raw))
print(solution)
command = commands[0]

# vm
var_in = 0
correct = 1
acc_idx = 0
what_idx = 0
what = "WHAT"


solver = Solver()
flag = [BitVec(f"flag_{i}", 16) for i in range(62)]
for fv in flag:
    # solver.add(fv > 0, fv < 256)
    # solver.add(fv != ord("%"))
    # solver.add(fv != 11)
    solver.add(Or(
        # digits 0–9
        And(fv >= ord('0'), fv <= ord('9')),
        # uppercase A–Z
        And(fv >= ord('A'), fv <= ord('Z')),
        # lowercase a–z
        And(fv >= ord('a'), fv <= ord('z')),
        # brace and underscore
        fv == ord('{'),
        fv == ord('}'),
        fv == ord('_'),
    ))


for i in range(len(command)):
    c = command[i]
    # print(c)

    if c == "?":
        var_in = flag[acc_idx]
        # var_out = solution[acc_idx]
        print(f"Acc: {acc_idx}")

    elif c == "W":
        var_in ^= ord(what[what_idx])
        # var_out = ord(what[what_idx]) ^ var_out
        what_idx = (what_idx + 1) % 4

    elif c == "H":
        var_in += ord(what[what_idx])
        # var_out -= ord(what[what_idx])
        what_idx = (what_idx + 1) % 4

    elif c == "A":
        var_in *= ord(what[what_idx])
        # var_out //= ord(what[what_idx])
        what_idx = (what_idx + 1) % 4

    elif c == "T":
        # print(var_in)
        print(acc_idx, solution[acc_idx])

        solver.add(var_in == solution[acc_idx])
        acc_idx += 1
        # correct &= var_in == solution[v3]

    elif c == "!":
        if correct == 1:
            print("oh, that makes sense.")
        else:
            print("I don't get it.")

print(acc_idx, len(solution))
assert acc_idx == len(solution)

# solver.add(flag[3] == ord("f"))
solver.add(flag[45] != ord("k"))

if solver.check() == sat:
    m = solver.model()
    raw_flag = [m[flag[i]].as_long() for i in range(len(solution))]
    print(raw_flag, len(raw_flag))
    f = "".join([chr(i) for i in raw_flag])
    print(f, len(f))
else:
    print("UNSAT — no solution found")


# bctf{1m_p3rplexed_to_s4y_th3_63ry_l34st_rzr664k1p5v2qe4qdym}
# bctf{1m_p3rplex%d_to_s4y_th3_63ry_l34st_rzr664k1p5v2qe4qdym}
# bctf{1m_p3rplexed_to_s4y_th3_v3ry_l34st_rzr664k1p5v2qe4qdKym}

# real flag
# bctf{1m_p3rplexed_to_s4y_th3_v3ry_l34st_rzr664k1p5v2qe4qdkym}  
```

플래그 일부가 잘 뽑히지 않아서, 수동으로 맞춰가며 수정해서 플래그를 구함. 

# flag
```
bctf{1m_p3rplexed_to_s4y_th3_v3ry_l34st_rzr664k1p5v2qe4qdkym}
```
