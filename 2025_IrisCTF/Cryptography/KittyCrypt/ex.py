import binascii

CharSet = ["🐱", "🐈", "😸", "😹", "😺", "😻", "😼", "😽", "😾", "😿", "🙀", "🐱‍👤", "🐱‍🏍", "🐱‍💻", "🐱‍👓", "🐱‍🚀"]

def decoding(string):
    ct = []
    l = len(string)
    idx = 0
    while idx < l:
        cur = string[idx:idx+3]
        bflag = False
        for i in range(9, 16):
            if cur == CharSet[i]:
                ct.append(i)
                bflag = True
                break
        if bflag:
            idx += 3
            continue
        cur = string[idx]
        for i in range(11):
            if cur == CharSet[i]:
                ct.append(i)
                idx += 1
                break
    return ct

def hex_to_keyed_text(hex_list):
    return ''.join(chr(int(''.join(map(str, hex_list[i:i+2])), 16)) for i in range(0, len(hex_list), 2))

def recover_keys(input_text, decoded_list):
    hex_str = ''.join([f"{x:X}" for x in decoded_list])
    keyed_text = binascii.unhexlify(hex_str).decode('utf-8')

    keys = [ord(keyed_text[i]) - ord(input_text[i]) for i in range(len(input_text))]
    return keys

def decrypt(input_text, decoded_list):
    hex_str = ''.join([f"{x:X}" for x in decoded_list])
    keyed_text = binascii.unhexlify(hex_str).decode('utf-8')

    keys = [ord(keyed_text[i]) - input_text[i] for i in range(len(input_text))]
    return keys

with open('example_output.txt', 'r') as f:
    ct = decoding(f.read())
    print(ct)

with open('example_input.txt', 'r') as f:
    input_text = f.read()
    keys = recover_keys(input_text, ct)
    print(keys)
    print(len(keys))

with open('flag_output.txt', 'r') as f:
    flag_ct = decoding(f.read())
    flag = decrypt(keys, flag_ct)
    print(''.join(chr(i) for i in flag))