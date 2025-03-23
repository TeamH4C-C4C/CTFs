import os

files =[]

def list_zlib_files():
    current_path = os.getcwd()
    files = [f for f in os.listdir(current_path) if f.endswith(".zlib")]
    return files

if __name__ == "__main__":
    zlib_files = list_zlib_files()
    for file in zlib_files:
        files.append(file)

import zlib

for file in files:
    with open('./'+file, "rb") as f:
        d = f.read()
    data = zlib.decompress(d)
    print(data)