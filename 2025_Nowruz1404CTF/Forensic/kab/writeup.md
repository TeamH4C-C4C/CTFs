문제에서는 pcap파일을 주는데 http object를 extract 하면 아래와 같은 파일들이 나온다.

![Screenshot of extracted files](Screenshot%202025-03-22%20at%209.47.43%20PM.png)

이는 스테가노 그라피 인코딩 방법과 키, 플래그가 숨겨진 사진을 제공해준다.

## 해결 방법

이를 아래와 같은 익스플로잇을 작성해서 해결하였다.

```python
from PIL import Image
import sys
import os

def extract_bit(byte, pos):
    # Get the bit at position pos (0-indexed from left/MSB) in byte.
    return (byte >> (7 - pos)) & 1

def load_key(key_path):
    with open(key_path, 'r') as f:
        # Read the key (e.g., "Im_THE_kyE") and trim any whitespace/newlines.
        key_content = f.read().strip()
    # Convert each character to its ASCII value.
    return [ord(c) for c in key_content]

def decode_image(image_path, key_bytes):
    img = Image.open(image_path)
    pixels = img.load()
    width, height = img.size

    bit_stream = []
    # Collect red channel values in pixel order: left-to-right, top-to-bottom.
    red_values = []
    for y in range(height):
        for x in range(width):
            # Assume image pixels are in RGB or RGBA format.
            red_values.append(pixels[x, y][0])
    
    # For each red value use the corresponding key byte (cycling through the key).
    for i, r in enumerate(red_values):
        key_byte = key_bytes[i % len(key_bytes)]
        # For each position (0 to 7) where the key_byte has a bit set, extract that bit from the carrier.
        positions = [pos for pos in range(8) if ((key_byte >> (7 - pos)) & 1)]
        for pos in positions:
            bit_stream.append(str(extract_bit(r, pos)))
    
    # Regroup bits into bytes and convert to characters.
    secret = ""
    for i in range(0, len(bit_stream), 8):
        byte_bits = bit_stream[i:i+8]
        if len(byte_bits) < 8:
            break
        byte_val = int("".join(byte_bits), 2)
        # Stop decoding if a null byte is encountered.
        if byte_val == 0:
            break
        secret += chr(byte_val)
    return secret

if __name__ == "__main__":
    # Expect the carrier image as the first parameter and the key file as the optional second.
    image_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join("forcs", "steg.png")
    key_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join("forcs", "key")
    
    key_bytes = load_key(key_path)
    secret_message = decode_image(image_path, key_bytes)
    print("Secret message:", secret_message)
```

## 플래그

`FMCTF{haha_ypu_unlocked_bitmap}`