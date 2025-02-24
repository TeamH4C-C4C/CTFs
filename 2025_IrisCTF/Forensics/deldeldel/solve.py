#!/usr/bin/env python3
import sys
import pyshark

# HID usage page mapping for standard US QWERTY
hid_keymap = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd',
    0x08: 'e', 0x09: 'f', 0x0A: 'g', 0x0B: 'h',
    0x0C: 'i', 0x0D: 'j', 0x0E: 'k', 0x0F: 'l',
    0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p',
    0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1A: 'w', 0x1B: 'x',
    0x1C: 'y', 0x1D: 'z',
    0x1E: '1', 0x1F: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8',
    0x26: '9', 0x27: '0',
    0x28: '\n',   # Enter
    0x29: '[ESC]',
    0x2a: '[BS]', # Backspace
    0x2b: '\t',   # Tab
    0x2c: ' ',    # Space
    0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']',
    0x31: '\\', 0x33: ';', 0x34: '\'',
    0x36: ',', 0x37: '.', 0x38: '/'
}

LEFT_SHIFT  = 0x02
RIGHT_SHIFT = 0x20

# Characters that change when Shift is pressed
shift_map = {
    'a': 'A', 'b': 'B', 'c': 'C', 'd': 'D',
    'e': 'E', 'f': 'F', 'g': 'G', 'h': 'H',
    'i': 'I', 'j': 'J', 'k': 'K', 'l': 'L',
    'm': 'M', 'n': 'N', 'o': 'O', 'p': 'P',
    'q': 'Q', 'r': 'R', 's': 'S', 't': 'T',
    'u': 'U', 'v': 'V', 'w': 'W', 'x': 'X',
    'y': 'Y', 'z': 'Z',
    '1': '!', '2': '@', '3': '#', '4': '$',
    '5': '%', '6': '^', '7': '&', '8': '*',
    '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}',
    '\\': '|', ';': ':', '\'': '"',
    ',': '<', '.': '>', '/': '?'
}

def decode_hid_report(report_hex: str) -> str:
    """
    Given a single leftover data hex string from usb.capdata (8 bytes, e.g. '00012c0000000000'),
    decode it to the corresponding keystrokes.
    """
    # Convert hex to a list of integers
    # e.g. '00012c0000000000' -> [0x00, 0x01, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x00]
    data = [int(report_hex[i : i + 2], 16) for i in range(0, len(report_hex), 2)]
    if len(data) < 8:
        return ''  # not a valid 8-byte HID report

    modifier = data[0]
    # bytes 2..7 => key codes
    keycodes = data[2:]

    shift_pressed = bool((modifier & LEFT_SHIFT) or (modifier & RIGHT_SHIFT))
    result = []

    for kc in keycodes:
        if kc == 0:
            continue
        char = hid_keymap.get(kc, '[UNK]')
        if shift_pressed and char in shift_map:
            char = shift_map[char]
        result.append(char)

    return ''.join(result)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcapng_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Create a PyShark capture, filtering for packets that have leftover data (usb.capdata).
    cap = pyshark.FileCapture(
        pcap_file,
        display_filter='(usb.src == "1.5.1") && (frame.len == 72)'
    )

    # Accumulate decoded keystrokes
    decoded_text = []

    for pkt in cap:
        # 1) Check if this packet has a "data" layer
        if hasattr(pkt, 'data'):
            # 2) Check if that "data" layer has a usb_capdata field
            if hasattr(pkt.data, 'usb_capdata'):
                # usb_capdata might look like '13:05:01:00:01:01:00'
                leftover_data_hex = pkt.data.usb_capdata.replace(':', '') 
                keystrokes = decode_hid_report(leftover_data_hex)
                decoded_text.append(keystrokes)
            

    cap.close()

    final_text = ''.join(decoded_text)
    print("Decoded keystrokes:")
    print(final_text)

if __name__ == "__main__":
    main()

# irisctf{this_keylogger_is_too_hard_to_use}