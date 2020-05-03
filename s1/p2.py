## S1C2 - Fixed XOR of two equal length buffers

import base64

def byte_xor(ba1, ba2):
    '''
    Returns the bitwise XOR of two equal length buffers

    Inputs

        ba1 - bytestring - First bytestring
        ba2 - bytestring - Second bytestring
    '''
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def main():
    hex_msg = "1c0111001f010100061a024b53535009181c"
    xor_add = "686974207468652062756c6c277320657965"

    b_hex_msg = bytes.fromhex(hex_msg)
    b_xor_add = bytes.fromhex(xor_add)

    b_xor_msg = byte_xor(b_hex_msg, b_xor_add)

    print(b_xor_msg.decode('utf-8'))

if __name__ == "__main__":
    main()