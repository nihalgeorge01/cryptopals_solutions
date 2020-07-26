## S1C01 - Convert hex to base64

import base64

def main():
    hex_msg = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"

    b_hex_msg = bytes.fromhex(hex_msg)
    b_b64_msg = base64.b64encode(b_hex_msg)
    print(b_b64_msg)
    print(b_b64_msg.decode('utf-8'))

if __name__ == "__main__":
    main()