## S1C05 - Repeating key XOR implementation

from p02 import byte_xor

def rep_key_xor(msg, key):
    '''
    Takes two bytestrings 'msg' and 'key', and returns the XOR of msg with
    a string of equal length constructed by concatenating copies of 'key'
    with itself.

    Inputs

        msg - bytestring - message needing encryption
        key - bytestring - key for encryption

    Outputs

        out - bytestring - result of repeating key XOR encryption
    '''
    #print("p5 msg: ", msg)
    #print("p5 key: ", key)
    keystr = ((len(msg)//len(key)) + 1) * key
    keystr = keystr[:len(msg)]

    return byte_xor(msg, keystr)

def main():
    msg = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    b_msg = bytes(msg, 'utf-8')

    key = "ICE"
    b_key = bytes(key, 'utf-8')

    b_cipher = rep_key_xor(b_msg, b_key)
    print(b_cipher.hex())

if __name__ == "__main__":
    main()