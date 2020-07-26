## S2C09 - Implementing PKCS#7 Padding

def pkcs7pad(msg, b_length):
    '''
    Takes a plaintext and a block length, and returns the plaintext with padding as specified by PKCS#7

    Input

        msg - bytestring - Unpadded plaintext
        b_length - int - Block length in bytes

    Output

        pad_msg - bytestring - PKCS#7 Padded Plaintext
    '''

    pad_length = b_length - (len(msg) % b_length)  # number of pad bytes
    pad_msg = msg
    pad_bytes = bytes(chr(pad_length), 'utf-8') * pad_length 
    pad_msg += pad_bytes

    return pad_msg

def main():
    msg = "YELLOW SUBMARINE"
    b_msg = bytes(msg, 'utf-8')
    b_pad_msg = pkcs7pad(b_msg, 20)
    print(b_pad_msg)

if __name__ == "__main__":
    main()
