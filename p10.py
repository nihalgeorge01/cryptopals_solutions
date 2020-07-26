## S2C10 - Implement Cipher Block Chaining (CBC) Mode

import math
from Crypto.Cipher import AES
from base64 import b64decode
from p02 import byte_xor
from p07 import aes_ecb_decrypt
from p09 import pkcs7pad

def aes_ecb_encrypt(msg, key):
    '''
    Encrypts plaintext with key, using AES-ECB

    Inputs

        msg - bytestring - Plaintext
        key - bytestring - Key

    Outputs

        ciph - bytestring - AES-ECB encrypted ciphertext
    '''

    ciph_obj = AES.new(key, AES.MODE_ECB)
    ciph = ciph_obj.encrypt(msg)
    return ciph

def get_msg_blocks(msg, b_len=16):
    '''
    Divides a plaintext into blocks of specified length

    Inputs

        msg - bytestring - Plaintext
        b_len - int - Block length - default=16

    Outputs

        blocks - list(bytestring) - List containing blocks of plaintext
    '''

    pad_msg = pkcs7pad(msg, b_len) # pad plaintext to suitable length
    blocks = [pad_msg[b_len*i:b_len*(i+1)] for i in range(int(math.ceil(len(msg)/b_len)))]
    return blocks

def cbc_encrypt(msg, key, b_len=16, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", enc="AES"):
    '''
    Encrypts plaintext with a specified encryption standard in Cipher Block Chaining (CBC) 
    mode

    Inputs

        msg - bytestring - Plaintext
        key - bytestring - Key
        b_len - int - Block length - default=16
        iv - bytestring - Initialization Vector for first block - default=b'\x00'*16
        enc - string - Encryption Standard - default="AES"

    Outputs

        ciph - bytestring - Ciphertext encrypted with CBC
    '''

    ciph_blocks = []
    msg_blocks = get_msg_blocks(msg, b_len)
    prev = iv
    if enc=="AES":
        enc_func = aes_ecb_encrypt
    
    for m_blk in msg_blocks:
        cbc_in = byte_xor(m_blk, prev)
        c_blk = enc_func(cbc_in, key)
        ciph_blocks.append(c_blk)
        prev = c_blk

    ciph = b''.join(ciph_blocks)

    return ciph

def cbc_decrypt(ciph, key, b_len=16, iv=b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", enc="AES"):
    '''
    Decrypts ciphertext with a specified encryption standard in Cipher Block Chaining (CBC) 
    mode

    Inputs

        ciph - bytestring - Encrypted ciphertext
        key - bytestring - Key
        b_len - int - Block length - default=16
        iv - bytestring - Initialization Vector for first block - default=b'\x00'*16
        enc - string - Encryption Standard - default="AES"

    Outputs

        msg - bytestring - Plaintext
    '''
    
    msg_blocks = []
    ciph_blocks = get_msg_blocks(ciph, b_len)
    prev = iv
    if enc=="AES":
        dec_func = aes_ecb_decrypt
    
    for c_blk in ciph_blocks:
        m_blk = dec_func(c_blk, key)
        m_blk = byte_xor(m_blk, prev)
        msg_blocks.append(m_blk)
        prev = c_blk

    msg = b''.join(msg_blocks)

    return msg

def main():
    with open("p10_in.txt") as input_file:
        ciph = b64decode(input_file.read())

    key = "YELLOW SUBMARINE"
    b_key = bytes(key, 'utf-8')
    print(cbc_decrypt(ciph, b_key).decode())

if __name__ == "__main__":
    main()