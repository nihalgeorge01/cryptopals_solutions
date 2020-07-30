## S2C12 - Byte-at-a-time ECB decryption

import base64
import secrets
from p09 import pkcs7pad
from p10 import aes_ecb_encrypt, cbc_encrypt
from p11 import ecb_cbc_detect_oracle

key = secrets.token_bytes(16)

def ecb_encrypt_oracle(msg):
    '''
    Randomly encrypts plaintext in AES-ECB or AES-CBC with equal chance

    Inputs

        msg - bytestring - Plaintext

    Outputs

        ciph - bytestring - Encrypted ciphertext

    '''

    global key
    
    b_suf = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg \
                            aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq \
                            dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg \
                            YnkK")

    new_msg = msg + b_suf
    new_msg = pkcs7pad(new_msg, 16)

    ciph = aes_ecb_encrypt(new_msg, key)

    return ciph

def gen_ecb_dict(ecb_enc_oracle, payload, blk_size):
    '''
    Generates dictionary of ECB inputs and outputs of an ECB oracle using constant unknown key.
    Uses blk_size-1 known characters and generates inputs and outputs for all values of
    last byte.

    Inputs

        ecb_enc_oracle - func pointer - ECB encryption oracle
        payload - bytestring - blk_size-1 known characters
        blk_size - int - ECB block size

    Outputs

        ecb_dict - dict - Dictionary of 255 entries with all possible combinations of last byte    
        
    '''
    
    ecb_dict = dict()
    payload = payload[:blk_size-1]

    for byte in range(256):
        b_hex_byte = bytes([byte])

        ecb_dict[ecb_enc_oracle(payload+b_hex_byte)[:blk_size]] = payload+b_hex_byte
    
    return ecb_dict    

def ecb_decrypt_oracle(ecb_enc_oracle):
    '''
    Makes repeated calls to the ECB encryption oracle (having constant but randomly chosen key)
    and decrypts the constant string being appended to a message supplied to this oracle.

    Inputs

        ecb_enc_oracle(string msg) - func pointer - ECB encryption oracle

    Outputs

        ans - string - constant pre-encryption suffix used by the encryption oracle

    '''

    '''
    ---Discovering Block Size---

    First pass 1 byte "A", then 2 bytes "AA", then "AAA" and so on.
    For each message, the ciphertext length starts with some length
    blk_size*blk_count.
    At some message size M, this length suddenly changes to 
    blk_size*(blk_count+1). Subtract the lengths to get block size 
    '''
    msg = "A"
    b_msg = bytes(msg, "utf-8")
    ciph = ecb_enc_oracle(b_msg)
    curr_len = len(ciph)
    num_blk = -1
    blk_size = -1
    while True:
        ciph = ecb_enc_oracle(b_msg)
        if curr_len != len(ciph):
            blk_size = len(ciph) - curr_len
            num_blk = (len(ciph) // blk_size) - 1
            if len(b_msg) == blk_size:
                num_blk -= 1
            break
        else:
            b_msg += bytes("A", "utf-8")
            
    '''
    ---Checking If Oracle Is ECB---

    Use the function we created in S2C11 (p11.py)
    '''

    for i in range(10):
        mode = ecb_cbc_detect_oracle(ecb_enc_oracle)
        if mode == 1:
            return "Cannot detect for non-ECB oracle."
    
    '''
    ---Byte-By-Byte Character Guessing---

    We make a dictionary of outputs that of all possibilities in
    "A" * (blk_size-1) + any byte (255 possibilities)

    Then we pass "A" * (blk_size-1) to the oracle.
    On appending the secret string, the last character of the first
    block will be the first character of the secret string

    i.e. input_blocks[0][blk_size-1] == suf[0]

    We compare the 1st block of ciphertext with the dictionary
    and obtain the first character.
    Now send "A" * (blk_size-2) + suf[0] + any byte (255 possibilities)
    This makes the new dictionary. 
    
    Repeat the process till you get blk_size bytes of suf.

    Now, if we pass "A" * (blk_size-1), we know the next blk_size chars
    of as they are the first block of suf. The last character of 
    block 2 is unknown. This can be again found by making a dictionary of
    outputs when suf[:blk_size-1] + any byte (255 possibilities) is passed.
    Then we compare the second block of output to the dictionary to get the unknown
    char.
    Repeat this till this block is extracted.

    Repeat this entire thing till the string is exhausted and all blocks have
    been recovered. We will get some padding bytes due to PKCS#7, which will
    change when reducing the payload length.

    In that event, the output block will not be found in the dictionary
    since the pad byte value would have increased by one, e.g., 0x01 -> 0x02
    At this point we break and return the answer.
    '''

    suf = b''
    
    for blk in range(num_blk):
        payload = "A" * (blk_size-1)
        b_payload = bytes(payload, 'utf-8')
        
        # extracting blk_size unknown chars
        for byte in range(blk_size):
            b_payload_w_suf = b_payload * max(1-blk,0) + suf[(blk-1)*blk_size+byte+1:blk*blk_size]*min(blk,1) + suf[(blk*blk_size):(blk*blk_size) + byte]
            ecb_dict = gen_ecb_dict(ecb_enc_oracle, b_payload_w_suf, blk_size)
            imp_blk = ecb_enc_oracle(b_payload)[blk*blk_size:(blk+1)*(blk_size)]

            try:
                new_char = ecb_dict[imp_blk][-1]
            except KeyError: # when pad bytes are encountered
                break

            suf += bytes([new_char])
            b_payload = b_payload[:len(b_payload)-1]

    return suf

def main():
    print("Running function to extract ECB constant unknown padding ...\n")
    b_suf = ecb_decrypt_oracle(ecb_encrypt_oracle)
    suf = b_suf.decode("utf-8")
    print("---Constant suffix---\n")
    print(suf)
    print("\n---Done---")

if __name__ == "__main__":
    main()
    