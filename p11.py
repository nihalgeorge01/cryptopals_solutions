## S2C11 - Implement ECB/CBC Detection Oracle

import secrets
from p09 import pkcs7pad
from p10 import aes_ecb_encrypt, cbc_encrypt

def ecb_cbc_encrypt_oracle(msg):
    '''
    Randomly encrypts plaintext in AES-ECB or AES-CBC with equal chance

    Inputs

        msg - bytestring - Plaintext

    Outputs

        ciph - bytestring - Encrypted ciphertext

    '''

    key = secrets.token_bytes(16) # 16 random bytes
    pre = secrets.token_bytes(secrets.randbelow(6) + 5) # Random number [5-10] of prefix bytes
    suf = secrets.token_bytes(secrets.randbelow(6) + 5) # Random number [5-10] of suffix bytes
    msg = pre + msg + suf
    msg = pkcs7pad(msg, 16)
    choice = secrets.randbelow(2)

    if choice == 0:
        # ECB
        ciph = aes_ecb_encrypt(msg, key)
    else:
        # CBC
        iv = secrets.token_bytes(16)
        ciph = cbc_encrypt(msg, key, 16, iv, "AES")

    return ciph

def ecb_cbc_detect_oracle(enc_oracle):
    '''
    Calls the random ECB/CBC encryption oracle and detects which mode was used

    Inputs

        enc_oracle - func pointer - Encryption Oracle

    Ouptuts

        mode - int - Mode of encryption (ECB=0, CBC=1)

    '''

    ## This uses the fact that ECB is stateless and deterministic, so identical
    ## plaintext blocks will have identical ciphertext blocks. 
    ## We send a bytestring of a single byte repeated many times (at least 48)
    ## so as to have at least 2 identical plaintext blocks. 
    ## If ECB is used, we get 2 identical ciphertext blocks.
    ## If CBC is used, we most likely will not get identical 
    mode = -1
    blk_size = 16

    msg = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"  # length 48
    b_msg = bytes(msg, 'utf-8')
    ciph = enc_oracle(b_msg)

    ## Since only 5-10 bytes are prepended, 2nd and 3rd blocks of input are 
    ## guaranteed to be As. 
    ## For ECB, 2nd and 3rd block of output will be identical.
    ## For CBC, 2nd and 3rd block of output will NOT be identical  
    
    blk2 = ciph[blk_size:2*blk_size]
    blk3 = ciph[2*blk_size:3*blk_size]

    if blk2 == blk3:
        mode = 0
    else:
        mode = 1
    
    return mode

def main():
    runs = 10
    print("Testing the oracles ...")
    for _ in range(runs):
        print("Mode: ", ecb_cbc_detect_oracle(ecb_cbc_encrypt_oracle))
    
    print("Done")

if __name__ == "__main__":
    main()
