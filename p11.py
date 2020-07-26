## S2C11 - Implement ECB/CBC Detection Oracle

import secrets
from p09 import pkcs7pad
from p10 import aes_ecb_encrypt, cbc_encrypt
'''
Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes. <<<DONE>>>

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it. <<<DONE>>>

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
'''

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

def ecb_cbc_detect_oracle(ciph):
    '''
    Calls the random ECB/CBC encryption oracle and detects which mode was used

    Inputs

        ciph - bytestring - Ciphertext

    Ouptuts

        mode - int - Mode of encryption (ECB=0, CBC=1)
    '''

    ## This uses the fact that ECB is stateless and deterministic, so identical
    ## plaintext blocks will have identical ciphertext blocks. 
    ## We send a bytestring of a singel byte repeated many times (at least 32)
    ## so as to have at least 2 identical plaintext blocks. 
    ## If ECB is used, we get 2 identical ciphertext blocks.
    ## If CBC is used, we most likely will not get identical 
    mode = -1

    return mode