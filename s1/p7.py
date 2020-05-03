## S1C7 - Decrypting AES ECB with OpenSSL

from Crypto.Cipher import AES
from base64 import b64decode

def aes_ecb_decrpyt(ciph, key):
    '''
    Decrypt using AES ECB mode given ciphertext and key, using Crypto.Cipher.AES

    Inputs

        ciph - bytestring - Ciphertext
        key - bytestring - Key

    Outputs

        msg - bytestring - Message
    '''
    
    ciph_obj = AES.new(key, AES.MODE_ECB)
    return ciph_obj.decrypt(ciph)

def main():
    with open("p7_in.txt") as input_file:
        ciph = b64decode(input_file.read())

    key = "YELLOW SUBMARINE"
    b_key = bytes(key, 'utf-8')
    print(aes_ecb_decrpyt(ciph, b_key).decode())

if __name__ == "__main__":
    main()

