## S1C06 - Breaking Repeating Key XOR

import base64
from itertools import combinations
from p05 import rep_key_xor
from p03 import single_byte_xor_break, single_char_xor, get_english_score
    
def hamming(a, b):
    '''
    Takes two equal length buffers and computes their bit-level hamming distance, i.e., 
    the number of indices i where bits_a[i] != bits_b[i].

    Inputs

        a - bytestring - First string
        b - bytestring - Second string

    Outputs

        dist - int - bit-level hamming distance between a and b 
    '''
    
    dist = 0

    for i in range(len(a)):
        
        if a[i] != b[i]:  #if characters are unequal
            xor_ab = bin(a[i] ^ b[i])[2:]  #take bitwise xor of a and b
            
            for bit in xor_ab:   # count number of set bits, equal to hamming for that character
                if bit == '1':
                    dist+=1

    return dist

def hamming_test():

    x = "this is a test"
    b_x = bytes(x, 'utf-8')

    y = "wokka wokka!!!"
    b_y = bytes(y, 'utf-8')
    
    assert hamming(b_x, b_y) == 37, "hamming sample test failed"
    print("hamming sample test passed")

def guess_key_length(ciph, lo, hi):
    '''
    Takes a message and guesses the length (between lower and upper limits) of the key in Repeating Key XOR cipher.
    More probable keys have lesser hamming distance across consecutive blocks.

    Inputs

        ciph - bytestring - ciphertext encrypted using Repeating Key XOR
        lo - int - lower limit of key length
        hi - int - upper limit of key length

    Outputs

        top_lens - int - top 3 most probable key lengths
    '''

    assert lo <= len(ciph)//2, "Lower limit of key length too high"

    l = lo
    r = min(hi, len(ciph)//2) # keylen assumed to be not longer than half the length of ciphertext
    dist_norms = {}
    for curr in range(l,r+1):  # computing normalized pairwise hamming of first 4 blocks
        chunks = [ciph[i:i + curr] for i in range(0, len(ciph), curr)][:4]
        dist_here = 0
        pairs = combinations(chunks, 2)
        for (x, y) in pairs:
            dist_here += hamming(x, y)

        dist_here /= 6 # 4c2 is 6
        dist_here_norm = dist_here/curr
        dist_norms[curr] = dist_here_norm

    top_lens = sorted(dist_norms, key=dist_norms.get)[:3]

    return top_lens # top 3 most probable key lengths

def guess_key(ciph, keylen):
    '''
    Guesses the most probable keys of length keylen for the ciphertext encrypted
    using Repeating Key XOR.

    Inputs

        ciph - bytestring - Ciphertext encrypted using Repeating Key XOR
        keylen - int - Length of key
    
    Outputs

        top_keys - list(bytestring) - Top 3 most probable keys
    '''

    poss_mess = []
    key = b''
    for i in range(keylen):  # Making keylen blocks, i'th block containing i'th byte of each of previous blocks.
        curr_block = b''
        for j in range(i, len(ciph), keylen):
            curr_block += bytes([ciph[j]])
        key += bytes([single_byte_xor_break(curr_block)['key']])

    poss_mess.append((rep_key_xor(ciph, key), key))
    return poss_mess

def b64_to_bytes(b64_msg):
    return base64.b64decode(b64_msg)

def break_repeating_key_xor(ciph, lo, hi):
    '''
    Finds the original message by choosing most probable key lengths and then breaking it
    using the technique for breaking Single Byte XOR for each byte in key.

    Inputs

        ciph - bytestring - ciphertext encrypted using Repeating Key XOR
        lo - int - lower limit of key length
        hi - int - upper limit of key length

    Outputs

        b_msg - tuple(bytestring, bytestring) - tuple of most probable message and key
    '''
    candidates = []
    key_lens = guess_key_length(ciph, lo, hi)
    for length in key_lens:
        candidates.extend(guess_key(ciph, length))

    return max(candidates, key=lambda k: get_english_score(k[0]))
     
def main():
    
    with open("p06_in.txt") as input_file:
        cipher = input_file.read()
 
    b_cipher = b64_to_bytes(cipher)
    lo = 2
    hi = 40

    b_msg = break_repeating_key_xor(b_cipher, lo, hi)
    print("Key below -----\n", b_msg[1].decode('utf-8'))
    print("Message below -----\n", b_msg[0].decode('utf-8'))

if __name__ == "__main__":
    main()