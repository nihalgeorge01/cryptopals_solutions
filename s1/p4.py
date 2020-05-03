## S1C4 - Detecting a single byte XOR cipher among random character snippets

import sys

character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253, 'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025, 'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056, 'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
}

def single_char_xor(input_bytes, char_val):
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_val])
    return output_bytes

def get_english_score(input_bytes):

    global character_frequencies
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def main():
    sys.stdin = open("p4_in.txt", 'r')

    max_score = -256
    for entry in range(327):

        cipher = input()
        b_cipher = bytes.fromhex(cipher)
    
        potent = []
        best_score_here = -256
    
        for j in range(256):
            b_xor_msg = single_char_xor(b_cipher, j)
            score = get_english_score(b_xor_msg)
            data = {'message':b_xor_msg, 'score':score, 'key':j}
            if score > best_score_here:
                best_score_here = score
                best_data = data
    
        best_score = best_data
        if best_score['score'] > max_score:
            max_score = best_score['score']
            max_msg = best_score['message']
            max_entry = entry
            max_key = best_score['key']

    print("Best message: ", max_msg)
    print("Score: ", max_score)
    print("Entry index: ", max_entry)
    print("Key: ", chr(max_key))

if __name__ == "__main__":
    main()