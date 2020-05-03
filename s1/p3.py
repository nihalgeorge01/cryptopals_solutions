## S1C3 - Breaking Single Byte XOR Cipher

def single_char_xor(input_bytes, char_val):
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_val])
    return output_bytes
# From https://en.wikipedia.org/wiki/Letter_frequency
character_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}
def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language
    """

    
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def single_byte_xor_break(b_cipher):
    

    potent = []
    for i in range(256):
        b_xor_msg = single_char_xor(b_cipher, i)
        score = get_english_score(b_xor_msg)
        data = {'message':b_xor_msg, 'score':score, 'key':i}
        potent.append(data)

    best_score = sorted(potent, key=lambda x: x['score'], reverse=True)[0]

    return best_score
    

def main():
    cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    b_cipher = bytes.fromhex(cipher)

    best_score = single_byte_xor_break(b_cipher)

    for item in best_score:
        print("{}: {}".format(item.title(), best_score[item]))

if __name__ == "__main__":
    main()