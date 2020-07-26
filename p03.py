## S1C03 - Breaking Single Byte XOR Cipher

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

def single_char_xor(msg, key):
    '''
    Returns the result of XOR-ing each byte of msg with key

    Inputs

        msg - bytestring - Message
        key - bytestring - Single byte key

    Outputs

        res - bytestring - Single byte XOR-ed result
    '''

    res = b''
    for byte in msg:
        res += bytes([byte ^ key])
    return res

def get_english_score(input_bytes):
    '''
    Compares each input byte to a character frequency chart and returns the score of a message based on the
    relative frequency the characters occur in the English language.
    
    Inputs

        input_bytes - bytestring - Bytestring to be scored

    Outputs

        score - float - Weighted score using letter freqeuncy chart
    '''
    
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def single_byte_xor_break(ciph):
    '''
    Returns plaintext from ciphertext encrypted by single byte XOR cipher, using letter frequency analysis

    Inputs

        ciph - bytestring - Ciphertext

    Outputs

        best_score - list(msg, score, key) - List containing the plaintext, its score and key
    '''    

    potent = []
    for i in range(256): # Iterate over all possible ASCII characters for the key
        b_xor_msg = single_char_xor(ciph, i)
        score = get_english_score(b_xor_msg)
        data = [b_xor_msg, score, i]
        potent.append(data)

    best_score = sorted(potent, key=lambda x: x[1], reverse=True)[0] # Get the message with the highest score

    return best_score
    

def main():
    cipher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    b_cipher = bytes.fromhex(cipher)

    best_score = single_byte_xor_break(b_cipher)

    for item in best_score:
        print("{}: {}".format(item.title(), best_score[item]))

if __name__ == "__main__":
    main()