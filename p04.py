## S1C04 - Detecting a single byte XOR cipher among random character snippets

from p03 import single_char_xor, get_english_score, character_frequencies

def detect_single_byte_xor(ciph_lst):
    '''
    Detect the ciphertext most probably encrypted using single byte XOR

    Inputs

        ciph_lst - list(bytestring) - List of ciphertexts

    Outputs

        best_score - list()
    '''

    max_score = -256
    for entry in range(len(ciph_lst)): # Iterate over all ciphertexts

        b_cipher = ciph_lst[entry]

        best_score_here = -256
    
        for j in range(256): # Break each ciphertext and score with letter frequency analysis
            b_xor_msg = single_char_xor(b_cipher, j)
            score = get_english_score(b_xor_msg)
            data = {'message':b_xor_msg, 'score':score, 'key':j}
            if score > best_score_here: # Store the top scoring key and its params
                best_score_here = score
                best_data = data
    
        best_score = best_data
        if best_score['score'] > max_score: # If current message is best, store it
            max_score = best_score['score']
            max_msg = best_score['message']
            max_entry = entry
            max_key = best_score['key']

    best_score = [max_msg, max_score, max_entry, max_key]
    return best_score

def main():
    ciph_lst = [bytes.fromhex(line.strip()) for line in open("p04_in.txt")]
    best_score = detect_single_byte_xor(ciph_lst)

    print("Best message: ", best_score[0])
    print("Score: ", best_score[1])
    print("Entry index: ", best_score[2])
    print("Key: ", chr(best_score[3]))


if __name__ == "__main__":
    main()