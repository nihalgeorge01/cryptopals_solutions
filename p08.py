## S1C08 - Detecting AES-ECB

from Crypto.Cipher.AES import block_size

def aes_ecb_repeats(ciph):
    '''
    Returns the number of repeated chunks of length block_size in ciph

    Inputs

        ciph - bytestring - Ciphertext

    Outputs

        reps - int - Number of repeats
    '''

    chunks = [ciph[i:i + block_size] for i in range(0, len(ciph), block_size)]
    reps = len(chunks) - len(set(chunks))
    return reps

def detect_aes_ecb(ciph_lst):
    '''
    Returns the most probable ciphertext encrypted using AES-ECB among a list of candidate ciphertexts.

    Inputs

        ciph_lst - list(bytestring) - List of candidate ciphertexts

    Outputs

        best - list(int, int) - Container with index and repetitions of the most probable of ciphertext
    '''
    
    best = [-1, 0]

    for i in range(len(ciph_lst)):
        reps = aes_ecb_repeats(ciph_lst[i])
        best = max(best, (i, reps), key=lambda x: x[1])

    return best

def main():
    ciph_lst = [bytes.fromhex(line.strip()) for line in open("p08_in.txt")]
    result = detect_aes_ecb(ciph_lst)
    print("Detected probable AES-ECB ciphertext at position", result[0], "with", result[1], "repetitions")

if __name__ == "__main__":
    main()
