
import itertools
import binascii
import time
key_expansion_time=0.0
def key_expansion(key):
    round_keys = [key[i:i+4] for i in range(0, len(key), 4)]
    for i in range(4, 44):
        word = round_keys[i-1]
        if i % 4 == 0:
            word = [word[1], word[2], word[3], word[0]]
            word = [s_box[byte] for byte in word]
            word[0] ^= r_con[i//4][0]
        round_keys.append([word[j] ^ round_keys[i-4][j] for j in range(4)])
    return round_keys
def generate_mul_tables():
    mul2 = [0] * 256
    mul3 = [0] * 256
    mul2 = {(i << 1) ^ (0x11B if (i & 0x80) else 0): i for i in range(256)}
    mul3 = {i: mul2[i] ^ i for i in range(256)}
    return mul2, mul3
mul2, mul3 = generate_mul_tables()
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]
# AES Round Constants
r_con = [
    [0x00, 0x00, 0x00, 0x00],
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]
def add_round_key(state, key):
    # return [[state[i][j] ^ key[i][j] for j in range(4)] for i in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key[j][i]
def transpose_state(state):
    transposed_state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            transposed_state[j][i] = state[i][j]
    return transposed_state
def mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        temp = []
        temp = [mul2[col[row]] ^ mul3[col[(row + 1) % 4]] ^ col[(row + 2) % 4] ^ col[(row + 3) % 4] for row in range(4)]
        for j in range(4):
            state[j][i] = temp[j]
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box[state[i][j]]
def shift_rows(state):
    # state=transpose_state(state)
    for i in range(1, 4):
        state[i] = state[i][i:] + state[i][:i]
    # state=transpose_state(state)
    return state


def aes_encrypt(plaintext, key):
    """
    Encrypts the plaintext using AES encryption algorithm with the given key.

    Parameters:
        plaintext (str): The plaintext message to be encrypted.
        key (str): The encryption key to be used for encryption.

    Returns:
        list: The ciphertext generated after encryption.
    """

    # Initialize an empty list to store the ciphertext
    ciphertext = []

    # Iterate over the plaintext in blocks of 16 bytes (128 bits)
    for i in range(0, len(plaintext), 16):
        
        # Extract a block of 16 bytes from the plaintext
        block = plaintext[i:i + 16]
        
        # Divide the block into a 4x4 matrix (state)
        state = [block[i:i + 4] for i in range(0, len(block), 4)]
        
        # Transpose the state matrix
        state=transpose_state(state)

        # Perform key expansion to generate round keys
        global key_expansion_time
        start_time=time.time()
        round_keys = key_expansion(key)
        key_expansion_time=time.time()-start_time
        
        # Add the initial round key to the state
        add_round_key(state, round_keys[:4])

        # Perform 10 rounds of AES encryption
        for i in range(1, 10):
            sub_bytes(state)        # Substitute bytes using S-box
            state=shift_rows(state) # Shift rows in the state matrix
            mix_columns(state)      # Mix columns in the state matrix
            add_round_key(state, round_keys[4*i:4*(i+1)])  # Add round key
        
        # Perform final round of AES encryption
        sub_bytes(state)        # Substitute bytes using S-box
        state=shift_rows(state) # Shift rows in the state matrix
        add_round_key(state, round_keys[40:])  # Add round key
        
        # Transpose the state matrix back
        state=transpose_state(state)
        
        # Flatten the state matrix and append to the ciphertext list
        ciphertext.extend([state[i][j] for i in range(4) for j in range(4)])
    
    # Return the ciphertext
    return ciphertext


# impelement aes decryption
s_box_inv = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]
inv_mix_column_matrix = [
    [0x0e, 0x0b, 0x0d, 0x09],
    [0x09, 0x0e, 0x0b, 0x0d],
    [0x0d, 0x09, 0x0e, 0x0b],
    [0x0b, 0x0d, 0x09, 0x0e]
]
# implement inv_mix_columns using gf theorem
def inv_mix_columns(state):
    for i in range(4):
        col = [state[j][i] for j in range(4)]
        temp = []
        for row in range(4):
            a = col[row]
            b = col[(row + 1) % 4]
            c = col[(row + 2) % 4]
            d = col[(row + 3) % 4]
            result = gf_multiply(a, 0x0e) ^ gf_multiply(b, 0x0b) ^ gf_multiply(c, 0x0d) ^ gf_multiply(d, 0x09)
            temp.append(result)
        for j in range(4):
            state[j][i] = temp[j]
def gf_multiply(a, b):
    result = 0
    while a and b:
        result ^= a if b & 1 else 0
        a = mul2[a]
        b >>= 1
    return result
def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = s_box_inv[state[i][j]]

def inv_shift_rows(state):
    # state=transpose_state(state)
    for i in range(1, 4):
        state[i] = state[i][-i:] + state[i][:-i]


#implement aes decryption using aes decryption each block is 16 bytes 
def aes_decrypt(ciphertext, key):
    plaintext = []
    for i in range(0, len(ciphertext), 16):
        # Extract a block of 16 bytes from the ciphertext
        block = ciphertext[i:i + 16]
        # Divide the block into a 4x4 matrix (state)
        state = [block[i:i + 4] for i in range(0, len(block), 4)]
        state=transpose_state(state)
        global key_expansion_time
        start_time=time.time()
        # Perform key expansion to generate round keys
        round_keys = key_expansion(key)
        key_expansion_time=key_expansion_time+(time.time()-start_time)
        add_round_key(state, round_keys[40:])
        inv_shift_rows(state)
        inv_sub_bytes(state)
        # inv_mix_columns(state)
         # Apply the inverse operations of AES encryption for 9 rounds
        for i in range(9, 0, -1):
            add_round_key(state, round_keys[4*i:4*(i+1)])
            inv_mix_columns(state)
            inv_shift_rows(state)
            inv_sub_bytes(state)
        # Perform the final round of AES decryption
        add_round_key(state, round_keys[:4])
        state=transpose_state(state)
        plaintext.extend([state[i][j] for i in range(4) for j in range(4)])
    return plaintext

def pad_or_truncate(data):
    """Pad data with zeros if shorter than 16 bytes, truncate if longer."""
    return data + (b'\0' * (16 - len(data))) if len(data) < 16 else data[:16]
def main():
    for _ in itertools.count():
        plaintext = input("Enter the plaintext : ")
        length=len(plaintext)
        plaintext += '0' * (16 - (len(plaintext) % 16)) if len(plaintext) > 16 else ''
        plaintext_bytes = plaintext.encode('utf-8')
        print("plaintext (Hex):", binascii.hexlify(plaintext_bytes).decode('utf-8'))
        key =input("Enter the key: " )
        key_bytes = pad_or_truncate(key.encode('utf-8'))
        print("Key(Hex):", binascii.hexlify(key_bytes).decode('utf-8'))
        plaintext_bytes = [byte for byte in plaintext_bytes]  # Convert bytes to list of integers
        plaintext_bytes = [byte & 0xFF for byte in plaintext_bytes]  # Ensure each byte is within the range [0, 255]
        key_bytes= [byte for byte in key_bytes]  # Convert bytes to list of integers
        key_bytes= [byte & 0xFF for byte in key_bytes]  # Ensure each byte is within the range [0, 255]
        start_time=time.time()
        ciphertext = aes_encrypt(plaintext_bytes, key_bytes)
        encryption_time=time.time()-start_time
        ciphertext_str = ''.join(chr(byte) for byte in ciphertext)
        print("ASCII ciphertext : ",ciphertext_str)
        cipher_bytes=bytes(ciphertext)
        print("ciphertext(Hex): ",binascii.hexlify(cipher_bytes).decode('utf-8'))
        start_time=time.time()
        decrypted = aes_decrypt(ciphertext, key_bytes)
        decrypted_time=time.time()-start_time
        decrypted = bytes(decrypted)
        print("Decrypted as a Bytes  : ",decrypted)
        print("Decrypted(Hex):",binascii.hexlify(decrypted).decode('utf-8'))
        decrypted = decrypted.decode('latin-1')
        print("Decrypted as string:", decrypted[:length])
        #time for encryption ,decryption and key expansion
        print("Execution Time  ")
        print("--------------------------------------------------------------------------------------")
        print("encryption time: ", encryption_time)
        print("decryption time: ",decrypted_time)
        print("key_expansion_time : ",key_expansion_time)
        # Ask the user if they want to continue
        ok = input("Continue? (yes/no): ")
        # choice="sdff"
        if ok.upper() != "YES":
            break

if __name__ == "__main__":
    main()