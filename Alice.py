from aes import aes_encrypt,pad_or_truncate
from rsa import rsa_encrypt,generate_key_pairs
import itertools
import binascii
import time
import os
key_expansion_time=0
def main():
    for _ in itertools.count():
        print("------------------------------------------------------------------------------------------")
        print("Use AES encrypt the Plaintext")
        print("-------------------------------------------------------------------------------------------")
        plaintext = input("Enter plaintext: ")
        #write plaintext in the plaintext.txt
        folder_name = "Don't Open this"
        file_pth=os.path.join(folder_name,'plaintext.txt') 
        with open(file_pth,'w') as file:
            file.write(plaintext)
         
        
        length=len(plaintext)
        # Paraphrased code using a ternary operator
        plaintext += '0' * (16 - (len(plaintext) % 16)) if len(plaintext) > 16 else ''
        plaintext_bytes = plaintext.encode('utf-8')
        print("plaintext (Hex):", binascii.hexlify(plaintext_bytes).decode('utf-8'))
        key =input("Enter key: " )
        key_bytes = pad_or_truncate(key.encode('utf-8'))
        print("Key(Hex):", binascii.hexlify(key_bytes).decode('utf-8'))
        plaintext_bytes = [byte for byte in plaintext_bytes]  # Convert bytes to list of integers
        plaintext_bytes = [byte & 0xFF for byte in plaintext_bytes]  # Ensure each byte is within the range [0, 255]
        key_bytes= [byte for byte in key_bytes]  # Convert bytes to list of integers
        key_bytes= [byte & 0xFF for byte in key_bytes]  # Ensure each byte is within the range [0, 255]
        start_time=time.time()
        ciphertext = aes_encrypt(plaintext_bytes, key_bytes)
        encryption_time=time.time()-start_time
        # ciphertext_str = ''.join(chr(byte) for byte in ciphertext)
        ciphertext_plaintext=str(ciphertext)
        print("ASCII ciphertext : ",ciphertext_plaintext)
        # file_path4=os.path.
        cipher_bytes=bytes(ciphertext)
        print("ciphertext(Hex): ",binascii.hexlify(cipher_bytes).decode('utf-8'))
        print("encryption time of Plaintext: ", encryption_time)
        # print("decryption time: ",decrypted_time)
        print("key_expansion_time  of AES: ",key_expansion_time)
        print("-----------------------------------------------------------------------------------------")
        print("Using RSA Encrypted the Key")
        print("-------------------------------------------------------------------------------------------")
        public_key,private_key=generate_key_pairs(16)
        # Construct the file path
        file_path = os.path.join(folder_name, 'public.txt')
        file_path2=os.path.join(folder_name,'private.txt')
        file_path4=os.path.join(folder_name,'encrypted_plaintext.txt')
        public_key_str=tuple(map(str,public_key))
        private_key_str=tuple(map(str,private_key))
        public_key_str=','.join(public_key_str)
        private_key_str=','.join(private_key_str)

        # Ensure the folder exists, create it if it doesn't
        # if not os.path.exists(folder_name):
        #         os.makedirs(folder_name)
        # Write the public key to the text file
        with open(file_path, 'w') as file:
            file.write(public_key_str)
        with open(file_path2,'w') as file:
             file.write(private_key_str)
        with open(file_path4,'w') as file:
            file.write(ciphertext_plaintext)
          # Encrypt plaintext
        start_time = time.time()
        ciphertext_key =rsa_encrypt(key, public_key)
        encryption_time = time.time() - start_time
        ciphertext_key=str(ciphertext_key)
        file_path3=os.path.join(folder_name,'encrypted_key.txt')
        with open(file_path3,'w') as file:
            file.write(ciphertext_key)

        print("-----------------------------------------------------------------------------------------")
        # Ask the user if they want to continue
        ok = input("Continue? (yes/no): ")
        # choice="sdff"
        if ok.upper() != "YES":
            break

if __name__ == "__main__":
    main()