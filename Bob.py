from aes import pad_or_truncate,aes_decrypt
from rsa import rsa_decrypt
import itertools
import binascii
import time
import random
import os
def exitance(file_path):
     if os.path.exists(file_path):
          with open(file_path,'r') as file:
               res=file.read()
               return res
     else:
          print("File not found:", file_path)
          return "-1"
def main():
        print("------------------------------------------------------------------------------------------")
        print("Use RSA decrypt  the key first")
        print("-------------------------------------------------------------------------------------------")
        folder_name = "Don't Open this"
        # Construct the file path
        file_path1 = os.path.join(folder_name, 'private.txt')
        file_path2=os.path.join(folder_name,'encrypted_key.txt')
        # Private key read
        private_key = exitance(file_path1)
        print("private key as string",private_key)
        private_key = tuple(int(x) for x in private_key.split(','))
        print("tuple of private key",private_key)
        #encrypted_key read
        cipherkey=exitance(file_path2)
        print("cipherkey as string",cipherkey)
        cipherkey=eval(cipherkey)
        print("cipherkey as list:",cipherkey)
        # Decrypt cipher key
        start_time = time.time()
        decrypted_key = rsa_decrypt(cipherkey, private_key)
        decryption_time = time.time() - start_time
        print("decrypted key :",decrypted_key)
        print("---------------------------------------------------")
        print("By using decrypted key and AES Algo ,decrypt the ciphertext ")
        print("-----------------------------------------------")
        #read the ciphertext from file
        file_path3=os.path.join(folder_name,'encrypted_plaintext.txt')
        encrypted_plaintext=exitance(file_path3)
        print("encrypted plaintext as string:",encrypted_plaintext)
        encrypted_plaintext=eval(encrypted_plaintext)
        print("encrypted plaintext as string:",encrypted_plaintext)
        key_bytes=pad_or_truncate(decrypted_key.encode('utf-8'))
        key_bytes= [byte for byte in key_bytes] 
        key_bytes= [byte & 0xFF for byte in key_bytes] 
        decrypted_text=aes_decrypt(encrypted_plaintext,key_bytes)
        decrypted_time=time.time()-start_time
        decrypted_text = bytes(decrypted_text)
        print("Decrypted as a Bytes  : ",decrypted_text)
        print("Decrypted(Hex):",binascii.hexlify(decrypted_text).decode('utf-8'))
        decrypted_text = decrypted_text.decode('utf-8')
        decrypted_text=decrypted_text.rstrip('0')
        print("Decrypted as string:", decrypted_text)
        #write the decrypted text in DPT
        file_path4=os.path.join(folder_name, 'DPT.txt')
        with open(file_path4, 'w') as file:
            file.write(decrypted_text)
        

        
if __name__ == "__main__":
    main()