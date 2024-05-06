
import subprocess
import Bob
import os
def main():
        #run Bob.py from here
        subprocess.run(["python","Bob.py"])
        #read the plaintext from plaintext.txt
        folder_name="Don't Open this"
        file_path=os.path.join(folder_name,'plaintext.txt')
        plaintext=Bob.exitance(file_path)
        #read the decryptedtext from DPT.txt
        file_path1=os.path.join(folder_name,'DPT.txt')
        decrypted_text=Bob.exitance(file_path1)
        if plaintext==decrypted_text:
            print("Alhamdulillah ,succeed")
        else:
            print("Alhamdulillah,Failed.Failure is pillar of suceess")

if __name__ == "__main__":
    main()