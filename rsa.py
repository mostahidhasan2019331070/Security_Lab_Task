import random
import time

# Miller-Rabin primality test for checking if a number is prime
def is_prime(n, k=5):
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    # Write n as (2^r * d) + 1
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(k):
        a = random.randint(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

# Generate a prime number with k bits
def generate_prime(k):
    while True:
        num = random.getrandbits(k)
        num |= (1 << k - 1) | 1  # Ensure it's odd and has k bits
        if is_prime(num):
            return num

# Generate key pairs (public and private keys)
def generate_key_pairs(k):
    p = generate_prime(k // 2)
    q = generate_prime(k // 2)
    while p == q:
        q = generate_prime(k // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = random.randint(2, phi - 1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi - 1)

    # Compute d as the modular multiplicative inverse of e modulo phi
    d = modinv(e, phi)

    return ((e, n), (d, n))

# Extended Euclidean Algorithm to find modular multiplicative inverse
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a
# Compute d as the modular multiplicative inverse of e modulo phi
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

# Encrypt plaintext character by character using RSA encryption
def rsa_encrypt(plaintext, public_key):
    e, n = public_key
    encrypted_text = []
    for char in plaintext:
        encrypted_text.append(pow(ord(char), e, n))
    return encrypted_text

# Decrypt ciphertext and match it with the original plaintext
def rsa_decrypt(ciphertext, private_key):
    d, n = private_key
    decrypted_text = ''
    for char in ciphertext:
        decrypted_text += chr(pow(char, d, n))
    return decrypted_text

# Test the implementation
def test_rsa(k, plaintext):
    # Generate key pairs
    start_time = time.time()
    public_key, private_key = generate_key_pairs(k)
    key_generation_time = time.time() - start_time

    # Encrypt plaintext
    start_time = time.time()
    ciphertext = rsa_encrypt(plaintext, public_key)
    encryption_time = time.time() - start_time

    # Decrypt ciphertext
    start_time = time.time()
    decrypted_text = rsa_decrypt(ciphertext, private_key)
    decryption_time = time.time() - start_time

    # Report time-related performance
    print(f"Key Length: {k} bits")
    print(f"Original Plaintext: {plaintext}")
    print(f"Public Key (e, n): {public_key}")
    print(f"Private Key (d, n): {private_key}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted Text: {decrypted_text}")
    print(f"Key Generation Time: {key_generation_time} seconds")
    print(f"Encryption Time: {encryption_time} seconds")
    print(f"Decryption Time: {decryption_time} seconds")

# Test with different key lengths and plaintext
def main():

   test_rsa(16, "BUETCSEVSSUSTCSE")
   test_rsa(32, "BUETCSEVSSUSTCSE")
   test_rsa(64, "BUETCSEVSSUSTCSE")
  
if __name__ == "__main__":
    main()