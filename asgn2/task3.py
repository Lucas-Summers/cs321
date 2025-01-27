import random
from Crypto.Util.number import getPrime, inverse
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# RSA Key Generation
def generate_rsa_keypair(bits=2048, e=65537):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        if phi_n % e != 0:
            break
    d = inverse(e, phi_n)
    return (n, e), (n, d)  # Public key, Private key

# RSA Encryption
def rsa_encrypt(m, public_key):
    n, e = public_key
    return pow(m, e, n)

# RSA Decryption
def rsa_decrypt(c, private_key):
    n, d = private_key
    return pow(c, d, n)

def rsa_malleability_attack():
    # Generate keys
    public_key, private_key = generate_rsa_keypair()
    n, e = public_key

    # Alice chooses a symmetric key (s) and encrypts it
    s = random.randint(2, n - 1)  # Random key less than n
    c = rsa_encrypt(s, public_key)  # Encrypted symmetric key

    # Mallory modifies the ciphertext
    c_prime = (c * pow(2, e, mod=n))  # Multiply original ciphertext by 2^e mod n

    # Alice decrypts c_prime
    s_prime = rsa_decrypt(c_prime, private_key)  # Alice computes new "s"
    
    # Mallory computes s from s_prime
    recovered_s = s_prime // 2  # Divide the modified plaintext by 2

    # Verify Mallory's attack
    print("Original symmetric key (s):", s)
    print("Recovered symmetric key by Mallory:", recovered_s)
    print("Attack Successful:", s == recovered_s)

    # Encrypt a message with AES using the original symmetric key
    shared_key = hashlib.sha256(str(s).encode()).digest()[:16]
    message = "Hi Bob!"
    cipher = AES.new(shared_key, AES.MODE_CBC, b'1234567890123456')
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))

    # Mallory decrypts the message using the recovered symmetric key
    mallory_key = hashlib.sha256(str(recovered_s).encode()).digest()[:16]
    mallory_cipher = AES.new(mallory_key, AES.MODE_CBC, b'1234567890123456')
    recovered_message = unpad(mallory_cipher.decrypt(ciphertext), AES.block_size).decode()

    print("Original Message:", message)
    print("Recovered Message by Mallory:", recovered_message)

# Signature Malleability
def rsa_signature_malleability():
    # Generate keys
    public_key, private_key = generate_rsa_keypair()
    n, d = private_key
    e = public_key[1]

    # Mallory sees signatures for two messages
    m1 = int.from_bytes("Hello".encode(), 'big') 
    m2 = int.from_bytes("World".encode(), 'big')
    sig1 = rsa_encrypt(m1, private_key)  # Signature for m1
    sig2 = rsa_encrypt(m2, private_key)  # Signature for m2

    # Mallory creates a signature for m3 = m1 * m2
    m3 = (m1 * m2) % n
    sig3 = (sig1 * sig2) % n  # Signature for m3

    # Verify Mallory's attack
    verified_m3 = rsa_decrypt(sig3, public_key)
    print("\nSignature Malleability Attack:")
    print("Message m3 (as integer):", m3)
    print("Recovered m3 from signature:", verified_m3)
    print("Attack Successful:", m3 == verified_m3)

# Run the attacks
print("=== RSA Malleability Attack ===")
rsa_malleability_attack()

print("\n=== RSA Signature Malleability ===")
rsa_signature_malleability()