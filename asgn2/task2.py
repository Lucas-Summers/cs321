import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# large parameters
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E286"
        "75A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF"
        "365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)

alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E"
            "5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
            "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D59"
            "18D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)

# Diffie-Hellman Key Exchange with MITM Attack
def mitm_attack_key_tampering():
    # Alice's private and public keys
    X_A = random.randint(1, q - 1)
    Y_A = pow(alpha, X_A, q)
    
    # Bob's private and public keys
    X_B = random.randint(1, q - 1)
    Y_B = pow(alpha, X_B, q)
    
    # Mallory intercepts and replaces public keys
    Y_A_tampered = q
    Y_B_tampered = q
    
    # Alice and Bob compute shared secrets
    s_A = pow(Y_B_tampered, X_A, q)
    s_B = pow(Y_A_tampered, X_B, q)
    
    # Mallory computes the same shared secret (s = 0 due to tampered keys)
    mallory_shared_secret = 0
    
    # Generate keys
    shared_key = hashlib.sha256(str(s_A).encode()).digest()[:16]
    mallory_key = hashlib.sha256(str(mallory_shared_secret).encode()).digest()[:16]
    
    # Alice encrypts a message
    message = "Hi Bob!"
    cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456')
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    
    # Mallory decrypts the message
    cipher = AES.new(mallory_key, AES.MODE_CBC, iv=b'1234567890123456')
    mallory_decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    
    print("Mallory Decrypted Message from Alice to Bob:", mallory_decrypted_message)

def mitm_attack_alpha_tampering():
    for case in [1, 2, 3]:  # Test tampering with alpha = 1, q, q-1
        if case == 1:
            return 1
        elif case == 2:
            return q
        elif case == 3:
            return q - 1
        
        # Alice's private and public keys
        X_A = random.randint(1, q - 1)
        Y_A = pow(tampered_alpha, X_A, q)
        
        # Bob's private and public keys
        X_B = random.randint(1, q - 1)
        Y_B = pow(tampered_alpha, X_B, q)
        
        # Shared secrets
        s_A = pow(Y_B, X_A, q)
        s_B = pow(Y_A, X_B, q)
        
        # Mallory computes the same predictable shared secret
        if tampered_alpha == 1:
            mallory_shared_secret = 1
        elif tampered_alpha == q:
            mallory_shared_secret = 0
        elif tampered_alpha == q - 1:
            mallory_shared_secret = 1 if X_A % 2 == 0 and X_B % 2 == 0 else q - 1
        
        # Generate keys
        shared_key = hashlib.sha256(str(s_A).encode()).digest()[:16]
        mallory_key = hashlib.sha256(str(mallory_shared_secret).encode()).digest()[:16]
        
        # Alice encrypts a message
        message = "Hi Bob!"
        cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456')
        ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
        
        # Mallory decrypts the message
        cipher = AES.new(mallory_key, AES.MODE_CBC, iv=b'1234567890123456')
        mallory_decrypted_message = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
        
        print(f"Case {case} (alpha = {tampered_alpha}): Mallory Decrypted Message:", mallory_decrypted_message)

# Run the attacks
print("=== MITM Attack: Tampering with Keys ===")
mitm_attack_key_tampering()

print("\n=== MITM Attack: Tampering with Alpha ===")
mitm_attack_alpha_tampering()