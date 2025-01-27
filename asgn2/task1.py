import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# small parameteres
#q = 37
#alpha = 5

# large parameters
q = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E286"
        "75A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
        "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF"
        "365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)

alpha = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E"
            "5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
            "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D59"
            "18D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)


# Alice keys
X_A = random.randint(1, q - 1)  ### priv
Y_A = pow(alpha, X_A, q)  # pub

# Bob keys
X_B = random.randint(1, q - 1)  # bob priv
Y_B = pow(alpha, X_B, q)  # bob pub

# shared secret
s_A = pow(Y_B, X_A, q)  # Alice 
s_B = pow(Y_A, X_B, q)  # Bob

# check shared secrets r equal
assert s_A == s_B, "Shared secrets do not match!"
s = s_A

# final shared key
shared_key = hashlib.sha256(str(s).encode()).digest()[:16]  

# Alice message encrypted
message_A = "Hi Bob!"
cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456') #16 dig IV
ciphertext_A = cipher.encrypt(pad(message_A.encode(), AES.block_size))

# Bob decrypts Alice message
cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456')
decrypted_message_A = unpad(cipher.decrypt(ciphertext_A), AES.block_size).decode()

# Bob reply encrypted
message_B = "Hi Alice!"
cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456')
ciphertext_B = cipher.encrypt(pad(message_B.encode(), AES.block_size))

# Alice decrypts Bob reply
cipher = AES.new(shared_key, AES.MODE_CBC, iv=b'1234567890123456')
decrypted_message_B = unpad(cipher.decrypt(ciphertext_B), AES.block_size).decode()


print("Alice's Message:", message_A)
print("Ciphertext Sent from Alice to Bob:", ciphertext_A)
print("Decrypted Message at Bob's End:", decrypted_message_A)
print("Bob's Message:", message_B)
print("Ciphertext Sent from Bob to Alice:", ciphertext_B)
print("Decrypted Message at Alice's End:", decrypted_message_B)