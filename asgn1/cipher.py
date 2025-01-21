from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import sys


def pkcs7_pad(data, block_size=16):
    padding_len = block_size - (len(data) % block_size)
    return data + bytes([padding_len] * padding_len)

def pkcs7_unpad(data):
    padding_len = data[-1]
    return data[:-padding_len]

def aes_ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        ciphertext += cipher.encrypt(block)
    return ciphertext

def aes_cbc_encrypt(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = b""
    prev_block = iv
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        block = bytes(a ^ b for a, b in zip(block, prev_block))
        encrypted_block = cipher.encrypt(block)
        ciphertext += encrypted_block
        prev_block = encrypted_block
    return iv + ciphertext

def encrypt_aes(key, data, mode):
    padded_data = pkcs7_pad(data)
    
    if mode == 'ecb':
        encrypted_data = aes_ecb_encrypt(padded_data, key)
    elif mode == 'cbc':
        iv = get_random_bytes(16)
        encrypted_data = aes_cbc_encrypt(padded_data, key, iv)
    else:
        raise ValueError("Not a valid mode")    
    return encrypted_data

def decrypt_aes(key, data, mode):
    if mode == 'ecb':
        cipher = AES.new(key, AES.MODE_ECB)
        plaintext = pkcs7_unpad(cipher.decrypt(data), AES.block_size)
    elif mode == 'cbc':
        iv = data[:16]
        ciphertext = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = pkcs7_unpad(cipher.decrypt(ciphertext), AES.block_size)
    else:
        raise ValueError("Not a valid mode")
    return plaintext

if __name__ == "__main__":
    with open(sys.argv[1], 'rb') as f:
        header = f.read(54)  # Adjust if the header is 138 bytes
        data = f.read()

    key = get_random_bytes(16)
    encrypted_data = encrypt_aes(key, data, sys.argv[3])

    with open(sys.argv[2], 'wb') as f:
        f.write(header + encrypted_data)
