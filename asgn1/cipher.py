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
    return ciphertext

def process_bmp(file_path, mode):
    with open(file_path, 'rb') as f:
        header = f.read(54)  # Adjust if the header is 138 bytes
        data = f.read()
    
    key = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    padded_data = pkcs7_pad(data)
    
    if mode == 'ecb':
        encrypted_data = aes_ecb_encrypt(padded_data, key)
    elif mode == 'cbc':
        encrypted_data = aes_cbc_encrypt(padded_data, key, iv)
    
    with open(f'encrypted_{mode}.bmp', 'wb') as f:
        f.write(header + encrypted_data)

if __name__ == "__main__":
    process_bmp(sys.argv[1], sys.argv[2])