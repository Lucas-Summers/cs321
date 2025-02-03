import hashlib
import random
import time
import matplotlib.pyplot as plt

def sha256_hash(data):
    """Compute SHA-256 hash of the input data and return as a hex string."""
    return hashlib.sha256(data.encode()).hexdigest()

def bit_flip(string, bit_pos):
    """Flip a single bit at bit_pos in a binary string representation."""
    byte_list = bytearray(string.encode())
    byte_list[bit_pos // 8] ^= 1 << (bit_pos % 8)  # Flip the bit
    return byte_list.decode(errors='ignore')

def truncate_hash(hex_digest, bits):
    """Truncate a SHA-256 hash to the first `bits` bits."""
    binary_digest = bin(int(hex_digest, 16))[2:].zfill(256)
    return binary_digest[:bits]

def find_collision(bits, method="birthday"):
    """
    Find a collision for a truncated hash output.
    - method = "birthday" (default): Uses the Birthday Paradox approach.
    - method = "weak": Tries to find a collision for a target hash.
    """
    start_time = time.time()
    hash_dict = {}
    attempts = 0

    while True:
        random_input = str(random.getrandbits(256))
        hex_digest = sha256_hash(random_input)
        truncated_hash = truncate_hash(hex_digest, bits)

        if method == "birthday":
            if truncated_hash in hash_dict:
                elapsed_time = time.time() - start_time
                return attempts, elapsed_time, random_input, hash_dict[truncated_hash]
            hash_dict[truncated_hash] = random_input

        elif method == "weak":
            if attempts == 0:
                target_input = random_input
                target_truncated_hash = truncated_hash
            elif truncated_hash == target_truncated_hash:
                elapsed_time = time.time() - start_time
                return attempts, elapsed_time, target_input, random_input

        attempts += 1

def experiment():
    """Run collision tests for different bit sizes and plot results."""
    bit_sizes = list(range(8, 51, 2))  # 8-bit to 50-bit truncation in steps of 2
    num_inputs_list = []
    time_list = []

    for bits in bit_sizes:
        attempts, elapsed_time, input1, input2 = find_collision(bits, method="birthday")
        print(f"Collision found at {bits} bits: {input1} and {input2}")
        num_inputs_list.append(attempts)
        time_list.append(elapsed_time)

    # Plot graphs
    plt.figure(figsize=(10, 5))
    
    plt.subplot(1, 2, 1)
    plt.plot(bit_sizes, time_list, marker='o', linestyle='-')
    plt.xlabel("Digest Size (bits)")
    plt.ylabel("Time to Find Collision (seconds)")
    plt.title("Digest Size vs Collision Time")
    
    plt.subplot(1, 2, 2)
    plt.plot(bit_sizes, num_inputs_list, marker='s', linestyle='-', color='r')
    plt.xlabel("Digest Size (bits)")
    plt.ylabel("Number of Inputs Tried")
    plt.title("Digest Size vs Inputs Needed for Collision")
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    # Part (a): SHA-256 Hashing
    test_strings = ["hello", "world", "test123", "crypto"]
    for s in test_strings:
        print(f"SHA-256({s}) = {sha256_hash(s)}")

    # Part (b): Hashing two strings with a 1-bit difference
    base_string = "hello"
    for i in range(3):  # Do this a few times
        bit_flipped_string = bit_flip(base_string, i)
        print(f"Original: {base_string}, Hash: {sha256_hash(base_string)}")
        print(f"Modified: {bit_flipped_string}, Hash: {sha256_hash(bit_flipped_string)}")
        print("-" * 50)

    # Part (c): Collision Search and Graphs
    experiment()