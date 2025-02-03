import bcrypt
import time
import nltk
from nltk.corpus import words
import concurrent.futures
from tqdm import tqdm

nltk.download('words')

# Load wordlist from NLTK corpus (filtering words between 6 and 10 characters)
wordlist = [w.lower() for w in words.words() if 6 <= len(w) <= 10]

def parse_shadow_file(filename):
    """Parses the shadow file to extract user credentials."""
    user_data = {}
    with open(filename, "r") as f:
        for line in f:
            parts = line.strip().split("$")
            if len(parts) < 4:
                continue
            user = parts[0].split(":")[0]
            salt = f"${parts[1]}${parts[2]}${parts[3][:22]}"
            hashed = f"${parts[1]}${parts[2]}${parts[3]}"
            user_data[user] = (salt, hashed)
    return user_data

def check_password(candidate, hashed_password):
    """Checks if a candidate password matches the bcrypt hash."""
    return bcrypt.checkpw(candidate.encode(), hashed_password.encode())

def crack_user_password(user, salt, hashed_password):
    """Attempts to crack bcrypt hashes using multithreading with a progress bar."""
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        future_to_word = {executor.submit(check_password, word, hashed_password): word for word in wordlist}

        with tqdm(total=len(wordlist), desc=f"Cracking {user}", unit=" tries") as pbar:
            for future in concurrent.futures.as_completed(future_to_word):
                word = future_to_word[future]
                if future.result():  # If password matches
                    end_time = time.time()
                    print(f"\n✅ Password for {user}: {word} (Time: {end_time - start_time:.2f}s)")
                    return user, word, end_time - start_time
                pbar.update(1)  # Update progress bar

    return user, None, None  # If not cracked


def parallel_brute_force_bcrypt(user_data):
    """Cracks multiple bcrypt passwords in parallel."""
    cracked_passwords = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(crack_user_password, user, salt, hashed): user for user, (salt, hashed) in user_data.items()}

        for future in concurrent.futures.as_completed(futures):
            user, password, time_taken = future.result()
            if password:
                cracked_passwords[user] = (password, time_taken)

    return cracked_passwords

if __name__ == "__main__":
    shadow_file = "shadow.txt"  # Replace with actual filename
    user_data = parse_shadow_file(shadow_file)
    cracked_passwords = parallel_brute_force_bcrypt(user_data)

    # Log results
    with open("cracked_results.txt", "w") as f:
        for user, (password, time_taken) in cracked_passwords.items():
            f.write(f"{user}: {password}, Time: {time_taken:.2f}s\n")