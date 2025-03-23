import random

# Sample data (e.g., a sensitive database column)
data = [12, 7, 5, 19, 21]  # plaintext values

# Setup phase: generate random masks for each data point
masks_sum = [random.randint(1000, 9999) for _ in data]
masks_count = [random.randint(1000, 9999) for _ in data]

# Encrypt data for SUM query: add each mask to the corresponding value
ciphertext_data = [x + r for x, r in zip(data, masks_sum)]

# Encrypt data for COUNT query: represent each record's presence as 1, then mask it
ciphertext_ones = [1 + r for r in masks_count]

# Simulated server computes aggregates on encrypted data (without seeing plaintext)
cipher_sum = sum(ciphertext_data)   # sum of masked values (encrypted sum)
cipher_count = sum(ciphertext_ones) # sum of masked 1's (encrypted count)

# KeyGen (functional key derivation): data owner computes sum of all masks for each function
key_sum = sum(masks_sum)
key_count = sum(masks_count)

# Decryption using functional keys: subtract mask sums to retrieve actual results
result_sum = cipher_sum - key_sum         # decrypted SUM
result_count = cipher_count - key_count   # decrypted COUNT
result_avg = result_sum / result_count    # compute AVG from SUM and COUNT

# Output the step-by-step results
print("Original data (plaintext):", data)
print("Query: Compute SUM, COUNT, and AVG on the encrypted data")
print("Encrypted data (sent to server):", ciphertext_data)
print("Server computed encrypted SUM:", cipher_sum)
print("Server computed encrypted COUNT:", cipher_count)
print("Decrypted SUM result:", result_sum)
print("Decrypted COUNT result:", result_count)
print("Decrypted AVG result:", result_avg)