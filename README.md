# Crypto
This program employs AES-256-GCM encryption to secure files, offering two key management modes to accommodate different security requirements. Given the resilience of modern symmetric encryption against both classical and foreseeable quantum attacks, this solution provides users with a robust means of data protection.

# I. Overview
The program can encrypt any file using AES-256-GCM and produce a corresponding .enc file. With the appropriate key, it can also decrypt .enc files back to the original data. Users can choose between two key management approaches, offering flexibility in how keys are stored and protected.

# II. Encryption and Decryption Workflow
Encryption:

The program obtains a 256-bit AES key held in memory.
It generates a 12-byte random nonce for each encryption operation.
Using AES-256-GCM, it encrypts the file’s content and outputs the .enc file containing the nonce, an authentication tag (tag), and the ciphertext.
Decryption:

The program reads the nonce, tag, and ciphertext from the .enc file.
With the same AES key, it decrypts and verifies the file’s integrity using AES-256-GCM. If successful, the original data is restored.
# III. Key Management Modes
Standard Key Mode:
The generated 256-bit key is stored in plaintext form in a .key file. To encrypt or decrypt, the user only needs to load this file. This mode is suitable for environments where the key file can be safely protected.

Encrypted Key with Passphrase Mode:
After generating the AES key, the program prompts the user for a passphrase. A Key Derivation Function (KDF), such as PBKDF2, uses this passphrase to derive a Key Encryption Key (KEK).

Saving the key: The 32-byte AES key is encrypted with AES-GCM using the KEK and then saved to the .key file.
Loading the key: The user must enter the same passphrase to derive the KEK, which is then used to decrypt the key data from the .key file, restoring the original AES key.
This approach ensures that even if the .key file is stolen, an attacker without the passphrase cannot recover the actual key.

# IV. Security Considerations
Classical Computing Difficulty:
The AES-256 key space is 2^256, making brute-force attacks by classical supercomputers utterly infeasible. This sheer complexity ensures that unauthorized decryption without the correct key remains effectively impossible.

Quantum Computing Perspective:
While quantum algorithms like Grover’s algorithm could theoretically reduce brute-force search complexity from O(2^n) to O(2^(n/2)), AES-256 would still require on the order of 2^128 operations, a number far beyond any practical computing capability. Even with advancements like Google’s “Willow” quantum chip, leveraging such power to brute-force AES-256 in any realistic timeframe remains out of reach.

KDF and Passphrase Strengthening:
Using a KDF to derive keys from a passphrase increases the effort needed to guess or brute-force that passphrase. Both classical and quantum attackers face an immense computational barrier, especially when the passphrase and KDF parameters are chosen wisely.

# V. Summary
This program builds on the inherent security of AES-256-GCM, offering two key management modes to meet user needs. Despite rapid progress in classical and quantum computing, AES-256 remains trusted against brute-force attacks for the foreseeable future. By integrating passphrase protection (via KDFs) and robust authentication, the program ensures that unauthorized data recovery remains prohibitively difficult, providing a strong defense for the user’s sensitive information.
