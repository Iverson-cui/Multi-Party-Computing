from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


def generate_key_pair():
    """
    Generate a new RSA key pair.
    Returns both private and public keys.
    """
    # Generate a private key with 2048-bit key size
    # 65537 is a commonly used public exponent (it's prime and efficient)
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )

    # The public key is derived from the private key
    public_key = private_key.public_key()

    return private_key, public_key


def encrypt_message(message, public_key):
    """
    Encrypt a message using the public key.
    Uses OAEP padding for security.
    """
    # Convert string to bytes if necessary
    if isinstance(message, str):
        message = message.encode("utf-8")

    # Encrypt using OAEP padding with SHA-256
    # OAEP (Optimal Asymmetric Encryption Padding) adds randomness for security
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Mask Generation Function
            algorithm=hashes.SHA256(),  # Hash algorithm
            label=None,  # Optional label (rarely used)
        ),
    )

    return ciphertext


def decrypt_message(ciphertext, private_key):
    """
    Decrypt a message using the private key.
    Must use the same padding scheme as encryption.
    """
    # Decrypt using the same OAEP padding configuration
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Convert bytes back to string
    return plaintext.decode("utf-8")


def save_keys_to_files(private_key, public_key):
    """
    Save keys to files for later use.
    Keys are serialized in PEM format for portability.
    """
    # Serialize private key (keep this secret!)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),  # For simplicity, no password
    )

    # Serialize public key (safe to share)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Save to files
    with open("private_key.pem", "wb") as f:
        f.write(private_pem)

    with open("public_key.pem", "wb") as f:
        f.write(public_pem)

    print("Keys saved to private_key.pem and public_key.pem")


def load_keys_from_files():
    """
    Load previously saved keys from files.
    """
    # Load private key
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()  # No password was used
        )

    # Load public key
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(), backend=default_backend()
        )

    return private_key, public_key


# Demonstration of the complete process
def main():
    # Step 1: Generate key pair
    print("Generating RSA key pair...")
    private_key, public_key = generate_key_pair()

    # Step 2: Save keys (optional - for reuse later)
    save_keys_to_files(private_key, public_key)

    # Step 3: Encrypt a message
    original_message = "Hello! This is a secret message that needs encryption."
    print(f"Original message: {original_message}")

    encrypted_data = encrypt_message(original_message, public_key)
    print(f"Encrypted data (first 50 chars): {encrypted_data[:50]}...")

    # Step 4: Decrypt the message
    decrypted_message = decrypt_message(encrypted_data, private_key)
    print(f"Decrypted message: {decrypted_message}")

    # Verify they match
    print(f"Messages match: {original_message == decrypted_message}")

    # Demonstrate loading keys from files
    print("\nTesting key loading from files...")
    loaded_private, loaded_public = load_keys_from_files()

    # Test with loaded keys
    test_message = "Testing with loaded keys!"
    encrypted_with_loaded = encrypt_message(test_message, loaded_public)
    decrypted_with_loaded = decrypt_message(encrypted_with_loaded, loaded_private)
    print(f"Test with loaded keys successful: {test_message == decrypted_with_loaded}")


if __name__ == "__main__":
    main()
