"""
Public Key Encryption Module

This module provides a clean interface for RSA public key encryption operations.
It handles key generation, encryption, decryption, and key serialization.

The design philosophy here is to hide the complexity of the underlying cryptography
library while providing a simple, safe interface for users.
"""

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend


class PublicKeyEncryption:
    """
    A wrapper class that simplifies RSA public key encryption operations.

    This class encapsulates all the details about padding schemes, hash algorithms,
    and key formats, so users don't need to worry about these cryptographic details.
    """

    def __init__(self, key_size=2048):
        """
        Initialize the encryption system.

        Args:
            key_size (int): The size of RSA keys to generate. 2048 is currently
                           considered secure for most applications.
        """
        self.key_size = key_size
        self.backend = default_backend()

    def generate_keypair(self):
        """
        Generate a new RSA key pair.

        Returns:
            tuple: (private_key, public_key) where both are cryptography objects

        The public exponent 65537 is used because it's prime, relatively small
        (which makes encryption faster), and has become the de facto standard.
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=self.key_size, backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt(self, message, public_key):
        """
        Encrypt a message using a public key.

        Args:
            message (str or bytes): The message to encrypt
            public_key: The recipient's public key

        Returns:
            bytes: The encrypted ciphertext

        Note: We use OAEP padding because it provides semantic security,
        meaning the same message encrypted twice will produce different ciphertexts.
        """
        # Convert string to bytes if necessary - this makes our interface flexible
        if isinstance(message, str):
            message = message.encode("utf-8")

        # OAEP with SHA-256 is currently considered the gold standard for RSA encryption
        ciphertext = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    def decrypt(self, ciphertext, private_key):
        """
        Decrypt a message using a private key.

        Args:
            ciphertext (bytes): The encrypted message
            private_key: The private key for decryption

        Returns:
            str: The decrypted message as a string

        Raises:
            ValueError: If decryption fails (wrong key, corrupted data, etc.)
        """
        try:
            # Use the same padding scheme as encryption - this is critical!
            plaintext = private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return plaintext.decode("utf-8")
        except Exception as e:
            # Wrap the cryptography library's exceptions in something more user-friendly
            raise ValueError(f"Decryption failed: {str(e)}")

    def serialize_private_key(self, private_key, password=None):
        """
        Convert a private key to PEM format for storage.

        Args:
            private_key: The private key to serialize
            password (bytes, optional): Password to encrypt the key file

        Returns:
            bytes: The serialized key in PEM format
        """
        # Choose encryption algorithm based on whether password is provided
        if password is not None:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        else:
            encryption_algorithm = serialization.NoEncryption()

        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption_algorithm,
        )

    def serialize_public_key(self, public_key):
        """
        Convert a public key to PEM format for storage or transmission.

        Args:
            public_key: The public key to serialize

        Returns:
            bytes: The serialized key in PEM format
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def load_private_key(self, pem_data, password=None):
        """
        Load a private key from PEM format.

        Args:
            pem_data (bytes): The PEM-encoded private key
            password (bytes, optional): Password if the key is encrypted

        Returns:
            Private key object
        """
        return serialization.load_pem_private_key(
            pem_data, password=password, backend=self.backend
        )

    def load_public_key(self, pem_data):
        """
        Load a public key from PEM format.

        Args:
            pem_data (bytes): The PEM-encoded public key

        Returns:
            Public key object
        """
        return serialization.load_pem_public_key(pem_data, backend=self.backend)

    def create_dummy_public_key(self):
        """
        Generate a public key without keeping the corresponding private key.

        This is useful for protocols like oblivious transfer where you need
        a "fake" key that looks legitimate but can't actually decrypt anything.

        Returns:
            Public key object (with no accessible private key)
        """
        # Generate a temporary key pair
        temp_private, temp_public = self.generate_keypair()

        # Return only the public key - the private key goes out of scope
        # and becomes inaccessible
        return temp_public


# Convenience functions for quick operations
def quick_encrypt(message, public_key):
    """
    Convenience function for one-off encryption operations.
    """
    pke = PublicKeyEncryption()
    return pke.encrypt(message, public_key)


def quick_decrypt(ciphertext, private_key):
    """
    Convenience function for one-off decryption operations.
    """
    pke = PublicKeyEncryption()
    return pke.decrypt(ciphertext, private_key)


def quick_keygen():
    """
    Convenience function to quickly generate a key pair.
    """
    pke = PublicKeyEncryption()
    return pke.generate_keypair()
