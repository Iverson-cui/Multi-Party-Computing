"""
Oblivious Transfer Implementation

This module implements the 1-out-of-2 oblivious transfer protocol using
the public key encryption primitives from our separate module.

The beauty of this design is that we could swap out different encryption
schemes (like elliptic curve cryptography) just by changing the import,
as long as they provide the same interface.
"""

# Import our custom public key encryption module
from public_key_encryption import PublicKeyEncryption


class OTReceiver:
    """
    The Receiver in a 1-out-of-2 Oblivious Transfer protocol.

    The receiver has a secret choice bit and wants to learn exactly one
    of the sender's two secrets without revealing which one they chose.
    """

    def __init__(self, selection_bit):
        """
        Initialize the receiver with their secret choice.

        Args:
            selection_bit (int): Either 0 or 1, indicating which secret they want
        """
        if selection_bit not in [0, 1]:
            raise ValueError("Selection bit must be 0 or 1")

        self.selection_bit = selection_bit
        self.pke = PublicKeyEncryption()  # Our encryption engine
        self.private_key = None  # Will store the real private key
        self.public_key = None  # Will store the real public key

    def prepare_key_pairs(self):
        """
        Step 1 of the OT protocol: Prepare the key arrangement.

        This is where the magic happens. We create one real key pair and one
        dummy public key, then arrange them based on our selection bit.
        The sender will see two legitimate-looking public keys but won't know
        which one we can actually use.

        Returns:
            tuple: (pk0, pk1) - the two public keys to send to the sender
        """
        print(f"🔐 Receiver: I secretly want x_{self.selection_bit}")

        # Generate our real key pair - this is the only private key we'll keep
        self.private_key, self.public_key = self.pke.generate_keypair()
        print("🔑 Receiver: Generated real key pair")

        # Create a dummy public key (we throw away its private key)
        dummy_public_key = self.pke.create_dummy_public_key()
        print("🎭 Receiver: Generated dummy public key")

        # Here's the clever bit: arrange the keys based on our secret choice
        if self.selection_bit == 0:
            # We want secret 0, so put our real key in position 0
            pk0, pk1 = self.public_key, dummy_public_key
            print("📍 Receiver: Real key placed in position 0")
        else:
            # We want secret 1, so put our real key in position 1
            pk0, pk1 = dummy_public_key, self.public_key
            print("📍 Receiver: Real key placed in position 1")

        print("📤 Receiver: Sending key pair to sender")
        return pk0, pk1

    def decrypt_chosen_secret(self, e0, e1):
        """
        Step 3 of the OT protocol: Decrypt the ciphertext we can actually decrypt.

        We'll receive two encrypted secrets but can only decrypt one of them
        (the one encrypted with our real public key).

        Args:
            e0 (bytes): Encryption of secret 0
            e1 (bytes): Encryption of secret 1

        Returns:
            str: The secret we chose to receive
        """
        print("📥 Receiver: Received encrypted secrets from sender")
        print("🔓 Receiver: Attempting to decrypt...")

        # Try to decrypt both, but only one should work
        decryption_results = {}

        # Attempt to decrypt e0
        try:
            secret_0 = self.pke.decrypt(e0, self.private_key)
            decryption_results[0] = secret_0
            print(f"✅ Successfully decrypted secret 0: '{secret_0}'")
        except ValueError:
            decryption_results[0] = None
            print("❌ Cannot decrypt secret 0 (this is expected if we chose 1)")

        # Attempt to decrypt e1
        try:
            secret_1 = self.pke.decrypt(e1, self.private_key)
            decryption_results[1] = secret_1
            print(f"✅ Successfully decrypted secret 1: '{secret_1}'")
        except ValueError:
            decryption_results[1] = None
            print("❌ Cannot decrypt secret 1 (this is expected if we chose 0)")

        # Return the secret we actually wanted
        chosen_secret = decryption_results[self.selection_bit]
        if chosen_secret is None:
            raise RuntimeError("Failed to decrypt the chosen secret! Protocol error.")

        print(f"🎯 Receiver: Successfully obtained chosen secret: '{chosen_secret}'")
        return chosen_secret


class OTSender:
    """
    The Sender in a 1-out-of-2 Oblivious Transfer protocol.

    The sender has two secrets and is willing to let the receiver learn
    exactly one of them, but doesn't want to know which one the receiver chose.
    """

    def __init__(self, secret_0, secret_1):
        """
        Initialize the sender with their two secrets.

        Args:
            secret_0 (str): The first secret
            secret_1 (str): The second secret
        """
        self.secret_0 = secret_0
        self.secret_1 = secret_1
        self.pke = PublicKeyEncryption()  # Our encryption engine

    def encrypt_secrets(self, pk0, pk1):
        """
        Step 2 of the OT protocol: Encrypt both secrets with the received keys.

        The sender receives two public keys but doesn't know which one
        corresponds to a private key that the receiver actually possesses.
        So they encrypt both secrets and send both back.

        Args:
            pk0: Public key for encrypting secret 0
            pk1: Public key for encrypting secret 1

        Returns:
            tuple: (e0, e1) - the two encrypted secrets
        """
        print("📥 Sender: Received two public keys from receiver")
        print(f"🔒 Sender: Encrypting secret 0 = '{self.secret_0}'")
        print(f"🔒 Sender: Encrypting secret 1 = '{self.secret_1}'")

        # Encrypt each secret with its corresponding public key
        e0 = self.pke.encrypt(self.secret_0, pk0)
        e1 = self.pke.encrypt(self.secret_1, pk1)

        print("📤 Sender: Sending both encrypted secrets to receiver")
        print("🤷 Sender: I don't know which one they can decrypt!")

        return e0, e1


def demonstrate_oblivious_transfer():
    """
    Run a complete demonstration of the oblivious transfer protocol.

    This function shows how the two parties interact and highlights
    the security properties of the protocol.
    """
    print("=" * 80)
    print("🎭 OBLIVIOUS TRANSFER PROTOCOL DEMONSTRATION")
    print("=" * 80)

    # Set up the scenario
    secret_0 = "The vault combination is 15-23-42"
    secret_1 = "The treasure map is hidden behind the painting"
    receiver_choice = 1  # Receiver secretly wants secret 1

    print("\n📋 SCENARIO SETUP:")
    print("   📊 Sender has two secrets:")
    print(f"      x_0 = '{secret_0}'")
    print(f"      x_1 = '{secret_1}'")
    print(f"   🎯 Receiver secretly wants x_{receiver_choice}")
    print(
        f"   🔒 Goal: Receiver learns x_{receiver_choice}, Sender learns nothing about choice"
    )

    # Create the participants
    receiver = OTReceiver(selection_bit=receiver_choice)
    sender = OTSender(secret_0, secret_1)

    print("\n📍 STEP 1: Receiver prepares key arrangement")
    print("-" * 40)
    pk0, pk1 = receiver.prepare_key_pairs()

    print("\n📍 STEP 2: Sender encrypts both secrets")
    print("-" * 40)
    e0, e1 = sender.encrypt_secrets(pk0, pk1)

    print("\n📍 STEP 3: Receiver decrypts chosen secret")
    print("-" * 40)
    received_secret = receiver.decrypt_chosen_secret(e0, e1)

    # Verify the result
    expected_secret = secret_1 if receiver_choice == 1 else secret_0
    success = received_secret == expected_secret

    print("\n🎉 PROTOCOL RESULT:")
    print(f"   ✅ Success: {success}")
    print(f"   📩 Receiver got: '{received_secret}'")
    print(f"   🎯 Expected: '{expected_secret}'")

    print("\n🔒 SECURITY ANALYSIS:")
    print(
        f"   🔐 Receiver Privacy: Sender doesn't know receiver chose x_{receiver_choice}"
    )
    print(
        f"   🛡️  Sender Privacy: Receiver only learned x_{receiver_choice}, not both secrets"
    )
    print("   ✅ Correctness: Receiver got exactly what they wanted")


def test_both_choices():
    """
    Test the protocol with both possible receiver choices to verify correctness.

    This is important for demonstrating that our protocol works regardless
    of which secret the receiver chooses.
    """
    print("\n" + "=" * 80)
    print("🧪 TESTING BOTH RECEIVER CHOICES")
    print("=" * 80)

    test_secrets = [
        "Alice's phone number: 555-ALICE",
        "Bob's email: bob@secretcorp.com",
    ]

    for choice in [0, 1]:
        print(f"\n🔬 Test Case: Receiver chooses x_{choice}")
        print("-" * 50)

        # Create fresh participants for this test
        receiver = OTReceiver(selection_bit=choice)
        sender = OTSender(test_secrets[0], test_secrets[1])

        # Run the protocol
        pk0, pk1 = receiver.prepare_key_pairs()
        e0, e1 = sender.encrypt_secrets(pk0, pk1)
        result = receiver.decrypt_chosen_secret(e0, e1)

        # Verify correctness
        expected = test_secrets[choice]
        print(f"📊 Expected: '{expected}'")
        print(f"📋 Received: '{result}'")
        print(f"✅ Correct: {result == expected}")


if __name__ == "__main__":
    demonstrate_oblivious_transfer()
    test_both_choices()
