"""
Oblivious Transfer Implementation based on public key encryption

This module implements oblivious transfer protocols using
the public key encryption primitives from our separate module.

The module provides:
1. OTReceiver, OTSender: Original 1-out-of-2 oblivious transfer
2. OT4Receiver, OT4Sender: 1-out-of-4 oblivious transfer
3. GeneralOTReceiver, GeneralOTSender: Generalized 1-out-of-n oblivious transfer

The generalized classes (GeneralOTReceiver, GeneralOTSender) are the recommended
approach as they can handle any number of secrets n >= 2. The original classes
are kept for backward compatibility and educational purposes.

Usage:
    # For any number of secrets (recommended)
    receiver = GeneralOTReceiver(selection_index=2, num_secrets=5)
    sender = GeneralOTSender(["secret0", "secret1", "secret2", "secret3", "secret4"])

    # For exactly 2 secrets (legacy)
    receiver = OTReceiver(selection_bit=1)
    sender = OTSender("secret0", "secret1")

The beauty of this design is that we could swap out different encryption
schemes (like elliptic curve cryptography) just by changing the import,
as long as they provide the same interface.
"""

# Generalized 1-out-of-n OT implemented below.
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
        # create_dummy_public_key is actually doing the same thing like generate_keypair except that the secret key is discarded.
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


class OT4Receiver:
    """
    The Receiver in a 1-out-of-4 Oblivious Transfer protocol.

    The receiver has a secret choice (0, 1, 2, or 3) and wants to learn exactly one
    of the sender's four secrets without revealing which one they chose.
    """

    def __init__(self, selection_index):
        """
        Initialize the receiver with their secret choice.

        Args:
            selection_index (int): 0, 1, 2, or 3, indicating which secret they want
        """
        if selection_index not in [0, 1, 2, 3]:
            raise ValueError("Selection index must be 0, 1, 2, or 3")

        self.selection_index = selection_index
        self.pke = PublicKeyEncryption()  # Our encryption engine
        self.private_key = None  # Will store the real private key
        self.public_key = None  # Will store the real public key

    def prepare_key_pairs(self):
        """
        Step 1 of the 1-out-of-4 OT protocol: Prepare the key arrangement.

        We create one real key pair and three dummy public keys, then arrange them
        based on our selection index. The sender will see four legitimate-looking
        public keys but won't know which one we can actually use.

        Returns:
            tuple: (pk0, pk1, pk2, pk3) - the four public keys to send to the sender
        """
        print(f"🔐 Receiver: I secretly want x_{self.selection_index}")

        # Generate our real key pair - this is the only private key we'll keep
        self.private_key, self.public_key = self.pke.generate_keypair()
        print("🔑 Receiver: Generated real key pair")

        # Create three dummy public keys (we throw away their private keys)
        dummy_public_keys = []
        for i in range(3):
            dummy_key = self.pke.create_dummy_public_key()
            dummy_public_keys.append(dummy_key)
        print("🎭 Receiver: Generated 3 dummy public keys")

        # Arrange the keys: put our real key in the position corresponding to our choice
        keys = [None, None, None, None]
        keys[self.selection_index] = self.public_key

        # Fill the remaining positions with dummy keys
        dummy_index = 0
        for i in range(4):
            if keys[i] is None:
                keys[i] = dummy_public_keys[dummy_index]
                dummy_index += 1

        print(f"📍 Receiver: Real key placed in position {self.selection_index}")
        print("📤 Receiver: Sending 4 public keys to sender")

        return tuple(keys)

    def decrypt_chosen_secret(self, e0, e1, e2, e3):
        """
        Step 3 of the 1-out-of-4 OT protocol: Decrypt the ciphertext we can actually decrypt.

        We'll receive four encrypted secrets but can only decrypt one of them
        (the one encrypted with our real public key).

        Args:
            e0 (bytes): Encryption of secret 0
            e1 (bytes): Encryption of secret 1
            e2 (bytes): Encryption of secret 2
            e3 (bytes): Encryption of secret 3

        Returns:
            str: The secret we chose to receive
        """
        print("📥 Receiver: Received 4 encrypted secrets from sender")
        print("🔓 Receiver: Attempting to decrypt...")

        encrypted_secrets = [e0, e1, e2, e3]
        decryption_results = {}

        # Attempt to decrypt all four secrets
        for i, encrypted_secret in enumerate(encrypted_secrets):
            try:
                secret = self.pke.decrypt(encrypted_secret, self.private_key)
                decryption_results[i] = secret
                print(f"✅ Successfully decrypted secret {i}: '{secret}'")
            except ValueError:
                decryption_results[i] = None
                print(
                    f"❌ Cannot decrypt secret {i} (expected if we didn't choose {i})"
                )

        # Return the secret we actually wanted
        chosen_secret = decryption_results[self.selection_index]
        if chosen_secret is None:
            raise RuntimeError("Failed to decrypt the chosen secret! Protocol error.")

        print(f"🎯 Receiver: Successfully obtained chosen secret: '{chosen_secret}'")
        return chosen_secret


class OT4Sender:
    """
    The Sender in a 1-out-of-4 Oblivious Transfer protocol.

    The sender has four secrets and is willing to let the receiver learn
    exactly one of them, but doesn't want to know which one the receiver chose.
    """

    def __init__(self, secret_0, secret_1, secret_2, secret_3):
        """
        Initialize the sender with their four secrets.

        Args:
            secret_0 (str): The first secret
            secret_1 (str): The second secret
            secret_2 (str): The third secret
            secret_3 (str): The fourth secret
        """
        self.secrets = [secret_0, secret_1, secret_2, secret_3]
        self.pke = PublicKeyEncryption()  # Our encryption engine

    def encrypt_secrets(self, pk0, pk1, pk2, pk3):
        """
        Step 2 of the 1-out-of-4 OT protocol: Encrypt all four secrets with the received keys.

        The sender receives four public keys but doesn't know which one
        corresponds to a private key that the receiver actually possesses.
        So they encrypt all four secrets and send them all back.

        Args:
            pk0: Public key for encrypting secret 0
            pk1: Public key for encrypting secret 1
            pk2: Public key for encrypting secret 2
            pk3: Public key for encrypting secret 3

        Returns:
            tuple: (e0, e1, e2, e3) - the four encrypted secrets
        """
        print("📥 Sender: Received 4 public keys from receiver")

        public_keys = [pk0, pk1, pk2, pk3]
        encrypted_secrets = []

        for i, (secret, pk) in enumerate(zip(self.secrets, public_keys)):
            print(f"🔒 Sender: Encrypting secret {i} = '{secret}'")
            encrypted_secret = self.pke.encrypt(secret, pk)
            encrypted_secrets.append(encrypted_secret)

        print("📤 Sender: Sending all 4 encrypted secrets to receiver")
        print("🤷 Sender: I don't know which one they can decrypt!")

        return tuple(encrypted_secrets)


def demonstrate_1_out_of_4_oblivious_transfer():
    """
    Run a complete demonstration of the 1-out-of-4 oblivious transfer protocol.

    This function shows how the two parties interact and highlights
    the security properties of the protocol.
    """
    print("=" * 80)
    print("🎭 1-OUT-OF-4 OBLIVIOUS TRANSFER PROTOCOL DEMONSTRATION")
    print("=" * 80)

    # Set up the scenario
    secrets = [
        "Database password: super_secret_123",
        "Server location: building-7-room-42",
        "Encryption key: AES256-7F9A2E4D8B",
        "Admin phone: +1-555-ADMIN-01",
    ]
    receiver_choice = 2  # Receiver secretly wants secret 2

    print("\n📋 SCENARIO SETUP:")
    print("   📊 Sender has four secrets:")
    for i, secret in enumerate(secrets):
        print(f"      x_{i} = '{secret}'")
    print(f"   🎯 Receiver secretly wants x_{receiver_choice}")
    print(
        f"   🔒 Goal: Receiver learns x_{receiver_choice}, Sender learns nothing about choice"
    )

    # Create the participants
    receiver = OT4Receiver(selection_index=receiver_choice)
    sender = OT4Sender(*secrets)

    print("\n📍 STEP 1: Receiver prepares key arrangement")
    print("-" * 40)
    pk0, pk1, pk2, pk3 = receiver.prepare_key_pairs()

    print("\n📍 STEP 2: Sender encrypts all four secrets")
    print("-" * 40)
    e0, e1, e2, e3 = sender.encrypt_secrets(pk0, pk1, pk2, pk3)

    print("\n📍 STEP 3: Receiver decrypts chosen secret")
    print("-" * 40)
    received_secret = receiver.decrypt_chosen_secret(e0, e1, e2, e3)

    # Verify the result
    expected_secret = secrets[receiver_choice]
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
        f"   🛡️  Sender Privacy: Receiver only learned x_{receiver_choice}, not the other 3 secrets"
    )
    print("   ✅ Correctness: Receiver got exactly what they wanted")


def test_all_1_out_of_4_choices():
    """
    Test the 1-out-of-4 protocol with all possible receiver choices to verify correctness.

    This demonstrates that our protocol works regardless of which secret the receiver chooses.
    """
    print("\n" + "=" * 80)
    print("🧪 TESTING ALL 1-OUT-OF-4 RECEIVER CHOICES")
    print("=" * 80)

    test_secrets = [
        "Secret Alpha: Project Moonbeam classified",
        "Secret Beta: Launch codes 7-7-4-9-2",
        "Secret Gamma: Safe combination L32-R18-L7",
        "Secret Delta: Emergency contact +1-800-HELP",
    ]

    for choice in [0, 1, 2, 3]:
        print(f"\n🔬 Test Case: Receiver chooses x_{choice}")
        print("-" * 50)

        # Create fresh participants for this test
        receiver = OT4Receiver(selection_index=choice)
        sender = OT4Sender(*test_secrets)

        # Run the protocol
        pk0, pk1, pk2, pk3 = receiver.prepare_key_pairs()
        e0, e1, e2, e3 = sender.encrypt_secrets(pk0, pk1, pk2, pk3)
        result = receiver.decrypt_chosen_secret(e0, e1, e2, e3)

        # Verify correctness
        expected = test_secrets[choice]
        print(f"📊 Expected: '{expected}'")
        print(f"📋 Received: '{result}'")
        print(f"✅ Correct: {result == expected}")


# Aside from 1-out-of-2 and 4, we have more general version
# where you can choose how many secrets to transfer
# But we keep the 2OT and 4OT for compatibility.


class GeneralOTReceiver:
    """
    Generalized Receiver for 1-out-of-n Oblivious Transfer protocol.

    The receiver has a secret choice index and wants to learn exactly one
    of the sender's n secrets without revealing which one they chose.
    """

    def __init__(self, selection_index, num_secrets):
        """
        Initialize the receiver with their secret choice.

        Args:
            selection_index (int): Index (0 to num_secrets-1) of the secret they want
            num_secrets (int): Total number of secrets the sender has
        """
        if not isinstance(num_secrets, int) or num_secrets < 2:
            raise ValueError("Number of secrets must be an integer >= 2")
        if not isinstance(selection_index, int) or not (
            0 <= selection_index < num_secrets
        ):
            raise ValueError(f"Selection index must be between 0 and {num_secrets-1}")

        self.selection_index = selection_index
        self.num_secrets = num_secrets
        self.pke = PublicKeyEncryption()  # Our encryption engine
        self.private_key = None  # Will store the real private key
        self.public_key = None  # Will store the real public key

    def prepare_key_pairs(self):
        """
        Step 1 of the 1-out-of-n OT protocol: Prepare the key arrangement.

        We create one real key pair and (n-1) dummy public keys, then arrange them
        based on our selection index. The sender will see n legitimate-looking
        public keys but won't know which one we can actually use.

        Returns:
            list: List of n public keys to send to the sender
        """
        print(
            f"🔐 Receiver: I secretly want x_{self.selection_index} (out of {self.num_secrets} secrets)"
        )

        # Generate our real key pair - this is the only private key we'll keep
        self.private_key, self.public_key = self.pke.generate_keypair()
        print("🔑 Receiver: Generated real key pair")

        # Create (n-1) dummy public keys (we throw away their private keys)
        dummy_public_keys = []
        for i in range(self.num_secrets - 1):
            dummy_key = self.pke.create_dummy_public_key()
            dummy_public_keys.append(dummy_key)
        print(f"🎭 Receiver: Generated {self.num_secrets - 1} dummy public keys")

        # Arrange the keys: put our real key in the position corresponding to our choice
        keys = []
        for i in range(self.num_secrets):
            if i == self.selection_index:
                keys.append(self.public_key)
            else:
                keys.append(None)

        # Fill the remaining positions with dummy keys
        dummy_index = 0
        for i in range(self.num_secrets):
            if keys[i] is None:
                keys[i] = dummy_public_keys[dummy_index]
                dummy_index += 1

        print(f"📍 Receiver: Real key placed in position {self.selection_index}")
        print(f"📤 Receiver: Sending {self.num_secrets} public keys to sender")

        return keys

    def decrypt_chosen_secret(self, encrypted_secrets):
        """
        Step 3 of the 1-out-of-n OT protocol: Decrypt the ciphertext we can actually decrypt.

        We'll receive n encrypted secrets but can only decrypt one of them
        (the one encrypted with our real public key).

        Args:
            encrypted_secrets (list): List of n encrypted secrets

        Returns:
            str: The secret we chose to receive
        """
        if len(encrypted_secrets) != self.num_secrets:
            raise ValueError(
                f"Expected {self.num_secrets} encrypted secrets, got {len(encrypted_secrets)}"
            )

        print(f"📥 Receiver: Received {self.num_secrets} encrypted secrets from sender")
        print("🔓 Receiver: Attempting to decrypt...")

        decryption_results = {}

        # Attempt to decrypt all secrets
        for i, encrypted_secret in enumerate(encrypted_secrets):
            try:
                secret = self.pke.decrypt(encrypted_secret, self.private_key)
                decryption_results[i] = secret
                print(f"✅ Successfully decrypted secret {i}: '{secret}'")
            except ValueError:
                decryption_results[i] = None
                print(
                    f"❌ Cannot decrypt secret {i} (expected if we didn't choose {i})"
                )

        # Return the secret we actually wanted
        chosen_secret = decryption_results[self.selection_index]
        if chosen_secret is None:
            raise RuntimeError("Failed to decrypt the chosen secret! Protocol error.")

        print(f"🎯 Receiver: Successfully obtained chosen secret: '{chosen_secret}'")
        return chosen_secret


class GeneralOTSender:
    """
    Generalized Sender for 1-out-of-n Oblivious Transfer protocol.

    The sender has n secrets and is willing to let the receiver learn
    exactly one of them, but doesn't want to know which one the receiver chose.
    """

    def __init__(self, secrets):
        """
        Initialize the sender with their secrets.

        Args:
            secrets (list): List of secrets (strings)
        """
        if not isinstance(secrets, (list, tuple)):
            raise ValueError("Secrets must be provided as a list or tuple")
        if len(secrets) < 2:
            raise ValueError("Must have at least 2 secrets")

        self.secrets = list(secrets)
        self.num_secrets = len(self.secrets)
        self.pke = PublicKeyEncryption()  # Our encryption engine

    def encrypt_secrets(self, public_keys):
        """
        Step 2 of the 1-out-of-n OT protocol: Encrypt all secrets with the received keys.

        The sender receives n public keys but doesn't know which one
        corresponds to a private key that the receiver actually possesses.
        So they encrypt all secrets and send them all back.

        Args:
            public_keys (list): List of n public keys

        Returns:
            list: List of n encrypted secrets
        """
        # Receiver must give right number of secrets.
        if len(public_keys) != self.num_secrets:
            raise ValueError(
                f"Expected {self.num_secrets} public keys, got {len(public_keys)}"
            )

        print(f"📥 Sender: Received {self.num_secrets} public keys from receiver")

        encrypted_secrets = []
        for i, (secret, pk) in enumerate(zip(self.secrets, public_keys)):
            print(f"🔒 Sender: Encrypting secret {i} = '{secret}'")
            encrypted_secret = self.pke.encrypt(secret, pk)
            encrypted_secrets.append(encrypted_secret)

        print(
            f"📤 Sender: Sending all {self.num_secrets} encrypted secrets to receiver"
        )
        print("🤷 Sender: I don't know which one they can decrypt!")

        return encrypted_secrets


def demonstrate_general_oblivious_transfer(num_secrets=3, receiver_choice=1):
    """
    Run a complete demonstration of the generalized oblivious transfer protocol.

    Args:
        num_secrets (int): Number of secrets (default 3)
        receiver_choice (int): Which secret the receiver wants (default 1)
    """
    print("=" * 80)
    print(
        f"🎭 GENERALIZED 1-OUT-OF-{num_secrets} OBLIVIOUS TRANSFER PROTOCOL DEMONSTRATION"
    )
    print("=" * 80)

    # Generate secrets dynamically
    secret_templates = [
        "Database password: secret_{}_db",
        "Server location: building-{}-room-42",
        "Encryption key: AES256-KEY{:02d}",
        "Admin contact: +1-555-{:04d}",
        "API token: TOKEN_{}_SECURE",
        "Backup location: /vault/{}/backup",
        "License key: LIC-{:03d}-PROD",
        "Emergency code: EMRG-{:02d}-ALPHA",
    ]

    secrets = []
    for i in range(num_secrets):
        template = secret_templates[i % len(secret_templates)]
        secret = template.format(i + 1)
        secrets.append(secret)

    print("\n📋 SCENARIO SETUP:")
    print(f"   📊 Sender has {num_secrets} secrets:")
    for i, secret in enumerate(secrets):
        print(f"      x_{i} = '{secret}'")
    print(f"   🎯 Receiver secretly wants x_{receiver_choice}")
    print(
        f"   🔒 Goal: Receiver learns x_{receiver_choice}, Sender learns nothing about choice"
    )

    # Create the participants
    receiver = GeneralOTReceiver(
        selection_index=receiver_choice, num_secrets=num_secrets
    )
    sender = GeneralOTSender(secrets)

    print("\n📍 STEP 1: Receiver prepares key arrangement")
    print("-" * 40)
    public_keys = receiver.prepare_key_pairs()

    print("\n📍 STEP 2: Sender encrypts all secrets")
    print("-" * 40)
    encrypted_secrets = sender.encrypt_secrets(public_keys)

    print("\n📍 STEP 3: Receiver decrypts chosen secret")
    print("-" * 40)
    received_secret = receiver.decrypt_chosen_secret(encrypted_secrets)

    # Verify the result
    expected_secret = secrets[receiver_choice]
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
        f"   🛡️  Sender Privacy: Receiver only learned x_{receiver_choice}, not the other {num_secrets-1} secrets"
    )
    print("   ✅ Correctness: Receiver got exactly what they wanted")


def test_general_ot_multiple_configurations():
    """
    Test the generalized protocol with various configurations to verify correctness.
    """
    print("\n" + "=" * 80)
    print("🧪 TESTING GENERALIZED OT WITH MULTIPLE CONFIGURATIONS")
    print("=" * 80)

    # Test different numbers of secrets
    configurations = [
        (2, [0, 1]),  # 1-out-of-2 (like original)
        (3, [0, 1, 2]),  # 1-out-of-3
        (4, [0, 1, 2, 3]),  # 1-out-of-4 (like extended version)
        (5, [0, 2, 4]),  # 1-out-of-5 (test subset of choices)
        (8, [0, 3, 7]),  # 1-out-of-8 (larger test)
    ]

    for num_secrets, test_choices in configurations:
        print(f"\n🔬 Configuration: 1-out-of-{num_secrets}")
        print("-" * 60)

        # Generate test secrets
        test_secrets = [
            f"Secret-{i:02d}: Data_{chr(65+i)}_classified" for i in range(num_secrets)
        ]

        for choice in test_choices:
            print(f"\n  📝 Test: Receiver chooses x_{choice}")

            # Create fresh participants for this test
            receiver = GeneralOTReceiver(
                selection_index=choice, num_secrets=num_secrets
            )
            sender = GeneralOTSender(test_secrets)

            # Run the protocol
            public_keys = receiver.prepare_key_pairs()
            encrypted_secrets = sender.encrypt_secrets(public_keys)
            result = receiver.decrypt_chosen_secret(encrypted_secrets)

            # Verify correctness
            expected = test_secrets[choice]
            success = result == expected
            print(f"     📊 Expected: '{expected}'")
            print(f"     📋 Received: '{result}'")
            print(f"     ✅ Correct: {success}")

            if not success:
                print(
                    f"     ❌ ERROR: Test failed for {num_secrets} secrets, choice {choice}"
                )


# Update the main section to include generalized demonstrations
if __name__ == "__main__":
    # Original 1-out-of-2 demonstrations
    demonstrate_oblivious_transfer()
    test_both_choices()

    # Original 1-out-of-4 demonstrations
    demonstrate_1_out_of_4_oblivious_transfer()
    test_all_1_out_of_4_choices()

    # New generalized demonstrations
    print("\n" + "🔥" * 80)
    print("NEW GENERALIZED OBLIVIOUS TRANSFER DEMONSTRATIONS")
    print("🔥" * 80)

    # Test with 3 secrets
    demonstrate_general_oblivious_transfer(num_secrets=3, receiver_choice=1)

    # Test with 6 secrets
    demonstrate_general_oblivious_transfer(num_secrets=6, receiver_choice=4)

    # Comprehensive testing
    test_general_ot_multiple_configurations()
