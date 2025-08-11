# Yao's Garbled Circuit Implementation

A complete implementation of Andrew Yao's Garbled Circuit protocol for secure two-party computation, demonstrating how two parties can jointly compute a function over their private inputs without revealing those inputs to each other.

## Overview

This project implements the foundational protocol for secure multi-party computation (MPC), allowing Alice (Sender) and Bob (Receiver) to compute functions like `f(alice_input, bob_input) = output` where:
- Alice learns nothing about Bob's input
- Bob learns nothing about Alice's input  
- Both parties learn the final result
- The computation is performed on encrypted data

## File Structure

### Core Implementation Files

#### [`yao_garbled_circuit.py`](yao_garbled_circuit.py)
The main implementation file containing:

- **Circuit Representation**: [`Circuit`](yao_garbled_circuit.py), [`Gate`](yao_garbled_circuit.py), [`Wire`](yao_garbled_circuit.py) classes for defining Boolean circuits
- **Garbled Circuit Structures**: [`GarbledCircuit`](yao_garbled_circuit.py), [`GarbledGate`](yao_garbled_circuit.py), [`GarbledWire`](yao_garbled_circuit.py) for the encrypted versions
- **Protocol Parties**: 
  - [`Sender`](yao_garbled_circuit.py) class (Alice) - garbles circuits and provides input labels
  - [`Receiver`](yao_garbled_circuit.py) class (Bob) - evaluates garbled circuits
- **Cryptographic Utilities**: [`CryptoUtils`](yao_garbled_circuit.py) class with encryption/decryption functions
- **Example Circuits**: 
  - [`create_and_circuit()`](yao_garbled_circuit.py) - Simple AND gate
  - [`create_comparison_circuit()`](yao_garbled_circuit.py) - 2-bit number comparison
  - [`create_8bit_multiplication_circuit()`](yao_garbled_circuit.py) - a more complex circuit

#### [`oblivious_transfer.py`](oblivious_transfer.py)
Implements the 1-out-of-2 Oblivious Transfer protocol. This public key version is implemented with the help of public_key_encryption.py file below. You can also just use some implementations in the lib, which are on-the-shelf. To further enhance my understanding I just implement it with my hands. Details below:

- **[`OTReceiver`](oblivious_transfer.py)**: Manages the receiver's side of OT
  - [`prepare_key_pairs()`](oblivious_transfer.py) - Creates real and dummy public keys
  - [`decrypt_chosen_secret()`](oblivious_transfer.py) - Decrypts the chosen secret
- **[`OTSender`](oblivious_transfer.py)**: Manages the sender's side of OT
  - [`encrypt_secrets()`](oblivious_transfer.py) - Encrypts both secrets with provided keys

#### [`public_key_encryption.py`](public_key_encryption.py)
RSA public key cryptography wrapper:

- **[`PublicKeyEncryption`](public_key_encryption.py)**: Clean interface for RSA operations
  - [`generate_keypair()`](public_key_encryption.py) - Creates RSA key pairs
  - [`encrypt()`](public_key_encryption.py) / [`decrypt()`](public_key_encryption.py) - RSA encryption with OAEP padding
  - [`create_dummy_public_key()`](public_key_encryption.py) - Creates decoy keys for OT
  - Key serialization functions for PEM format

### Configuration Files

- **[`.gitignore`](.gitignore)**: Excludes sensitive key files (`*.pem`) and Python cache
- **`private_key.pem`** / **`public_key.pem`**: RSA key pair files (ignored by git for security)

## How the Components Connect

```
┌─────────────────────────────────────────────────────────────┐
│                    YAOGARBLED CIRCUIT PROTOCOL              │
├─────────────────────────────────────────────────────────────┤
│  1. Circuit Definition (yao_garbled_circuit.py)             │
│     ├── Circuit, Gate, Wire classes                         │
│     └── Example circuits (AND, comparison, multiplication)  │
│                                                             │
│  2. Circuit Garbling (Sender class)                         │
│     ├── Generate random labels for each wire                │
│     ├── Encrypt gate truth tables                           │
│     └── Create output decoding information                  │
│                                                             │
│  3. Input Label Transfer                                    │
│     ├── Alice's inputs: Direct transfer                     │
│     └── Bob's inputs: Via Oblivious Transfer ───────────────┼─┐
│                                                             │ │
│  4. Circuit Evaluation (Receiver class)                     │ │
│     ├── Decrypt garbled gates using input labels            │ │
│     ├── Propagate labels through circuit                    │ │
│     └── Decode final output                                 │ │
└─────────────────────────────────────────────────────────────┘ │
                                                                │
┌─────────────────────────────────────────────────────────────┐ │
│                OBLIVIOUS TRANSFER PROTOCOL                  │ │
├─────────────────────────────────────────────────────────────┤ │
│  (oblivious_transfer.py)                                    │◄┘
│                                                             │
│  1. Receiver prepares key arrangement                       │
│     ├── Generate real key pair                              │
│     ├── Generate dummy public key                           │
│     └── Arrange keys based on secret choice bit             │
│                                                             │
│  2. Sender encrypts both secrets                            │
│     └── Uses both public keys to encrypt                    │
│                                                             │
│  3. Receiver decrypts chosen secret                         │
│     └── Can only decrypt one (corresponding to choice)      │
└─────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌─────────────────────────────────────────────────────────────┐
│              RSA PUBLIC KEY ENCRYPTION                      │
├─────────────────────────────────────────────────────────────┤
│  (public_key_encryption.py)                                 │
│                                                             │
│  • RSA key generation and management                        │
│  • OAEP padding for semantic security                       │
│  • PEM serialization for key storage                        │
│  • Clean interface hiding crypto library complexity         │
└─────────────────────────────────────────────────────────────┘
```

## Protocol Flow

1. **Setup**: Alice creates a [`Circuit`](yao_garbled_circuit.py) representing the desired computation
2. **Garbling**: Alice ([`Sender`](yao_garbled_circuit.py)) creates a [`GarbledCircuit`](yao_garbled_circuit.py) with encrypted truth tables
3. **Circuit Transfer**: Alice sends the garbled circuit to Bob ([`Receiver`](yao_garbled_circuit.py))
4. **Input Label Transfer**:
   - Alice's inputs: Direct transfer of corresponding labels
   - Bob's inputs: Secure transfer via [`ObliviousTransfer`](oblivious_transfer.py)
5. **Evaluation**: Bob evaluates the garbled circuit using only the labels
6. **Output**: Bob decodes the final result and shares it with Alice

## Usage Examples

### Running the Demonstration

```python
python yao_garbled_circuit.py
```

This runs three examples:
1. Simple AND circuit (2 inputs → 1 output)
2. 2-bit number comparison (4 inputs → 1 output)  
3. 8-bit multiplication (8 inputs → 8 outputs)
4. 8-bit comparison

### Creating Custom Circuits

The circuit consists of multiple gates and wires. Circuit structures are implemented by specifying the input and output wires for each gate. Make sure to connect every wire and gate correctly.
```python
from yao_garbled_circuit import Circuit, Gate, Wire, GateType

# Define wires
input_a = Wire("input_a")
input_b = Wire("input_b") 
output = Wire("output")

# Create gate
xor_gate = Gate("xor1", GateType.XOR, [input_a, input_b], output)

# Build circuit
circuit = Circuit(
    gates=[xor_gate],
    input_wires=[input_a, input_b],
    output_wires=[output],
    alice_input_wires=[input_a],
    bob_input_wires=[input_b]
)
```

## Security Properties

- **Privacy**: Neither party learns the other's private inputs
- **Correctness**: The protocol computes the correct function result
- **Semi-honest Security**: Secure against parties who follow the protocol but try to learn extra information
- **Semantic Security**: Uses proper cryptographic primitives (RSA-OAEP, random labels)

## Dependencies

- `cryptography` library for RSA operations
- Python 3.7+ for type hints and dataclasses
- Standard library modules: `hashlib`, `secrets`, `json`, `time`

## Installation

```bash
pip install cryptography
```

## Educational Purpose

This implementation prioritizes clarity and educational value over production-level optimizations. Real-world implementations would include:
- Free-XOR optimization for XOR gates
- Network communication protocols
- Protection against malicious adversaries
- Hardware-specific optimizations

## Further implementation
- Point-and-permute optimization for garbled tables

## License
Educational implementation for cryptography coursework.