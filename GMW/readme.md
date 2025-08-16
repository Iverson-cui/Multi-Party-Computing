# GMW Protocol Implementation

A complete implementation of the **Goldreich-Micali-Wigderson (GMW) Protocol** for secure two-party computation of Boolean circuits. This implementation enables two parties to jointly compute a function over their private inputs without revealing anything beyond the output.


## Key Features

This implementation can support circuit with AND, XOR and NOT gates. XOR and NOT gates are evaluated locally for both parties. AND gates need to go through 1-out-of-4 OTs.
For now, the protocol evaluates the circuit gate by gate, no parallelism is included, nor does any precomputation and extension of OT. I have heard that the AND gate within the same layer can be processed in parallel and it's a feature TBD.

## 📋 Protocol Flow

```
1. Input Sharing    → Both parties share their inputs using XOR secret sharing
2. Gate Evaluation  → Evaluate circuit gates in topological order:
   - XOR gates: Local computation (no communication)
   - NOT gates: One party flips share (no communication)  
   - AND gates: 1-out-of-4 Oblivious Transfer
3. Output Reconstruction → Parties combine shares to reveal final result
```

## 🏗️ Architecture

### Core Components

| Module                  | Description                                                      |
| ----------------------- | ---------------------------------------------------------------- |
| `gmw_protocol.py`       | Main protocol implementation with Party1 and Party2 classes      |
| `gmw_circuit.py`        | Boolean circuit representation (gates, wires, circuit structure) |
| `gmw_shares.py`         | XOR secret sharing implementation and share management           |
| `oblivious_transfer.py` | 1-out-of-4 OT implementation (located in ../GC/)                 |

### Class Hierarchy

```
GMWProtocol
├── GMWParty1 (Initiator)
├── GMWParty2 (Responder)  
├── GMWCircuit (Circuit representation)
│   ├── GMWWire (Circuit wires)
│   └── GMWGate (AND/XOR/NOT gates)
└── GMWShareManager (Secret share management)
```

## 🧮 Cryptographic Primitives

### XOR Secret Sharing
```python
# Share a secret bit s as (s1, s2) where s = s1 ⊕ s2
share1, share2 = XORSecretSharing.share_secret(secret_bit)
reconstructed = share1 ^ share2  # equals original secret_bit
```

### AND Gate Evaluation
The most complex operation requiring secure computation:

1. **Party 2** (sender) chooses random output share `z2`
2. **Party 2** provides 4 OT values such that **Party 1** obtains:
   ```
   z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2))
   ```
3. Result: `z1 ⊕ z2 = (x1 ⊕ x2) ∧ (y1 ⊕ y2)` (correct AND of shared inputs)

### Gate Types
- **XOR Gates**: `output = input1 ⊕ input2` (local evaluation)
- **AND Gates**: `output = input1 ∧ input2` (requires OT)
- **NOT Gates**: `output = ¬input` (Party 1 flips share)

## 🚀 Usage Examples

### Basic Protocol Execution

```python
from gmw_protocol import GMWProtocol, create_complex_boolean_circuit
from gmw_circuit import GMWWire

# Create a circuit
circuit = create_complex_boolean_circuit()

# Define private inputs for each party
party1_inputs = {
    GMWWire("party1_a"): True,
    GMWWire("party1_b"): False,
}

party2_inputs = {
    GMWWire("party2_c"): True,
    GMWWire("party2_d"): False,
}

# Execute the protocol
protocol = GMWProtocol(circuit)
result = protocol.execute_protocol(party1_inputs, party2_inputs)

# Get the output
output = result[GMWWire("output")]
print(f"Secure computation result: {output}")
```

### Available Test Circuits

#### 1. Complex Boolean Circuit
Computes: `f(a,b,c,d) = (NOT(a) AND b) XOR (c AND NOT(d))`

```python
# Uses all three gate types (AND, XOR, NOT)
circuit = create_complex_boolean_circuit()
```

#### 2. Full Adder Circuit  
Computes: 1-bit binary addition with carry

```python
# Inputs: a, b, carry_in
# Outputs: sum, carry_out
circuit = create_full_adder_circuit()
```

## 🧪 Running Tests

Execute the test suite to verify protocol correctness:

```bash
cd GMW/
python gmw_protocol.py
```

This runs comprehensive tests on both representative circuits, testing various input combinations and verifying the mathematical correctness of the secure computation.

## 🔧 Dependencies

- **Python 3.7+**: Core implementation language
- **cryptography**: RSA operations for Oblivious Transfer
- **secrets**: Cryptographically secure random number generation

### External Dependencies
- `../GC/oblivious_transfer.py`: 1-out-of-4 Oblivious Transfer implementation
- `../GC/public_key_encryption.py`: RSA encryption for OT protocol

---

*This implementation is designed for educational purposes and demonstrates the core concepts of the GMW protocol in secure multi-party computation.*
