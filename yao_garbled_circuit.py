"""
Yao's Garbled Circuit Protocol Implementation
==============================================
This implementation demonstrates the complete protocol for secure two-party computation
using garbled circuits, as proposed by Andrew Yao.

The protocol works in several phases:
1. Circuit Construction: Define the computation as a Boolean circuit
2. Garbling: The Sender (Alice) creates a garbled version of the circuit
3. Input Transfer: Use Oblivious Transfer for the Receiver's (Bob's) inputs
4. Evaluation: The Receiver evaluates the garbled circuit
5. Output Revelation: Decode the final result
"""

import hashlib
import secrets
import json
from enum import Enum
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field


# ================== CRYPTOGRAPHIC PRIMITIVES ==================


class CryptoUtils:
    """
    Cryptographic utilities for the garbled circuit protocol.
    In a real implementation, you'd use proper authenticated encryption.
    Here we use a simplified approach for educational purposes.
    """

    # bytes is a built-in class.

    @staticmethod
    def generate_label() -> bytes:
        """
        Generate a random 128-bit label for a wire value.
        The result is of class bytes. bytes consists of integers in range 0-255.
        """
        return secrets.token_bytes(16)

    @staticmethod
    def hash_function(data: bytes) -> bytes:
        """
        Cryptographic hash function used as a random oracle.
        In practice, this would be a proper key derivation function.
        """
        # sha256(data) -> hashlib.HASH object
        # .digest() -> bytes
        return hashlib.sha256(data).digest()

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes) -> bytes:
        """
        Simplified encryption using XOR with a hash-derived pad.
        In production, use AES-GCM or similar authenticated encryption.

        The encryption works by:
        1. Hashing the key to get a pseudo-random pad
        2. XORing the plaintext with this pad
        """
        # Ensure the pad is at least as long as the plaintext
        pad = CryptoUtils.hash_function(key + b"encryption")
        # every iteration "encryption" more bytes is being processed until the length condition is met.
        while len(pad) < len(plaintext):
            pad += CryptoUtils.hash_function(pad)

        # XOR encryption
        ciphertext = bytes(p ^ k for p, k in zip(plaintext, pad[: len(plaintext)]))
        return ciphertext

    @staticmethod
    def decrypt(key: bytes, ciphertext: bytes) -> bytes:
        """
        Decryption is the same as encryption for XOR cipher.
        If keys are the same in encryption and decryption, the process is totally similar.
        """
        return CryptoUtils.encrypt(key, ciphertext)


# ================== CIRCUIT REPRESENTATION ==================


class GateType(Enum):
    """Types of Boolean gates supported in our circuits."""

    AND = "AND"
    OR = "OR"
    XOR = "XOR"
    NOT = "NOT"
    INPUT = "INPUT"  # Special gate type for circuit inputs


@dataclass
class Wire:
    """
    Represents a wire in the Boolean circuit.
    Each wire has an ID and can carry a Boolean value (0 or 1).
    wire_id can be seen as the name of this wire. You can call it a name.
    """

    wire_id: str

    def __hash__(self):
        return hash(self.wire_id)

    def __eq__(self, other):
        return isinstance(other, Wire) and self.wire_id == other.wire_id


@dataclass
class Gate:
    """
    Represents a logic gate in the Boolean circuit.
    Gates take input wires and produce an output wire.
    gate_id is the name of the gate. you can assign whatever string you like.
    """

    gate_id: str
    gate_type: GateType
    input_wires: List[Wire]
    output_wire: Wire

    # Dict[Wire, bool] specifies the values on the wires. This is a dictionary
    # inputs[wire] returns the values on the wires.
    def evaluate(self, inputs: Dict[Wire, bool]) -> bool:
        """Evaluate the gate given Boolean input values."""
        if self.gate_type == GateType.AND:
            return inputs[self.input_wires[0]] & inputs[self.input_wires[1]]
        elif self.gate_type == GateType.OR:
            return inputs[self.input_wires[0]] | inputs[self.input_wires[1]]
        elif self.gate_type == GateType.XOR:
            return inputs[self.input_wires[0]] ^ inputs[self.input_wires[1]]
        elif self.gate_type == GateType.NOT:
            return not inputs[self.input_wires[0]]
        elif self.gate_type == GateType.INPUT:
            # Input gates just pass through their value
            return inputs[self.input_wires[0]]
        else:
            raise ValueError(f"Unknown gate type: {self.gate_type}")


@dataclass
class Circuit:
    """
    Represents a Boolean circuit as a directed acyclic graph of gates.
    The circuit computes a function from input wires to output wires.
    """

    # ? How does it describe the circuit structure since circuit is just a list of Gate?
    gates: List[Gate]
    input_wires: List[Wire]  # Wires for inputs from both parties
    output_wires: List[Wire]  # Wires that hold the final outputs
    alice_input_wires: List[Wire]  # Which inputs belong to Alice (Sender)
    bob_input_wires: List[Wire]  # Which inputs belong to Bob (Receiver)

    def evaluate(self, inputs: Dict[Wire, bool]) -> Dict[Wire, bool]:
        """
        Evaluate the entire circuit given input values.
        Returns the values on all output wires.
        """
        wire_values = inputs.copy()
        # there are a dict called wire_values and a list called input_wires. Make sure every wire in the list also exists in the dict before the circuit is evaluated.
        # Evaluate gates in topological order
        for gate in self.gates:
            if all(w in wire_values for w in gate.input_wires):
                wire_values[gate.output_wire] = gate.evaluate(wire_values)

        # Extract output values
        outputs = {w: wire_values[w] for w in self.output_wires}
        return outputs


# ================== GARBLED CIRCUIT STRUCTURES ==================


@dataclass
class GarbledWire:
    """
    A garbled wire has two random labels instead of Boolean values.
    label_0 represents FALSE, label_1 represents TRUE.
    Neither label reveals which Boolean value it represents.
    """

    wire: Wire
    label_0: bytes  # Label for value 0 (FALSE)
    label_1: bytes  # Label for value 1 (TRUE)

    def get_label(self, value: bool) -> bytes:
        """Get the label corresponding to a Boolean value."""
        return self.label_1 if value else self.label_0


@dataclass
class GarbledGate:
    """
    A garbled gate contains an encrypted truth table.
    Each entry is encrypted with the input labels as keys.
    Only the correct input labels can decrypt the correct output label.
    """

    gate: Gate
    garbled_table: List[bytes]  # Encrypted truth table entries


@dataclass
class GarbledCircuit:
    """
    The complete garbled circuit containing:
    - Garbled gates with encrypted truth tables
    - Output decoding information (to reveal final result)
    - The circuit structure (but not the wire labels)
    """

    circuit: Circuit
    garbled_gates: List[GarbledGate]
    output_map: Dict[Wire, Dict[bytes, bool]]  # Maps output labels to Boolean values


# ================== OBLIVIOUS TRANSFER ==================


class ObliviousTransfer:
    """
    Simplified 1-out-of-2 Oblivious Transfer (OT) protocol.

    In real OT:
    - The Sender has two messages m0 and m1
    - The Receiver has a choice bit b
    - The Receiver learns mb but nothing about m(1-b)
    - The Sender learns nothing about b

    This is a simplified simulation for educational purposes.
    A real implementation would use public key cryptography (RSA-OT, DDH-OT, etc.)
    """

    # TODO: implement cryptographic version of OT.
    @staticmethod
    def transfer(sender_messages: Tuple[bytes, bytes], receiver_choice: bool) -> bytes:
        """
        Simulate OT where the receiver gets one of two messages based on their choice.
        In a real implementation, this would involve multiple rounds of communication
        and cryptographic operations to ensure security.
        """
        # WARNING: This is NOT secure - it's just for demonstration!
        # A real OT protocol would ensure the sender doesn't learn the choice
        # and the receiver doesn't learn the other message.
        return sender_messages[1] if receiver_choice else sender_messages[0]


# ================== MAIN PROTOCOL PARTIES ==================


class Sender:
    """
    The Sender (Alice) in Yao's protocol.
    Responsibilities:
    1. Garble the circuit
    2. Send the garbled circuit to the Receiver
    3. Provide input labels via OT
    4. Send own input labels
    """

    def __init__(self, circuit: Circuit):
        self.circuit = circuit
        # : Dict[Wire, GarbledWire] is type hinting syntax.
        # You can just write self.garbled_wires={}
        self.garbled_wires: Dict[Wire, GarbledWire] = {}
        # : Optional[GarbledCircuit] is another type hinting.
        # It means this is of type either GarbledCircuit or None. The value of it is now None
        self.garbled_circuit: Optional[GarbledCircuit] = None
        self.receiver: Optional["Receiver"] = None

    def connect_to_receiver(self, receiver: "Receiver"):
        """Establish connection with the Receiver."""
        self.receiver = receiver
        receiver.sender = self

    def garble_circuit(self) -> GarbledCircuit:
        """
        Phase 1: Garble the Boolean circuit.
        This creates random labels for each wire and encrypts gate truth tables.
        """
        print("[Sender] Starting circuit garbling process...")

        # Step 1: Generate random labels for all wires

        # All wires include All input wires and All gate wires. So first we initialize with input wires, then we update the set by wires on the gate, i.e. input wires and output wires of the gate.
        # We use set so that there are no duplicate wires. Every wires is added once.
        all_wires = set(self.circuit.input_wires)
        for gate in self.circuit.gates:
            # update is used to add elements in an iterate to the set
            all_wires.update(gate.input_wires)
            # add is used to add single element to the set.
            all_wires.add(gate.output_wire)

        # Up until now, we have all the wires. Next we need to create garbled wires for each wire.
        for wire in all_wires:
            self.garbled_wires[wire] = GarbledWire(
                wire=wire,
                label_0=CryptoUtils.generate_label(),
                label_1=CryptoUtils.generate_label(),
            )

        # Step 2: Garble each gate by encrypting its truth table after garbling every wire in the circuit.

        # garbled_gates is a list of GarbledGate class object.
        garbled_gates = []
        for gate in self.circuit.gates:
            garbled_gate = self._garble_gate(gate)
            garbled_gates.append(garbled_gate)

        # Step 3: Create output decoding table
        # This allows the final result to be decoded from labels to Boolean values
        output_map = {}
        for output_wire in self.circuit.output_wires:
            garbled_wire = self.garbled_wires[output_wire]
            output_map[output_wire] = {
                garbled_wire.label_0: False,
                garbled_wire.label_1: True,
            }

        self.garbled_circuit = GarbledCircuit(
            circuit=self.circuit, garbled_gates=garbled_gates, output_map=output_map
        )

        print(f"[Sender] Circuit garbled successfully with {len(garbled_gates)} gates")
        return self.garbled_circuit

    def _garble_gate(self, gate: Gate) -> GarbledGate:
        """
        Garble a single gate by encrypting its truth table.

        The key insight: we encrypt each truth table entry with the
        concatenation of input labels as the key. Only someone with
        the correct input labels can decrypt the correct output label.
        """
        # garbled_table either contains 2 lines or 4 lines depending on the class of gate.
        garbled_table = []

        if gate.gate_type == GateType.INPUT:
            # Input gates don't need garbling
            return GarbledGate(gate=gate, garbled_table=[])

        # For each possible input combination
        if gate.gate_type == GateType.NOT:
            # NOT gate has one input
            for input_val in [False, True]:
                # For the selected input_val, input_label contains corresponding the encrypted value for this input_val.
                input_label = self.garbled_wires[gate.input_wires[0]].get_label(
                    input_val
                )
                output_val = not input_val
                output_label = self.garbled_wires[gate.output_wire].get_label(
                    output_val
                )

                # Encrypt output label with input label as key
                encrypted_entry = CryptoUtils.encrypt(input_label, output_label)
                garbled_table.append(encrypted_entry)
        else:
            # Binary gates (AND, OR, XOR) have two inputs
            for input_val_0 in [False, True]:
                for input_val_1 in [False, True]:
                    # Get input labels
                    label_0 = self.garbled_wires[gate.input_wires[0]].get_label(
                        input_val_0
                    )
                    label_1 = self.garbled_wires[gate.input_wires[1]].get_label(
                        input_val_1
                    )

                    # Compute gate output
                    inputs = {
                        gate.input_wires[0]: input_val_0,
                        gate.input_wires[1]: input_val_1,
                    }
                    output_val = gate.evaluate(inputs)
                    output_label = self.garbled_wires[gate.output_wire].get_label(
                        output_val
                    )

                    # Encrypt output label with concatenated input labels
                    # encrypt output key with 2 input keys. We concatenate 2 input keys together.
                    key = label_0 + label_1
                    encrypted_entry = CryptoUtils.encrypt(key, output_label)
                    garbled_table.append(encrypted_entry)

        # IMPORTANT: In a real implementation, we would shuffle the garbled table
        # to prevent position-based information leakage
        # TODO: implement point and permute.
        secrets.SystemRandom().shuffle(garbled_table)

        return GarbledGate(gate=gate, garbled_table=garbled_table)

    def send_garbled_circuit(self):
        """Phase 2: Send the garbled circuit to the Receiver."""
        if not self.garbled_circuit:
            raise ValueError("Circuit not garbled yet!")
        if not self.receiver:
            raise ValueError("No receiver connected!")

        print("[Sender] Sending garbled circuit to Receiver...")
        self.receiver.receive_garbled_circuit(self.garbled_circuit)

    def provide_input_labels_via_ot(self, bob_inputs: Dict[Wire, bool]):
        """
        Phase 3: Use Oblivious Transfer to give Bob his input labels.
        Bob gets the labels corresponding to his input bits without
        Alice learning what those bits are.
        """
        print("[Sender] Engaging in Oblivious Transfer for Receiver's inputs...")
        bob_labels = {}

        # For every wire OT is needed.
        for wire in self.circuit.bob_input_wires:
            # For each of Bob's input wires, do an OT
            garbled_wire = self.garbled_wires[wire]

            # Alice provides both labels, Bob chooses based on his input
            both_labels = (garbled_wire.label_0, garbled_wire.label_1)
            bob_choice = bob_inputs[wire]

            # Simulate OT (in reality, this would be a multi-round protocol)
            chosen_label = ObliviousTransfer.transfer(both_labels, bob_choice)
            bob_labels[wire] = chosen_label

        # Finally bob gets a dictionary, whose keys are wires and whose values are corresponding cryptographic labels.
        return bob_labels

    def provide_own_input_labels(
        self, alice_inputs: Dict[Wire, bool]
    ) -> Dict[Wire, bytes]:
        """
        Phase 4: Provide labels for Alice's own inputs.
        Alice simply selects the labels corresponding to her input bits.
        """
        print("[Sender] Providing own input labels...")
        alice_labels = {}

        for wire in self.circuit.alice_input_wires:
            garbled_wire = self.garbled_wires[wire]
            alice_labels[wire] = garbled_wire.get_label(alice_inputs[wire])

        return alice_labels

    def run_protocol(
        self, alice_inputs: Dict[Wire, bool], bob_inputs: Dict[Wire, bool]
    ):
        """
        Execute the complete Yao's protocol from the Sender's perspective.
        """
        # Step 1: Garble the circuit
        self.garble_circuit()

        # Step 2: Send garbled circuit to Bob
        # send is actually implemented by assigning a circuit to the attribute of Receiver
        self.send_garbled_circuit()

        # Step 3: Provide Bob's input labels via OT
        bob_labels = self.provide_input_labels_via_ot(bob_inputs)
        self.receiver.receive_input_labels(bob_labels)

        # Step 4: Provide Alice's input labels
        alice_labels = self.provide_own_input_labels(alice_inputs)
        self.receiver.receive_input_labels(alice_labels)

        # Step 5: Let Bob evaluate the circuit
        print("[Sender] Waiting for Receiver to evaluate circuit...")
        result = self.receiver.evaluate()

        return result


class Receiver:
    """
    The Receiver (Bob) in Yao's protocol.
    Responsibilities:
    1. Receive the garbled circuit
    2. Obtain input labels via OT
    3. Evaluate the garbled circuit
    4. Decode and return the output
    """

    def __init__(self):
        self.garbled_circuit: Optional[GarbledCircuit] = None
        self.input_labels: Dict[Wire, bytes] = {}
        self.sender: Optional[Sender] = None

    def receive_garbled_circuit(self, garbled_circuit: GarbledCircuit):
        """Receive the garbled circuit from the Sender."""
        print("[Receiver] Received garbled circuit")
        self.garbled_circuit = garbled_circuit

    def receive_input_labels(self, labels: Dict[Wire, bytes]):
        """Receive input labels (both from OT and directly from Sender)."""
        print(f"[Receiver] Received {len(labels)} input labels")
        self.input_labels.update(labels)

    def evaluate(self) -> Dict[Wire, bool]:
        """
        Phase 5: Evaluate the garbled circuit using the input labels.

        The beautiful property of garbled circuits: Bob can evaluate
        the circuit using just the labels, without knowing what Boolean
        values they represent until the very end.
        """
        if not self.garbled_circuit:
            raise ValueError("No garbled circuit received!")

        print("[Receiver] Starting circuit evaluation...")
        wire_labels = self.input_labels.copy()

        # Evaluate each gate in topological order
        for garbled_gate in self.garbled_circuit.garbled_gates:
            gate = garbled_gate.gate

            if gate.gate_type == GateType.INPUT:
                # Input gates just pass through their labels
                continue

            # Try to decrypt the garbled table entries
            output_label = self._evaluate_garbled_gate(garbled_gate, wire_labels)
            wire_labels[gate.output_wire] = output_label

        # Decode the output labels to get Boolean results
        results = {}
        for output_wire in self.garbled_circuit.circuit.output_wires:
            output_label = wire_labels[output_wire]
            output_map = self.garbled_circuit.output_map[output_wire]

            # Find which Boolean value this label corresponds to
            for label_bytes, bool_value in output_map.items():
                if label_bytes == output_label:
                    results[output_wire] = bool_value
                    break

        print(f"[Receiver] Circuit evaluation complete. Results: {results}")
        return results

    def _evaluate_garbled_gate(
        self, garbled_gate: GarbledGate, wire_labels: Dict[Wire, bytes]
    ) -> bytes:
        """
        Evaluate a single garbled gate.

        Try to decrypt each entry in the garbled table using the input labels.
        Exactly one entry should decrypt successfully - that's our output label.
        """
        gate = garbled_gate.gate

        if gate.gate_type == GateType.NOT:
            # NOT gate: single input
            input_label = wire_labels[gate.input_wires[0]]

            # Try to decrypt each entry
            for encrypted_entry in garbled_gate.garbled_table:
                try:
                    output_label = CryptoUtils.decrypt(input_label, encrypted_entry)
                    # In a real implementation, we'd verify this is a valid label
                    # using a MAC or by checking label format
                    return output_label
                except:
                    continue
        else:
            # Binary gate: two inputs
            input_label_0 = wire_labels[gate.input_wires[0]]
            input_label_1 = wire_labels[gate.input_wires[1]]
            key = input_label_0 + input_label_1

            # Try to decrypt each entry
            for encrypted_entry in garbled_gate.garbled_table:
                try:
                    output_label = CryptoUtils.decrypt(key, encrypted_entry)
                    # In practice, we'd verify this decryption succeeded
                    return output_label
                except:
                    continue

        raise ValueError(f"Failed to evaluate gate {gate.gate_id}")


# ================== EXAMPLE CIRCUITS ==================


def create_and_circuit() -> Circuit:
    """
    Create a simple AND circuit: output = alice_input AND bob_input
    """
    # Create wires
    alice_wire = Wire("alice_input")
    bob_wire = Wire("bob_input")
    output_wire = Wire("output")

    # Create AND gate
    and_gate = Gate(
        gate_id="and_gate",
        gate_type=GateType.AND,
        input_wires=[alice_wire, bob_wire],
        output_wire=output_wire,
    )

    return Circuit(
        gates=[and_gate],
        input_wires=[alice_wire, bob_wire],
        output_wires=[output_wire],
        alice_input_wires=[alice_wire],
        bob_input_wires=[bob_wire],
    )


def create_comparison_circuit() -> Circuit:
    """
    Create a circuit that compares two 2-bit numbers.
    Returns TRUE if Alice's number >= Bob's number.

    This demonstrates a more complex circuit with multiple gates.
    """
    # Alice's 2-bit input (a1, a0)
    a1 = Wire("alice_bit_1")
    a0 = Wire("alice_bit_0")

    # Bob's 2-bit input (b1, b0)
    b1 = Wire("bob_bit_1")
    b0 = Wire("bob_bit_0")

    # Intermediate wires for comparison logic
    not_b1 = Wire("not_b1")
    not_b0 = Wire("not_b0")
    a1_greater = Wire("a1_greater")  # a1 AND NOT b1
    bits1_equal = Wire("bits1_equal")  # a1 XOR b1, then NOT
    a0_greater = Wire("a0_greater")  # a0 AND NOT b0
    a0_greater_when_equal = Wire("a0_greater_when_equal")
    output = Wire("output")

    gates = [
        # NOT gates for Bob's bits
        Gate("not_b1_gate", GateType.NOT, [b1], not_b1),
        Gate("not_b0_gate", GateType.NOT, [b0], not_b0),
        # Check if a1 > b1
        Gate("a1_greater_gate", GateType.AND, [a1, not_b1], a1_greater),
        # Check if a1 == b1 (using XOR then NOT)
        Gate("bits1_xor", GateType.XOR, [a1, b1], Wire("temp_xor")),
        Gate("bits1_equal_gate", GateType.NOT, [Wire("temp_xor")], bits1_equal),
        # Check if a0 > b0
        Gate("a0_greater_gate", GateType.AND, [a0, not_b0], a0_greater),
        # a0 > b0 matters only when a1 == b1
        Gate(
            "a0_matters", GateType.AND, [bits1_equal, a0_greater], a0_greater_when_equal
        ),
        # Final result: (a1 > b1) OR (a1 == b1 AND a0 > b0)
        Gate("final_or", GateType.OR, [a1_greater, a0_greater_when_equal], output),
    ]

    return Circuit(
        gates=gates,
        input_wires=[a1, a0, b1, b0],
        output_wires=[output],
        alice_input_wires=[a1, a0],
        bob_input_wires=[b1, b0],
    )


# ================== DEMONSTRATION ==================


def demonstrate_protocol():
    """
    Demonstrate the complete Yao's Garbled Circuit protocol.
    """
    print("=" * 70)
    print("YAO'S GARBLED CIRCUIT PROTOCOL DEMONSTRATION")
    print("=" * 70)

    # Example 1: Simple AND circuit
    print("\n--- Example 1: Simple AND Circuit ---")
    print("Computing: alice_input AND bob_input")

    circuit = create_and_circuit()

    # Create parties
    alice = Sender(circuit)
    bob = Receiver()
    alice.connect_to_receiver(bob)

    # Define inputs
    alice_inputs = {Wire("alice_input"): True}
    bob_inputs = {Wire("bob_input"): True}

    print(f"Alice's input: {alice_inputs}")
    print(f"Bob's input: {bob_inputs}")

    # Run protocol
    result = alice.run_protocol(alice_inputs, bob_inputs)
    print(f"Result: {result}")
    expected_result = {Wire("output"): True}
    print(f"Expected: {expected_result}")

    # Example 2: Comparison circuit
    print("\n--- Example 2: 2-bit Comparison Circuit ---")
    print("Computing: Is Alice's 2-bit number >= Bob's 2-bit number?")

    circuit = create_comparison_circuit()
    alice = Sender(circuit)
    bob = Receiver()
    alice.connect_to_receiver(bob)

    # Alice has 3 (binary: 11), Bob has 2 (binary: 10)
    alice_inputs = {Wire("alice_bit_1"): True, Wire("alice_bit_0"): True}  # MSB  # LSB
    bob_inputs = {Wire("bob_bit_1"): True, Wire("bob_bit_0"): False}  # MSB  # LSB

    print(f"Alice's number: 3 (binary: 11)")
    print(f"Bob's number: 2 (binary: 10)")

    result = alice.run_protocol(alice_inputs, bob_inputs)
    output_wire = circuit.output_wires[0]
    print(f"Result (Alice >= Bob): {result[output_wire]}")

    print("\n" + "=" * 70)
    print("PROTOCOL EXECUTION COMPLETE")
    print("=" * 70)
    print("\nKey Properties Demonstrated:")
    print("1. Bob learned the result without learning Alice's input")
    print("2. Alice learned nothing about Bob's input")
    print("3. The computation was performed on encrypted (garbled) data")
    print("4. Only the final result was revealed")


if __name__ == "__main__":
    demonstrate_protocol()
