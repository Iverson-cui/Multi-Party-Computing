"""
GMW Protocol Implementation

This module implements the complete GMW protocol for secure two-party computation.
The protocol works by:
1. Secret sharing all inputs using XOR shares
2. Evaluating XOR gates locally (no communication)
3. Evaluating AND gates using 1-out-of-4 Oblivious Transfer
4. Evaluating NOT gates locally (no communication, only one party flips)
5. Reconstructing the final output

Key insight for AND gate evaluation:
The sender (Party 2) chooses a random output share z2, then provides four OT values
such that the chooser (Party 1) obtains z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2)),
where x1,y1 are Party 1's input shares and x2,y2 are Party 2's input shares.
This ensures z1 ⊕ z2 = (x1 ⊕ x2) ∧ (y1 ⊕ y2), the correct AND result.

Key insight for NOT gate evaluation:
For NOT gates, only one party needs to flip their share. We use the convention
that Party 1 flips their share while Party 2 keeps theirs unchanged.
This ensures the XOR reconstruction gives the correct NOT result.
"""

import sys
import os
import time

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "GC"))

from typing import Dict, List, Tuple
import secrets
from gmw_circuit import GMWCircuit, GMWWire, GMWGate, GMWGateType
from gmw_shares import XORSecretSharing, GMWShareManager
from oblivious_transfer import OT4Receiver, OT4Sender


class GMWParty1:
    """
    Party 1 in the GMW protocol.
    Responsible for:
    1. Managing their secret shares
    2. Participating in OT for AND gates (as both sender and receiver)
    3. Local evaluation of XOR gates
    """

    def __init__(self, circuit: GMWCircuit):
        self.circuit = circuit
        self.share_manager = GMWShareManager(party_id=1)
        self.party2: "GMWParty2" = None
        self.inputs: Dict[GMWWire, bool] = None

    def connect_to_party2(self, party2: "GMWParty2"):
        """Establish connection with Party 2."""
        self.party2 = party2
        party2.party1 = self

    def set_inputs(self, inputs: Dict[GMWWire, bool]):
        """Set this party's private inputs."""
        self.inputs = inputs

    def share_inputs(self, party2_inputs: Dict[GMWWire, bool]):
        """
        Phase 1: Create XOR shares of all inputs.
        Both parties get shares of all inputs.
        Party 1 get its share by this function directly putting it back to the object.
        Party 2 share will be returned by this function.
        """
        print("[Party 1] Starting input sharing phase...")

        party1_shares, party2_shares = XORSecretSharing.share_inputs(
            self.inputs, party2_inputs
        )

        self.share_manager.set_input_shares(party1_shares)

        print(f"[Party 1] Input shares created: {party1_shares}")
        return party2_shares

    def evaluate_circuit(self) -> Dict[GMWWire, bool]:
        """
        Phase 2: Evaluate the circuit gate by gate.
        XOR gates are evaluated locally, AND gates require OT.
        """
        print("[Party 1] Starting circuit evaluation...")

        # Track which wires have been processed
        # At first only input wires have been processed
        processed_wires = set(self.circuit.input_wires)

        # Keep trying to process gates until all are done
        remaining_gates = self.circuit.gates.copy()

        while remaining_gates:
            gates_processed_this_round = []

            for gate in remaining_gates:
                # Check if all input wires for this gate are ready
                inputs_ready = all(wire in processed_wires for wire in gate.input_wires)

                if inputs_ready:
                    if gate.gate_type == GMWGateType.XOR:
                        self._evaluate_xor_gate(gate)
                    elif gate.gate_type == GMWGateType.AND:
                        self._evaluate_and_gate(gate)
                    elif gate.gate_type == GMWGateType.NOT:
                        self._evaluate_not_gate(gate)
                    elif gate.gate_type == GMWGateType.INPUT:
                        # Input gates don't need evaluation
                        pass

                    # Mark output wire as processed
                    processed_wires.add(gate.output_wire)
                    gates_processed_this_round.append(gate)

            # Remove processed gates
            for gate in gates_processed_this_round:
                remaining_gates.remove(gate)

            # If no gates were processed in this round, we have a problem
            if not gates_processed_this_round and remaining_gates:
                unprocessed_gates = [g.gate_id for g in remaining_gates]
                raise RuntimeError(
                    f"Circuit evaluation stuck. Unprocessed gates: {unprocessed_gates}"
                )

        # Get final output shares
        output_shares = self.share_manager.get_reconstruction_shares(
            self.circuit.output_wires
        )

        print(f"[Party 1] Circuit evaluation complete. Output shares: {output_shares}")
        return output_shares

    def _evaluate_xor_gate(self, gate: GMWGate):
        """Evaluate XOR gate locally (no communication needed)."""
        print(f"[Party 1] Evaluating XOR gate: {gate.gate_id}")
        self.share_manager.evaluate_xor_gate(gate.input_wires, gate.output_wire)

    def _evaluate_not_gate(self, gate: GMWGate):
        """Evaluate NOT gate locally (no communication needed)."""
        print(f"[Party 1] Evaluating NOT gate: {gate.gate_id}")
        if len(gate.input_wires) != 1:
            raise ValueError("NOT gate must have exactly 1 input")
        self.share_manager.evaluate_not_gate(gate.input_wires[0], gate.output_wire)

    def _evaluate_and_gate(self, gate: GMWGate):
        """
        Evaluate AND gate using 1-out-of-4 OT.

        The key insight: (a1⊕a2) ∧ (b1⊕b2) = (a1∧b1) ⊕ (a1∧b2) ⊕ (a2∧b1) ⊕ (a2∧b2)

        Party 1 acts as OT receiver, choosing one of 4 values based on their shares.
        Party 2 acts as OT sender, providing all 4 possible combinations.
        """
        print(f"[Party 1] Evaluating AND gate: {gate.gate_id}")

        # First, ensure we have computed shares for the input wires if they're intermediate results
        for input_wire in gate.input_wires:
            # if we don't have the share of this wire
            if input_wire not in self.share_manager.shares:
                # This input wire might be the output of another gate we need to evaluate first
                # Find the gate that produces this wire
                for circuit_gate in self.circuit.gates:
                    # this gate has this wire as the output wire
                    if circuit_gate.output_wire == input_wire:
                        # XOR gate: evaluate it
                        if circuit_gate.gate_type == GMWGateType.XOR:
                            self._evaluate_xor_gate(circuit_gate)
                        # AND gate: error
                        elif circuit_gate.gate_type == GMWGateType.AND:
                            # This shouldn't happen in proper topological order, but handle it
                            raise RuntimeError(
                                f"AND gate {gate.gate_id} depends on another AND gate {circuit_gate.gate_id}"
                            )
                        break

        # For now we have all input wires of the current gate prepared
        # Party 1 is the receiver in the 1-out-of-4 OT
        # Get our selection for OT based on our shares
        selection = self.share_manager.prepare_and_gate_ot_input(gate.input_wires)

        # Get the OT result from Party 2
        # This step also put party 2 share back to it.
        ot_result = self.party2.provide_and_gate_ot_values(gate, selection)

        # The OT result is our share of the output
        self.share_manager.set_share(gate.output_wire, ot_result)

        print(f"[Party 1] AND gate {gate.gate_id} result share: {ot_result}")


class GMWParty2:
    """
    Party 2 in the GMW protocol.
    Responsible for:
    1. Managing their secret shares
    2. Participating in OT for AND gates (as both sender and receiver)
    3. Local evaluation of XOR gates
    """

    def __init__(self, circuit: GMWCircuit):
        self.circuit = circuit
        self.share_manager = GMWShareManager(party_id=2)
        self.party1: GMWParty1 = None

    def set_inputs(self, inputs: Dict[GMWWire, bool]):
        """Set this party's private inputs."""
        self.inputs = inputs

    def receive_input_shares(self, shares: Dict[GMWWire, bool]):
        """Receive shares from Party 1."""
        print(f"[Party 2] Received input shares: {shares}")
        self.share_manager.set_input_shares(shares)

    def evaluate_circuit(self) -> Dict[GMWWire, bool]:
        """
        Phase 2: Evaluate the circuit gate by gate.
        XOR gates are evaluated locally, AND gates require OT.
        """
        print("[Party 2] Starting circuit evaluation...")

        # Track which wires have been processed
        processed_wires = set(self.circuit.input_wires)

        # Keep trying to process gates until all are done
        remaining_gates = self.circuit.gates.copy()

        while remaining_gates:
            gates_processed_this_round = []

            for gate in remaining_gates:
                # Check if all input wires for this gate are ready
                assert (
                    inputs_ready := all(
                        wire in processed_wires for wire in gate.input_wires
                    )
                )

                if inputs_ready:
                    if gate.gate_type == GMWGateType.XOR:
                        self._evaluate_xor_gate(gate)
                        # Mark output wire as processed
                        processed_wires.add(gate.output_wire)
                        gates_processed_this_round.append(gate)
                    elif gate.gate_type == GMWGateType.NOT:
                        self._evaluate_not_gate(gate)
                        # Mark output wire as processed
                        processed_wires.add(gate.output_wire)
                        gates_processed_this_round.append(gate)
                    elif gate.gate_type == GMWGateType.AND:
                        # AND gates are handled when Party 1 requests OT
                        # We still need to mark them as processed after OT
                        # This will be handled in provide_and_gate_ot_values
                        processed_wires.add(gate.output_wire)
                        # gates_processed_this_round.append(gate)
                    elif gate.gate_type == GMWGateType.INPUT:
                        # Input gates don't need evaluation
                        processed_wires.add(gate.output_wire)
                        gates_processed_this_round.append(gate)

            # Remove processed gates (except AND gates which are handled differently)
            for gate in gates_processed_this_round:
                remaining_gates.remove(gate)

            # Remove AND gates that have been processed
            and_gates_to_remove = []
            for gate in remaining_gates:
                if (
                    gate.gate_type == GMWGateType.AND
                    and gate.output_wire in self.share_manager.shares
                ):
                    # processed_wires.add(gate.output_wire)
                    and_gates_to_remove.append(gate)

            for gate in and_gates_to_remove:
                remaining_gates.remove(gate)

            # If no gates were processed in this round, we have a problem
            if (
                not gates_processed_this_round
                and not and_gates_to_remove
                and remaining_gates
            ):
                unprocessed_gates = [g.gate_id for g in remaining_gates]
                raise RuntimeError(
                    f"Circuit evaluation stuck. Unprocessed gates: {unprocessed_gates}"
                )

        # Get final output shares
        output_shares = self.share_manager.get_reconstruction_shares(
            self.circuit.output_wires
        )

        print(f"[Party 2] Circuit evaluation complete. Output shares: {output_shares}")
        return output_shares

    def _evaluate_xor_gate(self, gate: GMWGate):
        """Evaluate XOR gate locally (no communication needed)."""
        print(f"[Party 2] Evaluating XOR gate: {gate.gate_id}")
        # First, ensure we have computed shares for the input wires if they're intermediate results
        for input_wire in gate.input_wires:
            if input_wire not in self.share_manager.shares:
                # This input wire might be the output of another gate we need to evaluate first
                # Find the gate that produces this wire
                for circuit_gate in self.circuit.gates:
                    if circuit_gate.output_wire == input_wire:
                        if circuit_gate.gate_type == GMWGateType.XOR:
                            self._evaluate_xor_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.NOT:
                            self._evaluate_not_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.AND:
                            # This shouldn't happen in proper topological order, but handle it
                            raise RuntimeError(
                                f"AND gate {gate.gate_id} depends on another AND gate {circuit_gate.gate_id}"
                            )
                        break
        self.share_manager.evaluate_xor_gate(gate.input_wires, gate.output_wire)

    def _evaluate_not_gate(self, gate: GMWGate):
        """Evaluate NOT gate locally (no communication needed)."""
        print(f"[Party 2] Evaluating NOT gate: {gate.gate_id}")
        if len(gate.input_wires) != 1:
            raise ValueError("NOT gate must have exactly 1 input")

        # First, ensure we have computed shares for the input wires if they're intermediate results
        for input_wire in gate.input_wires:
            if input_wire not in self.share_manager.shares:
                # This input wire might be the output of another gate we need to evaluate first
                # Find the gate that produces this wire
                for circuit_gate in self.circuit.gates:
                    if circuit_gate.output_wire == input_wire:
                        if circuit_gate.gate_type == GMWGateType.XOR:
                            self._evaluate_xor_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.NOT:
                            self._evaluate_not_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.AND:
                            # This shouldn't happen in proper topological order, but handle it
                            raise RuntimeError(
                                f"AND gate {gate.gate_id} depends on another AND gate {circuit_gate.gate_id}"
                            )
                        break
        self.share_manager.evaluate_not_gate(gate.input_wires[0], gate.output_wire)

    def provide_and_gate_ot_values(self, gate: GMWGate, party1_selection: int) -> bool:
        """
        Provide OT values for AND gate evaluation using the standard GMW approach.

        Following the attachment's setting:
        - The sender (Party 2) chooses a random output share z2
        - The sender provides four inputs to the OT protocol such that
          the chooser obtains z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2))

        Where:
        - x1, y1 are Party 1's input shares (used for OT selection)
        - x2, y2 are Party 2's input shares
        - z1, z2 are the output shares such that z1 ⊕ z2 = (x1 ⊕ x2) ∧ (y1 ⊕ y2)
        """
        print(f"[Party 2] Providing OT values for AND gate: {gate.gate_id}")

        # First, ensure we have computed shares for the input wires if they're intermediate results
        for input_wire in gate.input_wires:
            if input_wire not in self.share_manager.shares:
                # This input wire might be the output of another gate we need to evaluate first
                # Find the gate that produces this wire

                for circuit_gate in self.circuit.gates:
                    if circuit_gate.output_wire == input_wire:
                        if circuit_gate.gate_type == GMWGateType.XOR:
                            self._evaluate_xor_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.NOT:
                            self._evaluate_not_gate(circuit_gate)
                        elif circuit_gate.gate_type == GMWGateType.AND:
                            # This shouldn't happen in proper topological order, but handle it
                            raise RuntimeError(
                                f"AND gate {gate.gate_id} depends on another AND gate {circuit_gate.gate_id}"
                            )
                        break

        # Get our shares of the input wires (x2, y2)
        x2 = self.share_manager.get_share(gate.input_wires[0])
        y2 = self.share_manager.get_share(gate.input_wires[1])

        # Choose a random output share z2 for Party 2
        z2 = secrets.choice([True, False])

        # Compute the 4 OT values for each possible combination of Party 1's shares (x1, y1)
        # For each (x1, y1), we want to provide z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2))
        ot_values = []

        for x1 in [False, True]:
            for y1 in [False, True]:
                # Compute the actual AND result: (x1 ⊕ x2) ∧ (y1 ⊕ y2)
                and_result = (x1 ^ x2) & (y1 ^ y2)

                # Compute Party 1's share: z1 = z2 ⊕ and_result
                z1 = z2 ^ and_result
                ot_values.append(z1)

        print(f"[Party 2] Random output share z2: {z2}")
        print(f"[Party 2] OT values for AND gate: {ot_values}")

        # Perform 1-out-of-4 OT
        receiver = OT4Receiver(selection_index=party1_selection)
        sender = OT4Sender(
            str(ot_values[0]), str(ot_values[1]), str(ot_values[2]), str(ot_values[3])
        )

        # Execute OT protocol
        pk0, pk1, pk2, pk3 = receiver.prepare_key_pairs()
        e0, e1, e2, e3 = sender.encrypt_secrets(pk0, pk1, pk2, pk3)
        chosen_value_str = receiver.decrypt_chosen_secret(e0, e1, e2, e3)

        # Convert back to boolean
        chosen_value = chosen_value_str == b"True"

        # Set our share of the output to the random z2
        self.share_manager.set_share(gate.output_wire, z2)

        print(f"[Party 2] AND gate {gate.gate_id} our share (z2): {z2}")
        print(
            f"[Party 1] AND gate {gate.gate_id} will receive share (z1): {chosen_value}"
        )

        return chosen_value


def create_2bit_multiplier_circuit() -> GMWCircuit:
    """
    Create a 2-bit multiplier circuit: C = A × B
    Where A = [a1, a0] and B = [b1, b0] are 2-bit numbers
    And C = [c3, c2, c1, c0] is the 4-bit result

    The multiplication algorithm:
      A = a1*2 + a0
      B = b1*2 + b0
      C = A*B = (a1*2 + a0) * (b1*2 + b0)
        = a1*b1*4 + a1*b0*2 + a0*b1*2 + a0*b0
        = (a1*b1)*4 + (a1*b0 + a0*b1)*2 + (a0*b0)

    In binary, this becomes:
      c3 c2 c1 c0 = (a1∧b1) (carry from c1) (a1∧b0 ⊕ a0∧b1) (a0∧b0)

    Where carry from c1 = (a1∧b0) ∧ (a0∧b1)
    And c2 = (a1∧b1) ⊕ carry_from_c1
    """
    # Input wires for A (party 1's 2-bit number)
    a1 = GMWWire("party1_a1")  # MSB
    a0 = GMWWire("party1_a0")  # LSB

    # Input wires for B (party 2's 2-bit number)
    b1 = GMWWire("party2_b1")  # MSB
    b0 = GMWWire("party2_b0")  # LSB

    # Intermediate wires for partial products
    p00 = GMWWire("prod_a0_b0")  # a0 ∧ b0
    p01 = GMWWire("prod_a0_b1")  # a0 ∧ b1
    p10 = GMWWire("prod_a1_b0")  # a1 ∧ b0
    p11 = GMWWire("prod_a1_b1")  # a1 ∧ b1

    # Intermediate wires for carries
    carry1 = GMWWire("carry_from_c1")  # Carry from bit position 1

    # Output wires (4-bit result)
    c0 = GMWWire("output_c0")  # LSB
    c1 = GMWWire("output_c1")
    c2 = GMWWire("output_c2")
    c3 = GMWWire("output_c3")  # MSB

    gates = [
        # Step 1: Compute partial products using AND gates
        GMWGate("mult_a0_b0", GMWGateType.AND, [a0, b0], p00),
        GMWGate("mult_a0_b1", GMWGateType.AND, [a0, b1], p01),
        GMWGate("mult_a1_b0", GMWGateType.AND, [a1, b0], p10),
        GMWGate("mult_a1_b1", GMWGateType.AND, [a1, b1], p11),
        # Step 2: c0 = p00 (just copy)
        GMWGate("copy_c0", GMWGateType.XOR, [p00, GMWWire("zero_c0")], c0),
        # Step 3: c1 = p01 XOR p10
        GMWGate("compute_c1", GMWGateType.XOR, [p01, p10], c1),
        # Step 4: carry from c1 = p01 AND p10
        GMWGate("carry_from_c1", GMWGateType.AND, [p01, p10], carry1),
        # Step 5: c2 = p11 XOR carry1
        GMWGate("compute_c2", GMWGateType.XOR, [p11, carry1], c2),
        # Step 6: c3 = p11 AND carry1 (final carry)
        GMWGate("compute_c3", GMWGateType.AND, [p11, carry1], c3),
    ]

    # Create zero wire
    zero_c0 = GMWWire("zero_c0")

    return GMWCircuit(
        gates=gates,
        input_wires=[a1, a0, b1, b0, zero_c0],
        output_wires=[c3, c2, c1, c0],  # MSB to LSB
        party1_input_wires=[a1, a0, zero_c0],
        party2_input_wires=[b1, b0],
    )


def test_2bit_multiplier():
    """Test the 2-bit multiplier with several test cases."""
    print("\n--- Complex Example: 2-bit Multiplier ---")
    print("Computing: A * B where A and B are 2-bit numbers")

    circuit = create_2bit_multiplier_circuit()

    test_cases = [
        (3, 2, "3 * 2 = 6"),  # 11 * 10 = 0110
        (2, 3, "2 * 3 = 6"),  # 10 * 11 = 0110
        (3, 3, "3 * 3 = 9"),  # 11 * 11 = 1001
        (1, 2, "1 * 2 = 2"),  # 01 * 10 = 0010
        (0, 3, "0 * 3 = 0"),  # 00 * 11 = 0000
    ]

    for a_val, b_val, description in test_cases:
        print(f"\n🧮 Test case: {description}")

        # Convert to binary
        a1_bit = bool(a_val & 2)  # bit 1
        a0_bit = bool(a_val & 1)  # bit 0
        b1_bit = bool(b_val & 2)  # bit 1
        b0_bit = bool(b_val & 1)  # bit 0

        party1_inputs = {
            GMWWire("party1_a1"): a1_bit,
            GMWWire("party1_a0"): a0_bit,
            GMWWire("zero_c0"): False,
        }

        party2_inputs = {
            GMWWire("party2_b1"): b1_bit,
            GMWWire("party2_b0"): b0_bit,
        }

        print(f"Party 1: A = {a_val} (binary: {a1_bit}{a0_bit})")
        print(f"Party 2: B = {b_val} (binary: {b1_bit}{b0_bit})")

        # Create fresh protocol instance
        protocol = GMWProtocol(circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        # Extract result bits and convert to integer
        c3 = result[GMWWire("output_c3")]
        c2 = result[GMWWire("output_c2")]
        c1 = result[GMWWire("output_c1")]
        c0 = result[GMWWire("output_c0")]

        result_value = (int(c3) << 3) + (int(c2) << 2) + (int(c1) << 1) + int(c0)
        expected_value = a_val * b_val

        print(f"GMW result: {c3}{c2}{c1}{c0} = {result_value}")
        print(f"Expected: {expected_value}")
        print(f"✅ Correct: {result_value == expected_value}")

        # Also verify with plaintext evaluation
        all_inputs = {**party1_inputs, **party2_inputs}
        expected_circuit = circuit.evaluate_plaintext(all_inputs)
        print(f"Circuit plaintext verification: {expected_circuit}")


# ================== DEMONSTRATION ==================


def create_2bit_multiplier_circuit() -> GMWCircuit:
    """
    Create a 2-bit multiplier circuit: multiply two 2-bit numbers.
    Party 1 has number A = a1*2 + a0
    Party 2 has number B = b1*2 + b0
    Output: A * B = c3*8 + c2*4 + c1*2 + c0

    This creates a more complex circuit with multiple AND and XOR gates.
    """
    # Party 1's 2-bit input (a1 is MSB, a0 is LSB)
    a1 = GMWWire("party1_a1")  # MSB
    a0 = GMWWire("party1_a0")  # LSB

    # Party 2's 2-bit input (b1 is MSB, b0 is LSB)
    b1 = GMWWire("party2_b1")  # MSB
    b0 = GMWWire("party2_b0")  # LSB

    # Intermediate wires for partial products
    # p00 = a0 * b0, p01 = a0 * b1, p10 = a1 * b0, p11 = a1 * b1
    p00 = GMWWire("p00")
    p01 = GMWWire("p01")
    p10 = GMWWire("p10")
    p11 = GMWWire("p11")

    # Intermediate wires for carry
    carry1 = GMWWire("carry1")  # carry from adding p01 and p10

    # Output wires (4-bit result)
    c0 = GMWWire("output_c0")  # LSB
    c1 = GMWWire("output_c1")
    c2 = GMWWire("output_c2")
    c3 = GMWWire("output_c3")  # MSB

    gates = [
        # Step 1: Compute partial products using AND gates
        GMWGate("mult_a0_b0", GMWGateType.AND, [a0, b0], p00),
        GMWGate("mult_a0_b1", GMWGateType.AND, [a0, b1], p01),
        GMWGate("mult_a1_b0", GMWGateType.AND, [a1, b0], p10),
        GMWGate("mult_a1_b1", GMWGateType.AND, [a1, b1], p11),
        # Step 2: c0 = p00 (just copy)
        GMWGate("copy_c0", GMWGateType.XOR, [p00, GMWWire("zero_c0")], c0),
        # Step 3: c1 = p01 XOR p10
        GMWGate("compute_c1", GMWGateType.XOR, [p01, p10], c1),
        # Step 4: carry from c1 = p01 AND p10
        GMWGate("carry_from_c1", GMWGateType.AND, [p01, p10], carry1),
        # Step 5: c2 = p11 XOR carry1
        GMWGate("compute_c2", GMWGateType.XOR, [p11, carry1], c2),
        # Step 6: c3 = p11 AND carry1 (final carry)
        GMWGate("compute_c3", GMWGateType.AND, [p11, carry1], c3),
    ]

    # Create zero wire
    zero_c0 = GMWWire("zero_c0")

    return GMWCircuit(
        gates=gates,
        input_wires=[a1, a0, b1, b0, zero_c0],
        output_wires=[c3, c2, c1, c0],  # MSB to LSB
        party1_input_wires=[a1, a0, zero_c0],
        party2_input_wires=[b1, b0],
    )


class GMWProtocol:
    """
    Coordinates the complete GMW protocol execution between two parties.
    Handles timing and statistics collection.
    """

    def __init__(self, circuit: GMWCircuit):
        self.circuit = circuit
        self.party1 = GMWParty1(circuit)
        self.party2 = GMWParty2(circuit)

        # Connect parties
        self.party1.connect_to_party2(self.party2)

        # Timing statistics
        self.timing_stats = {}

    def execute_protocol(
        self, party1_inputs: Dict[GMWWire, bool], party2_inputs: Dict[GMWWire, bool]
    ) -> Dict[GMWWire, bool]:
        """
        Execute the complete GMW protocol with timing.

        Returns:
            Dict mapping output wires to their final Boolean values
        """
        total_start_time = time.time()

        print("\n🚀 Starting GMW Protocol Execution")
        print("=" * 50)

        # Phase 1: Input sharing
        print("\n📤 Phase 1: Input Sharing")
        sharing_start_time = time.time()

        self.party1.set_inputs(party1_inputs)
        self.party2.set_inputs(party2_inputs)

        party2_shares = self.party1.share_inputs(party2_inputs)
        self.party2.receive_input_shares(party2_shares)

        sharing_time = time.time() - sharing_start_time
        self.timing_stats["input_sharing"] = sharing_time
        print(f"⏱️  Input sharing completed in {sharing_time:.4f} seconds")

        # Phase 2: Circuit evaluation
        print("\n⚡ Phase 2: Circuit Evaluation")
        evaluation_start_time = time.time()

        # Both parties evaluate the circuit
        party1_output_shares = self.party1.evaluate_circuit()
        party2_output_shares = self.party2.evaluate_circuit()

        evaluation_time = time.time() - evaluation_start_time
        self.timing_stats["circuit_evaluation"] = evaluation_time
        print(f"⏱️  Circuit evaluation completed in {evaluation_time:.4f} seconds")

        # Phase 3: Output reconstruction
        print("\n🔍 Phase 3: Output Reconstruction")
        reconstruction_start_time = time.time()

        final_outputs = {}
        for wire in self.circuit.output_wires:
            share1 = party1_output_shares[wire]
            share2 = party2_output_shares[wire]
            final_value = XORSecretSharing.reconstruct_secret(share1, share2)
            final_outputs[wire] = final_value
            print(f"Output {wire.wire_id}: {share1} ⊕ {share2} = {final_value}")

        reconstruction_time = time.time() - reconstruction_start_time
        self.timing_stats["output_reconstruction"] = reconstruction_time
        print(
            f"⏱️  Output reconstruction completed in {reconstruction_time:.4f} seconds"
        )

        total_time = time.time() - total_start_time
        self.timing_stats["total_time"] = total_time

        print(f"\n🏁 Protocol completed in {total_time:.4f} seconds total")
        self._print_gate_statistics()
        self._print_detailed_timing()

        return final_outputs

    def _print_gate_statistics(self):
        """Print statistics about the circuit."""
        and_gates = len(self.circuit.get_and_gates())
        xor_gates = len(self.circuit.get_xor_gates())
        not_gates = len(self.circuit.get_not_gates())
        total_gates = len(self.circuit.gates)

        print(f"\n📊 Circuit Statistics:")
        print(f"   Total gates: {total_gates}")
        print(f"   AND gates: {and_gates} (require communication)")
        print(f"   XOR gates: {xor_gates} (local evaluation)")
        print(f"   NOT gates: {not_gates} (local evaluation)")
        print(f"   Communication rounds: {and_gates}")

    def _print_detailed_timing(self):
        """Print detailed timing breakdown."""
        print(f"\n⏱️  Detailed Timing Breakdown:")
        for phase, duration in self.timing_stats.items():
            percentage = (duration / self.timing_stats["total_time"]) * 100
            print(
                f"   {phase.replace('_', ' ').title()}: {duration:.4f}s ({percentage:.1f}%)"
            )


def test_not_gates():
    """Test circuits with NOT gates and timing."""
    print("\n--- Testing NOT Gate Functionality ---")

    # Import circuit examples - using direct import to avoid path issues
    from gmw_circuit import create_gmw_not_circuit, create_gmw_nand_circuit

    # Test 1: Simple NOT circuit
    print("\n🔧 Test 1: Simple NOT Circuit")
    print("Computing: NOT(party1_input)")

    not_circuit = create_gmw_not_circuit()
    protocol = GMWProtocol(not_circuit)

    party1_inputs = {GMWWire("party1_input"): True}
    party2_inputs = {}  # No inputs from party 2

    print(f"Party 1 input: {party1_inputs}")
    print(f"Party 2 input: {party2_inputs}")

    result = protocol.execute_protocol(party1_inputs, party2_inputs)
    expected = not_circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})

    print(f"GMW result: {result}")
    print(f"Expected: {expected}")
    print(f"✅ Correct: {result == expected}")

    # Test 2: NAND circuit (AND + NOT)
    print("\n🔧 Test 2: NAND Circuit (AND + NOT)")
    print("Computing: NOT(party1_input AND party2_input)")

    nand_circuit = create_gmw_nand_circuit()
    protocol = GMWProtocol(nand_circuit)

    test_cases = [
        (False, False, "0 NAND 0 = 1"),
        (False, True, "0 NAND 1 = 1"),
        (True, False, "1 NAND 0 = 1"),
        (True, True, "1 NAND 1 = 0"),
    ]

    for p1_val, p2_val, description in test_cases:
        print(f"\n🧮 Test case: {description}")

        party1_inputs = {GMWWire("party1_input"): p1_val}
        party2_inputs = {GMWWire("party2_input"): p2_val}

        protocol_fresh = GMWProtocol(nand_circuit)
        result = protocol_fresh.execute_protocol(party1_inputs, party2_inputs)
        expected = nand_circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})

        print(f"GMW result: {result}")
        print(f"Expected: {expected}")
        print(f"✅ Correct: {result == expected}")


def demonstrate_gmw_protocol():
    """Test the 2-bit multiplier with several test cases."""
    print("\n--- Complex Example: 2-bit Multiplier ---")
    print("Computing: A * B where A and B are 2-bit numbers")

    circuit = create_2bit_multiplier_circuit()

    test_cases = [
        (3, 2, "3 * 2 = 6"),  # 11 * 10 = 0110
        (2, 3, "2 * 3 = 6"),  # 10 * 11 = 0110
        (3, 3, "3 * 3 = 9"),  # 11 * 11 = 1001
        (1, 2, "1 * 2 = 2"),  # 01 * 10 = 0010
        (0, 3, "0 * 3 = 0"),  # 00 * 11 = 0000
    ]

    for a_val, b_val, description in test_cases:
        print(f"\n🧮 Test case: {description}")

        # Convert to binary
        a1_bit = bool(a_val & 2)  # bit 1
        a0_bit = bool(a_val & 1)  # bit 0
        b1_bit = bool(b_val & 2)  # bit 1
        b0_bit = bool(b_val & 1)  # bit 0

        party1_inputs = {
            GMWWire("party1_a1"): a1_bit,
            GMWWire("party1_a0"): a0_bit,
            GMWWire("zero_c0"): False,
        }

        party2_inputs = {
            GMWWire("party2_b1"): b1_bit,
            GMWWire("party2_b0"): b0_bit,
        }

        print(f"Party 1: A = {a_val} (binary: {a1_bit}{a0_bit})")
        print(f"Party 2: B = {b_val} (binary: {b1_bit}{b0_bit})")

        # Create fresh protocol instance
        protocol = GMWProtocol(circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        # Extract result bits and convert to integer
        c3 = result[GMWWire("output_c3")]
        c2 = result[GMWWire("output_c2")]
        c1 = result[GMWWire("output_c1")]
        c0 = result[GMWWire("output_c0")]

        result_value = (int(c3) << 3) + (int(c2) << 2) + (int(c1) << 1) + int(c0)
        expected_value = a_val * b_val

        print(f"GMW result: {c3}{c2}{c1}{c0} = {result_value}")
        print(f"Expected: {expected_value}")
        print(f"✅ Correct: {result_value == expected_value}")

        # Also verify with plaintext evaluation
        all_inputs = {**party1_inputs, **party2_inputs}
        expected_circuit = circuit.evaluate_plaintext(all_inputs)
        print(f"Circuit plaintext verification: {expected_circuit}")


def create_complex_boolean_circuit() -> GMWCircuit:
    """
    Create a complex Boolean circuit that combines multiple gate types:
    f(a, b, c, d) = (NOT(a) AND b) XOR (c AND NOT(d))

    This circuit demonstrates:
    - NOT gates for input negation
    - AND gates for conjunction
    - XOR gate for final combination
    """
    # Input wires
    a = GMWWire("party1_a")
    b = GMWWire("party1_b")
    c = GMWWire("party2_c")
    d = GMWWire("party2_d")

    # Intermediate wires
    not_a = GMWWire("not_a")
    not_d = GMWWire("not_d")
    left_and = GMWWire("left_and")  # NOT(a) AND b
    right_and = GMWWire("right_and")  # c AND NOT(d)

    # Output wire
    output = GMWWire("output")

    gates = [
        # Step 1: Compute NOT gates
        GMWGate("not_gate_a", GMWGateType.NOT, [a], not_a),
        GMWGate("not_gate_d", GMWGateType.NOT, [d], not_d),
        # Step 2: Compute AND gates
        GMWGate("and_left", GMWGateType.AND, [not_a, b], left_and),
        GMWGate("and_right", GMWGateType.AND, [c, not_d], right_and),
        # Step 3: Final XOR
        GMWGate("final_xor", GMWGateType.XOR, [left_and, right_and], output),
    ]

    return GMWCircuit(
        gates=gates,
        input_wires=[a, b, c, d],
        output_wires=[output],
        party1_input_wires=[a, b],
        party2_input_wires=[c, d],
    )


def create_full_adder_circuit() -> GMWCircuit:
    """
    Create a full adder circuit that adds three bits: a + b + carry_in
    Outputs: sum and carry_out

    Logic:
    sum = a XOR b XOR carry_in
    carry_out = (a AND b) OR (carry_in AND (a XOR b))

    Using De Morgan's equivalent for OR:
    carry_out = NOT(NOT(a AND b) AND NOT(carry_in AND (a XOR b)))
    """
    # Input wires
    a = GMWWire("party1_a")
    b = GMWWire("party1_b")
    carry_in = GMWWire("party2_carry_in")

    # Intermediate wires
    a_xor_b = GMWWire("a_xor_b")
    a_and_b = GMWWire("a_and_b")
    carry_and_xor = GMWWire("carry_and_xor")
    not_ab = GMWWire("not_ab")
    not_carry_xor = GMWWire("not_carry_xor")
    nor_result = GMWWire("nor_result")

    # Output wires
    sum_out = GMWWire("sum")
    carry_out = GMWWire("carry_out")

    gates = [
        # Compute sum = a XOR b XOR carry_in
        GMWGate("xor_ab", GMWGateType.XOR, [a, b], a_xor_b),
        GMWGate("sum_gate", GMWGateType.XOR, [a_xor_b, carry_in], sum_out),
        # Compute carry_out using De Morgan's law
        GMWGate("and_ab", GMWGateType.AND, [a, b], a_and_b),
        GMWGate("and_carry_xor", GMWGateType.AND, [carry_in, a_xor_b], carry_and_xor),
        # Apply De Morgan's: NOT(NOT(a AND b) AND NOT(carry_in AND (a XOR b)))
        GMWGate("not_ab_gate", GMWGateType.NOT, [a_and_b], not_ab),
        GMWGate("not_carry_xor_gate", GMWGateType.NOT, [carry_and_xor], not_carry_xor),
        GMWGate("nor_gate", GMWGateType.AND, [not_ab, not_carry_xor], nor_result),
        GMWGate("carry_out_gate", GMWGateType.NOT, [nor_result], carry_out),
    ]

    return GMWCircuit(
        gates=gates,
        input_wires=[a, b, carry_in],
        output_wires=[sum_out, carry_out],
        party1_input_wires=[a, b],
        party2_input_wires=[carry_in],
    )


def test_complex_boolean_circuit():
    """Test the complex Boolean circuit f(a,b,c,d) = (NOT(a) AND b) XOR (c AND NOT(d))"""
    print("\n--- Testing Complex Boolean Circuit ---")
    print("Computing: f(a,b,c,d) = (NOT(a) AND b) XOR (c AND NOT(d))")

    circuit = create_complex_boolean_circuit()

    # Test a few key cases
    test_cases = [
        (False, True, True, False),  # (NOT(0) AND 1) XOR (1 AND NOT(0)) = 1 XOR 1 = 0
        (True, True, False, False),  # (NOT(1) AND 1) XOR (0 AND NOT(0)) = 0 XOR 0 = 0
        (False, False, True, True),  # (NOT(0) AND 0) XOR (1 AND NOT(1)) = 0 XOR 0 = 0
        (True, False, True, False),  # (NOT(1) AND 0) XOR (1 AND NOT(0)) = 0 XOR 1 = 1
    ]

    for a_val, b_val, c_val, d_val in test_cases:
        print(f"\n🧮 Test: a={a_val}, b={b_val}, c={c_val}, d={d_val}")

        party1_inputs = {
            GMWWire("party1_a"): a_val,
            GMWWire("party1_b"): b_val,
        }

        party2_inputs = {
            GMWWire("party2_c"): c_val,
            GMWWire("party2_d"): d_val,
        }

        protocol = GMWProtocol(circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        output_val = result[GMWWire("output")]
        expected = (not a_val and b_val) ^ (c_val and not d_val)
        print(f"Expected: {expected}, Got: {output_val}")
        print(f"✅ Correct: {output_val == expected}")


def test_full_adder_circuit():
    """Test the full adder circuit."""
    print("\n--- Testing Full Adder Circuit ---")
    print("Computing: sum and carry_out for a + b + carry_in")

    circuit = create_full_adder_circuit()

    test_cases = [
        (False, False, False, False, False),  # 0+0+0 = 0, carry=0
        (True, False, False, True, False),  # 1+0+0 = 1, carry=0
        (True, True, False, False, True),  # 1+1+0 = 0, carry=1
        (True, True, True, True, True),  # 1+1+1 = 1, carry=1
    ]

    for a_val, b_val, carry_in_val, expected_sum, expected_carry in test_cases:
        print(f"\n🧮 Test: {int(a_val)} + {int(b_val)} + {int(carry_in_val)}")

        party1_inputs = {
            GMWWire("party1_a"): a_val,
            GMWWire("party1_b"): b_val,
        }

        party2_inputs = {
            GMWWire("party2_carry_in"): carry_in_val,
        }

        protocol = GMWProtocol(circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        sum_val = result[GMWWire("sum")]
        carry_val = result[GMWWire("carry_out")]

        arithmetic_result = int(a_val) + int(b_val) + int(carry_in_val)
        print(f"Expected: sum={expected_sum}, carry={expected_carry}")
        print(f"Got: sum={sum_val}, carry={carry_val}")
        print(
            f"Arithmetic check: {arithmetic_result} = {int(carry_val)}*2 + {int(sum_val)}"
        )
        print(f"✅ Correct: {sum_val == expected_sum and carry_val == expected_carry}")


def run_representative_tests():
    """Run tests for the 2 representative circuits that use all gate types (AND, XOR, NOT)."""
    print("🎯 Testing Representative Circuits with AND, XOR, and NOT Gates")
    print("=" * 70)

    test_complex_boolean_circuit()
    test_full_adder_circuit()

    print("\n🏆 All representative circuit tests completed!")


if __name__ == "__main__":
    # Run tests for the 2 representative circuits
    run_representative_tests()
