"""
GMW Protocol Implementation

This module implements the complete GMW protocol for secure two-party computation.
The protocol works by:
1. Secret sharing all inputs using XOR shares
2. Evaluating XOR gates locally (no communication)
3. Evaluating AND gates using 1-out-of-4 Oblivious Transfer
4. Reconstructing the final output

Key insight: AND gate evaluation uses the fact that:
(a1 ⊕ a2) ∧ (b1 ⊕ b2) = (a1 ∧ b1) ⊕ (a1 ∧ b2) ⊕ (a2 ∧ b1) ⊕ (a2 ∧ b2)
"""

import sys
import os

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
                inputs_ready = all(wire in processed_wires for wire in gate.input_wires)

                if inputs_ready:
                    if gate.gate_type == GMWGateType.XOR:
                        self._evaluate_xor_gate(gate)
                        # Mark output wire as processed
                        processed_wires.add(gate.output_wire)
                        gates_processed_this_round.append(gate)
                    elif gate.gate_type == GMWGateType.AND:
                        # AND gates are handled when Party 1 requests OT
                        # We still need to mark them as processed after OT
                        # This will be handled in provide_and_gate_ot_values
                        pass
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
                    processed_wires.add(gate.output_wire)
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
        self.share_manager.evaluate_xor_gate(gate.input_wires, gate.output_wire)

    def provide_and_gate_ot_values(self, gate: GMWGate, party1_selection: int) -> bool:
        """
        Provide OT values for AND gate evaluation.

        We compute all 4 possible output combinations and let Party 1 choose
        the one corresponding to their shares via OT.

        The 4 combinations correspond to:
        - 00: (False, False) -> output share
        - 01: (False, True)  -> output share
        - 10: (True, False)  -> output share
        - 11: (True, True)   -> output share
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
                        elif circuit_gate.gate_type == GMWGateType.AND:
                            # This shouldn't happen in proper topological order, but handle it
                            raise RuntimeError(
                                f"AND gate {gate.gate_id} depends on another AND gate {circuit_gate.gate_id}"
                            )
                        break

        # Get our shares of the input wires
        our_share_a = self.share_manager.get_share(gate.input_wires[0])
        our_share_b = self.share_manager.get_share(
            gate.input_wires[1]
        )  # Compute all 4 possible output shares
        # For each combination of Party 1's shares (a1, b1), compute the result
        ot_values = []

        # TODO: This share logic need to be polished
        for party1_a in [False, True]:
            for party1_b in [False, True]:
                # Compute: (party1_a ∧ party1_b) ⊕ (party1_a ∧ our_share_b) ⊕ (our_share_a ∧ party1_b) ⊕ (our_share_a ∧ our_share_b)
                term1 = party1_a & party1_b
                term2 = party1_a & our_share_b
                term3 = our_share_a & party1_b
                term4 = our_share_a & our_share_b

                # Our share of the AND result
                our_output_share = term1 ^ term2 ^ term3 ^ term4
                ot_values.append(our_output_share)

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
        chosen_value = chosen_value_str == "True"

        # Set our share of the output
        self.share_manager.set_share(gate.output_wire, ot_values[party1_selection])

        print(
            f"[Party 2] AND gate {gate.gate_id} our share: {ot_values[party1_selection]}"
        )

        return chosen_value


class GMWProtocol:
    """
    Main GMW protocol coordinator.
    Manages the complete protocol execution between two parties.
    """

    def __init__(self, circuit: GMWCircuit):
        self.circuit = circuit
        self.party1 = GMWParty1(circuit)
        self.party2 = GMWParty2(circuit)
        self.party1.connect_to_party2(self.party2)

    def execute_protocol(
        self, party1_inputs: Dict[GMWWire, bool], party2_inputs: Dict[GMWWire, bool]
    ) -> Dict[GMWWire, bool]:
        """
        Execute the complete GMW protocol.

        Returns:
            The final output values (reconstructed from shares)
        """
        print("🔐 Starting GMW Protocol Execution")
        print("=" * 50)

        # Set inputs
        self.party1.set_inputs(party1_inputs)
        self.party2.set_inputs(party2_inputs)

        # Phase 1: Input sharing
        # Both parties have all wire shares in this phase.
        print("\n📤 Phase 1: Input Sharing")
        party2_shares = self.party1.share_inputs(party2_inputs)
        self.party2.receive_input_shares(party2_shares)

        # Phase 2: Circuit evaluation
        # XOR gate: Both parties need to process it to get their own shares
        # AND gate: Party 1 is the OT receiver and propose evaluation requirement.
        print("\n⚙️  Phase 2: Circuit Evaluation")
        party1_output_shares = self.party1.evaluate_circuit()
        party2_output_shares = self.party2.evaluate_circuit()

        # Phase 3: Output reconstruction
        print("\n🔓 Phase 3: Output Reconstruction")
        final_outputs = {}

        for wire in self.circuit.output_wires:
            share1 = party1_output_shares[wire]
            share2 = party2_output_shares[wire]
            final_value = XORSecretSharing.reconstruct_secret(share1, share2)
            final_outputs[wire] = final_value

            print(
                f"Output wire {wire.wire_id}: shares=({share1}, {share2}) -> value={final_value}"
            )

        print("\n✅ GMW Protocol Complete!")
        print(f"Final outputs: {final_outputs}")

        return final_outputs


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


def demonstrate_gmw_protocol():
    """Demonstrate the GMW protocol with various circuits."""
    print("=" * 70)
    print("GMW PROTOCOL DEMONSTRATION")
    print("=" * 70)

    # Import circuit examples
    from gmw_circuit import (
        create_gmw_and_circuit,
        create_gmw_xor_circuit,
        create_gmw_adder_circuit,
    )

    # Example 1: Simple AND circuit
    print("\n--- Example 1: AND Circuit ---")
    print("Computing: party1_input AND party2_input")

    circuit = create_gmw_and_circuit()
    protocol = GMWProtocol(circuit)

    party1_inputs = {GMWWire("party1_input"): True}
    party2_inputs = {GMWWire("party2_input"): False}

    print(f"Party 1 input: {party1_inputs}")
    print(f"Party 2 input: {party2_inputs}")

    result = protocol.execute_protocol(party1_inputs, party2_inputs)
    expected = circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})

    print(f"GMW result: {result}")
    print(f"Expected: {expected}")
    print(f"Correct: {result == expected}")

    # Example 2: XOR circuit
    print("\n--- Example 2: XOR Circuit ---")
    print("Computing: party1_input XOR party2_input")

    circuit = create_gmw_xor_circuit()
    protocol = GMWProtocol(circuit)

    party1_inputs = {GMWWire("party1_input"): True}
    party2_inputs = {GMWWire("party2_input"): True}

    print(f"Party 1 input: {party1_inputs}")
    print(f"Party 2 input: {party2_inputs}")

    result = protocol.execute_protocol(party1_inputs, party2_inputs)
    expected = circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})

    print(f"GMW result: {result}")
    print(f"Expected: {expected}")
    print(f"Correct: {result == expected}")

    # Example 3: 1-bit Full Adder
    print("\n--- Example 3: 1-bit Full Adder ---")
    print("Computing: (sum, carry) = a + b + cin")

    circuit = create_gmw_adder_circuit()
    protocol = GMWProtocol(circuit)

    party1_inputs = {
        GMWWire("input_a"): True,  # a = 1
        GMWWire("input_cin"): True,  # cin = 1
    }
    party2_inputs = {GMWWire("input_b"): True}  # b = 1

    print("Party 1 inputs: a=1, cin=1")
    print("Party 2 inputs: b=1")
    print("Expected: 1+1+1 = sum=1, carry=1")

    result = protocol.execute_protocol(party1_inputs, party2_inputs)
    expected = circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})

    print(f"GMW result: {result}")
    print(f"Expected: {expected}")
    print(f"Correct: {result == expected}")

    # Example 4: 2-bit Multiplier (Complex test)
    test_2bit_multiplier()

    # Statistics
    print("\n" + "=" * 70)
    print("PROTOCOL STATISTICS")
    print("=" * 70)

    circuits = [
        ("AND Circuit", create_gmw_and_circuit()),
        ("XOR Circuit", create_gmw_xor_circuit()),
        ("1-bit Adder", create_gmw_adder_circuit()),
        ("2-bit Multiplier", create_2bit_multiplier_circuit()),
    ]

    for name, circuit in circuits:
        and_gates = len(circuit.get_and_gates())
        xor_gates = len(circuit.get_xor_gates())
        total_gates = len(circuit.gates)

        print(
            f"{name:15} : {total_gates:3d} gates ({and_gates:2d} AND, {xor_gates:2d} XOR)"
        )
        print(f"                 Communication rounds for AND gates: {and_gates}")


if __name__ == "__main__":
    demonstrate_gmw_protocol()
