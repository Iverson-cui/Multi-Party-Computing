"""
GMW Secret Sharing Module

This module implements XOR-based secret sharing for the GMW protocol.
In XOR secret sharing:
- A secret bit s is shared as (s1, s2) where s = s1 ⊕ s2
- Each party holds one share
- Both shares are needed to reconstruct the secret
"""

import secrets
from typing import Dict, Tuple, List
from gmw_circuit import GMWWire


class XORSecretSharing:
    """
    Implements XOR-based secret sharing for Boolean values.
    This is the foundation of the GMW protocol's privacy guarantees.
    This class is not real. It's just an aggregation for some functions.
    """

    @staticmethod
    def share_secret(secret: bool) -> Tuple[bool, bool]:
        """
        Share a secret Boolean value using XOR sharing.

        Args:
            secret: The Boolean value to share

        Returns:
            Tuple of (share1, share2) where secret = share1 ⊕ share2
        """
        # Generate a random share for party 1
        share1 = secrets.choice([True, False])
        # Party 2's share is computed to ensure correct reconstruction
        share2 = secret ^ share1

        return share1, share2

    @staticmethod
    def reconstruct_secret(share1: bool, share2: bool) -> bool:
        """
        Reconstruct a secret from its XOR shares.

        Args:
            share1: Party 1's share
            share2: Party 2's share

        Returns:
            The original secret value
        """
        return share1 ^ share2

    @staticmethod
    def share_inputs(
        party1_inputs: Dict[GMWWire, bool], party2_inputs: Dict[GMWWire, bool]
    ) -> Tuple[Dict[GMWWire, bool], Dict[GMWWire, bool]]:
        """
        Generate XOR shares for all circuit inputs.

        Args:
            party1_inputs: Party 1's input values
            party2_inputs: Party 2's input values

        Returns:
            Tuple of (party1_shares, party2_shares) where each party gets
            shares of all inputs (both their own and the other party's)

        party1_inputs contains half the wire, the same as party2_inputs
        output party_shares contains all the wires.
        """
        party1_shares = {}
        party2_shares = {}

        # Share Party 1's inputs
        for wire, value in party1_inputs.items():
            share1, share2 = XORSecretSharing.share_secret(value)
            party1_shares[wire] = share1
            party2_shares[wire] = share2

        # Share Party 2's inputs
        for wire, value in party2_inputs.items():
            share1, share2 = XORSecretSharing.share_secret(value)
            party1_shares[wire] = share1
            party2_shares[wire] = share2

        return party1_shares, party2_shares


class GMWShareManager:
    """
    Manages secret shares during GMW protocol execution.
    Each party maintains their shares of all wire values.
    This class is used for each parties to manage their shares.
    """

    def __init__(self, party_id: int):
        """
        Initialize the share manager for a specific party.

        Args:
            party_id: 1 for Party 1, 2 for Party 2
        """
        if party_id not in [1, 2]:
            raise ValueError("party_id must be 1 or 2")

        self.party_id = party_id
        self.shares: Dict[GMWWire, bool] = {}

    def set_input_shares(self, input_shares: Dict[GMWWire, bool]):
        """Set the initial input shares for this party."""
        self.shares.update(input_shares)

    def get_share(self, wire: GMWWire) -> bool:
        """Get this party's share of a wire's value."""
        if wire not in self.shares:
            raise ValueError(f"No share available for wire {wire.wire_id}")
        return self.shares[wire]

    def set_share(self, wire: GMWWire, share: bool):
        """Set this party's share of a wire's value."""
        self.shares[wire] = share

    def evaluate_xor_gate(
        self, gate_input_wires: List[GMWWire], gate_output_wire: GMWWire
    ):
        """
        Evaluate an XOR gate locally (no communication needed).
        This function will retrieve input shares and write back output shares itself.

        For XOR gates: share_output = share_input1 ⊕ share_input2
        This works because: (a ⊕ b) = (a1 ⊕ a2) ⊕ (b1 ⊕ b2) = (a1 ⊕ b1) ⊕ (a2 ⊕ b2)
        """

        if len(gate_input_wires) != 2:
            raise ValueError("XOR gate must have exactly 2 inputs")

        # read input shares from class
        share1 = self.get_share(gate_input_wires[0])
        share2 = self.get_share(gate_input_wires[1])
        output_share = share1 ^ share2

        # write back output shares automatically
        self.set_share(gate_output_wire, output_share)
        print(f"[Party {self.party_id}] XOR gate: {share1} ⊕ {share2} = {output_share}")

    def evaluate_not_gate(self, gate_input_wire: GMWWire, gate_output_wire: GMWWire):
        """
        Evaluate a NOT gate locally (no communication needed).

        For NOT gates in GMW protocol:
        We want NOT(x) = NOT(x1 ⊕ x2) = (NOT x1) ⊕ x2 = x1 ⊕ (NOT x2)

        The standard approach is to have only Party 1 flip their share,
        while Party 2 keeps their share unchanged. This ensures:
        NOT(x) = (NOT x1) ⊕ x2

        This works because:
        - If x = 0 = x1 ⊕ x2, then NOT(x) = 1 = (NOT x1) ⊕ x2
        - If x = 1 = x1 ⊕ x2, then NOT(x) = 0 = (NOT x1) ⊕ x2
        """

        # Get input share
        input_share = self.get_share(gate_input_wire)

        # Only Party 1 flips their share, Party 2 keeps theirs unchanged
        if self.party_id == 1:
            output_share = not input_share
            print(
                f"[Party {self.party_id}] NOT gate: NOT({input_share}) = {output_share} (flipped)"
            )
        else:
            output_share = input_share
            print(
                f"[Party {self.party_id}] NOT gate: {input_share} = {output_share} (unchanged)"
            )

        self.set_share(gate_output_wire, output_share)

    def prepare_and_gate_ot_input(self, gate_input_wires: List[GMWWire]) -> int:
        """
        Prepare the OT selection input for an AND gate.

        For AND gates, we need OT where the selection is based on this party's shares.
        The selection index is computed as: (share_a << 1) | share_b

        Returns:
            An integer 0-3 representing the OT choice
            This choice is based on the shares held in hand.
        """
        if len(gate_input_wires) != 2:
            raise ValueError("AND gate must have exactly 2 inputs")

        share_a = self.get_share(gate_input_wires[0])
        share_b = self.get_share(gate_input_wires[1])

        # Convert shares to selection index: 00=0, 01=1, 10=2, 11=3
        selection = (int(share_a) << 1) | int(share_b)

        print(
            f"[Party {self.party_id}] AND gate OT selection: ({share_a}, {share_b}) -> {selection}"
        )
        return selection

    def get_reconstruction_shares(
        self, output_wires: List[GMWWire]
    ) -> Dict[GMWWire, bool]:
        """
        Get this party's shares of the output wires for final reconstruction.
        Give output wires and it will return the shares it has for these wires.
        """
        return {wire: self.get_share(wire) for wire in output_wires}


def test_xor_secret_sharing():
    """Test the XOR secret sharing functionality."""
    print("Testing XOR Secret Sharing")
    print("=" * 40)

    # Test basic sharing and reconstruction
    test_secrets = [True, False, True, True, False]

    for i, secret in enumerate(test_secrets):
        share1, share2 = XORSecretSharing.share_secret(secret)
        reconstructed = XORSecretSharing.reconstruct_secret(share1, share2)

        print(
            f"Test {i+1}: secret={secret}, shares=({share1}, {share2}), reconstructed={reconstructed}"
        )
        assert reconstructed == secret, f"Reconstruction failed for test {i+1}"

    print("✅ All secret sharing tests passed!")

    # Test input sharing for a circuit
    print("\nTesting circuit input sharing:")

    from gmw_circuit import create_gmw_and_circuit

    circuit = create_gmw_and_circuit()

    party1_inputs = {GMWWire("party1_input"): True}
    party2_inputs = {GMWWire("party2_input"): False}

    party1_shares, party2_shares = XORSecretSharing.share_inputs(
        party1_inputs, party2_inputs
    )

    print(f"Party 1 inputs: {party1_inputs}")
    print(f"Party 2 inputs: {party2_inputs}")
    print(f"Party 1 shares: {party1_shares}")
    print(f"Party 2 shares: {party2_shares}")

    # Verify reconstruction
    for wire in party1_inputs:
        original = party1_inputs[wire]
        reconstructed = XORSecretSharing.reconstruct_secret(
            party1_shares[wire], party2_shares[wire]
        )
        print(
            f"Wire {wire.wire_id}: original={original}, reconstructed={reconstructed}"
        )
        assert reconstructed == original

    for wire in party2_inputs:
        original = party2_inputs[wire]
        reconstructed = XORSecretSharing.reconstruct_secret(
            party1_shares[wire], party2_shares[wire]
        )
        print(
            f"Wire {wire.wire_id}: original={original}, reconstructed={reconstructed}"
        )
        assert reconstructed == original

    print("✅ Circuit input sharing tests passed!")


if __name__ == "__main__":
    test_xor_secret_sharing()
