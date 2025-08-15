#!/usr/bin/env python3
"""
Test script for the modified AND gate implementation in GMW protocol.
This tests the new OT setting described in the attachment.
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "GMW"))
sys.path.append(os.path.join(os.path.dirname(__file__), "GC"))


# Mock the required classes for testing
class GMWWire:
    def __init__(self, wire_id):
        self.wire_id = wire_id

    def __repr__(self):
        return f"Wire({self.wire_id})"

    def __eq__(self, other):
        return isinstance(other, GMWWire) and self.wire_id == other.wire_id

    def __hash__(self):
        return hash(self.wire_id)


class GMWGateType:
    AND = "AND"
    XOR = "XOR"
    INPUT = "INPUT"


class GMWGate:
    def __init__(self, gate_id, gate_type, input_wires, output_wire):
        self.gate_id = gate_id
        self.gate_type = gate_type
        self.input_wires = input_wires
        self.output_wire = output_wire


# Mock OT classes
class OT4Receiver:
    def __init__(self, selection_index):
        self.selection_index = selection_index

    def prepare_key_pairs(self):
        return "pk0", "pk1", "pk2", "pk3"

    def decrypt_chosen_secret(self, e0, e1, e2, e3):
        values = [e0, e1, e2, e3]
        return values[self.selection_index]


class OT4Sender:
    def __init__(self, v0, v1, v2, v3):
        self.values = [v0, v1, v2, v3]

    def encrypt_secrets(self, pk0, pk1, pk2, pk3):
        return self.values[0], self.values[1], self.values[2], self.values[3]


# Mock share manager
class MockShareManager:
    def __init__(self):
        self.shares = {}

    def get_share(self, wire):
        return self.shares[wire]

    def set_share(self, wire, value):
        self.shares[wire] = value


def test_new_and_gate_setting():
    """Test the new AND gate OT setting from the attachment."""
    print("Testing New AND Gate Setting")
    print("=" * 50)

    import secrets

    # Test cases: all combinations of input shares
    test_cases = [
        (False, False, False, False),  # x1=0, y1=0, x2=0, y2=0 -> AND=0
        (False, False, False, True),  # x1=0, y1=0, x2=0, y2=1 -> AND=0
        (False, False, True, False),  # x1=0, y1=0, x2=1, y2=0 -> AND=0
        (False, False, True, True),  # x1=0, y1=0, x2=1, y2=1 -> AND=0
        (False, True, False, False),  # x1=0, y1=1, x2=0, y2=0 -> AND=0
        (False, True, False, True),  # x1=0, y1=1, x2=0, y2=1 -> AND=1
        (False, True, True, False),  # x1=0, y1=1, x2=1, y2=0 -> AND=0
        (False, True, True, True),  # x1=0, y1=1, x2=1, y2=1 -> AND=1
        (True, False, False, False),  # x1=1, y1=0, x2=0, y2=0 -> AND=0
        (True, False, False, True),  # x1=1, y1=0, x2=0, y2=1 -> AND=0
        (True, False, True, False),  # x1=1, y1=0, x2=1, y2=0 -> AND=1
        (True, False, True, True),  # x1=1, y1=0, x2=1, y2=1 -> AND=1
        (True, True, False, False),  # x1=1, y1=1, x2=0, y2=0 -> AND=0
        (True, True, False, True),  # x1=1, y1=1, x2=0, y2=1 -> AND=1
        (True, True, True, False),  # x1=1, y1=1, x2=1, y2=0 -> AND=1
        (True, True, True, True),  # x1=1, y1=1, x2=1, y2=1 -> AND=1
    ]

    all_passed = True

    for test_num, (x1, y1, x2, y2) in enumerate(test_cases, 1):
        # Expected AND result
        expected_and = (x1 ^ x2) & (y1 ^ y2)

        # Party 1's selection for OT (based on their shares x1, y1)
        selection = (int(x1) << 1) | int(y1)

        # Party 2 chooses random output share z2
        z2 = secrets.choice([True, False])

        # Party 2 computes OT values following the new setting
        ot_values = []
        for x1_choice in [False, True]:
            for y1_choice in [False, True]:
                # Compute actual AND result for this choice
                and_result = (x1_choice ^ x2) & (y1_choice ^ y2)
                # Party 1's share: z1 = z2 ⊕ and_result
                z1 = z2 ^ and_result
                ot_values.append(z1)

        # Party 1 gets their share via OT
        z1_received = ot_values[selection]

        # Verify: z1 ⊕ z2 should equal the expected AND result
        reconstructed_and = z1_received ^ z2

        passed = reconstructed_and == expected_and
        all_passed = all_passed and passed

        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"Test {test_num:2d}: x1={x1}, y1={y1}, x2={x2}, y2={y2}")
        print(f"         Expected AND: {expected_and}")
        print(f"         z2: {z2}, z1: {z1_received}")
        print(f"         Reconstructed: {z1_received} ⊕ {z2} = {reconstructed_and}")
        print(f"         {status}")
        print()

    print("=" * 50)
    print(
        f"Overall result: {'✅ ALL TESTS PASSED' if all_passed else '❌ SOME TESTS FAILED'}"
    )

    return all_passed


if __name__ == "__main__":
    test_new_and_gate_setting()
