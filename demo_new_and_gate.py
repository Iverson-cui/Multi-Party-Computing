#!/usr/bin/env python3
"""
Demonstration of the new AND gate OT setting for GMW protocol.
This shows how the modified implementation works according to the attachment.
"""

import secrets
from typing import Dict, List


class GMWWire:
    def __init__(self, wire_id):
        self.wire_id = wire_id

    def __repr__(self):
        return f"Wire({self.wire_id})"

    def __eq__(self, other):
        return isinstance(other, GMWWire) and self.wire_id == other.wire_id

    def __hash__(self):
        return hash(self.wire_id)


class SimpleShareManager:
    """Simplified share manager for demonstration."""

    def __init__(self, party_id: int):
        self.party_id = party_id
        self.shares: Dict[GMWWire, bool] = {}

    def set_share(self, wire: GMWWire, share: bool):
        self.shares[wire] = share

    def get_share(self, wire: GMWWire) -> bool:
        return self.shares[wire]


def demonstrate_new_and_gate_ot():
    """
    Demonstrate the new AND gate OT setting from the attachment.
    """
    print("=" * 70)
    print("DEMONSTRATION: New AND Gate OT Setting for GMW Protocol")
    print("=" * 70)
    print()

    print("Setting from attachment:")
    print("- Chooser (Party 1) inputs shares x1, y1")
    print("- Sender (Party 2) chooses random output share z2")
    print("- Sender provides 4 OT values such that chooser gets:")
    print("  z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2))")
    print("- Result: z1 ⊕ z2 = (x1 ⊕ x2) ∧ (y1 ⊕ y2)")
    print()

    # Example: Party 1 wants to compute AND of their bit with Party 2's bit
    print("Example: Party 1 has input A=1, Party 2 has input B=0")
    print("Goal: Compute A ∧ B = 1 ∧ 0 = 0")
    print()

    # Step 1: Secret sharing
    print("Step 1: Secret Sharing")
    print("-" * 30)

    # Party 1's input
    party1_input = True  # A = 1
    x1 = secrets.choice([True, False])  # Party 1's share of A
    x2 = party1_input ^ x1  # Party 2's share of A

    # Party 2's input
    party2_input = False  # B = 0
    y1 = secrets.choice([True, False])  # Party 1's share of B
    y2 = party2_input ^ y1  # Party 2's share of B

    print(f"Party 1's input A: {party1_input}")
    print(f"  A = x1 ⊕ x2 = {x1} ⊕ {x2} = {x1 ^ x2}")
    print(f"  Party 1 has share x1 = {x1}")
    print(f"  Party 2 has share x2 = {x2}")
    print()

    print(f"Party 2's input B: {party2_input}")
    print(f"  B = y1 ⊕ y2 = {y1} ⊕ {y2} = {y1 ^ y2}")
    print(f"  Party 1 has share y1 = {y1}")
    print(f"  Party 2 has share y2 = {y2}")
    print()

    # Step 2: AND gate evaluation using new OT setting
    print("Step 2: AND Gate Evaluation (New OT Setting)")
    print("-" * 50)

    # Party 1's OT selection based on their shares
    selection = (int(x1) << 1) | int(y1)
    print(f"Party 1's OT selection: (x1={x1}, y1={y1}) → index {selection}")
    print()

    # Party 2 chooses random output share
    z2 = secrets.choice([True, False])
    print(f"Party 2 chooses random output share z2 = {z2}")
    print()

    # Party 2 computes OT values
    print("Party 2 computes OT values:")
    ot_values = []
    for i, (x1_choice, y1_choice) in enumerate(
        [(False, False), (False, True), (True, False), (True, True)]
    ):
        # Compute AND result for this combination
        and_result = (x1_choice ^ x2) & (y1_choice ^ y2)

        # Party 1's share: z1 = z2 ⊕ and_result
        z1 = z2 ^ and_result
        ot_values.append(z1)

        print(f"  Index {i} (x1={x1_choice}, y1={y1_choice}): ")
        print(
            f"    AND result = ({x1_choice} ⊕ {x2}) ∧ ({y1_choice} ⊕ {y2}) = {x1_choice ^ x2} ∧ {y1_choice ^ y2} = {and_result}"
        )
        print(f"    z1 = z2 ⊕ AND = {z2} ⊕ {and_result} = {z1}")
    print()

    # Party 1 receives their share via OT
    z1_received = ot_values[selection]
    print(f"Party 1 receives z1 = {z1_received} (from OT index {selection})")
    print()

    # Step 3: Reconstruction
    print("Step 3: Result Reconstruction")
    print("-" * 35)

    final_result = z1_received ^ z2
    expected_result = party1_input & party2_input

    print(f"Final result = z1 ⊕ z2 = {z1_received} ⊕ {z2} = {final_result}")
    print(f"Expected: {party1_input} ∧ {party2_input} = {expected_result}")
    print()

    success = final_result == expected_result
    print(f"✅ Correct!" if success else "❌ Error!")
    print()

    # Show the key insight
    print("Key Insight:")
    print("-" * 20)
    print("The new OT setting is more efficient because:")
    print("1. Party 2 first chooses a random share z2")
    print("2. Then computes OT values to ensure correct reconstruction")
    print("3. This follows the standard GMW protocol structure")
    print("4. Only 2 messages needed (like mentioned in attachment)")

    return success


def compare_with_old_approach():
    """Compare the new approach with the old one conceptually."""
    print("\n" + "=" * 70)
    print("COMPARISON: New vs Old Approach")
    print("=" * 70)
    print()

    print("OLD APPROACH (from original code):")
    print("- Party 2 computes all 4 possible output combinations")
    print("- Uses complex formula: (a1∧b1) ⊕ (a1∧b2) ⊕ (a2∧b1) ⊕ (a2∧b2)")
    print("- Party 2's share is one of the computed values")
    print("- Less intuitive and more complex")
    print()

    print("NEW APPROACH (from attachment):")
    print("- Party 2 first chooses random share z2")
    print("- Computes OT values: z1 = z2 ⊕ ((x1 ⊕ x2) ∧ (y1 ⊕ y2))")
    print("- Ensures z1 ⊕ z2 = correct AND result")
    print("- More intuitive and follows standard GMW structure")
    print("- Better matches the theoretical description")
    print()

    print("ADVANTAGES of new approach:")
    print("✅ Clearer separation of concerns")
    print("✅ Random share generation first")
    print("✅ Simpler correctness verification")
    print("✅ Better matches literature")
    print("✅ More efficient preprocessing (as mentioned in attachment)")


if __name__ == "__main__":
    # Run multiple demonstrations
    print("Running multiple test cases...")
    print()

    success_count = 0
    total_tests = 5

    for i in range(total_tests):
        print(f"\n{'🧮 TEST CASE ' + str(i+1):=^70}")
        if demonstrate_new_and_gate_ot():
            success_count += 1

    compare_with_old_approach()

    print(f"\n{'SUMMARY':=^70}")
    print(f"Successful tests: {success_count}/{total_tests}")
    print(
        "✅ All tests passed!"
        if success_count == total_tests
        else "❌ Some tests failed!"
    )
