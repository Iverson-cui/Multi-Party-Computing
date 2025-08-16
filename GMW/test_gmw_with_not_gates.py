#!/usr/bin/env python3
"""
Test script for GMW protocol with NOT gate support and timing.

This script demonstrates:
1. NOT gate functionality in GMW circuits
2. NAND gate construction using AND + NOT
3. Timing measurements for protocol execution
4. Comprehensive testing of circuit evaluation
"""

import time
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(__file__))

from gmw_circuit import (
    GMWCircuit,
    GMWWire,
    GMWGate,
    GMWGateType,
    create_gmw_and_circuit,
    create_gmw_xor_circuit,
    create_gmw_adder_circuit,
    create_gmw_not_circuit,
    create_gmw_nand_circuit,
)
from gmw_shares import XORSecretSharing, GMWShareManager
from gmw_protocol import GMWParty1, GMWParty2


class TimedGMWProtocol:
    """
    Enhanced GMW protocol with timing measurements and NOT gate support.
    """

    def __init__(self, circuit: GMWCircuit):
        self.circuit = circuit
        self.party1 = GMWParty1(circuit)
        self.party2 = GMWParty2(circuit)
        self.party1.connect_to_party2(self.party2)

        # Timing statistics
        self.timing_stats = {}

    def execute_protocol(self, party1_inputs: dict, party2_inputs: dict) -> dict:
        """
        Execute the complete GMW protocol with detailed timing.

        Returns:
            Dict mapping output wires to their final Boolean values
        """
        total_start_time = time.time()

        print("\n🚀 Starting GMW Protocol with NOT Gate Support")
        print("=" * 60)

        # Phase 1: Input sharing
        print("\n📤 Phase 1: Input Sharing")
        sharing_start_time = time.time()

        self.party1.set_inputs(party1_inputs)
        self.party2.set_inputs(party2_inputs)

        party2_shares = self.party1.share_inputs(party2_inputs)
        self.party2.receive_input_shares(party2_shares)

        sharing_time = time.time() - sharing_start_time
        self.timing_stats["input_sharing"] = sharing_time
        print(f"⏱️  Input sharing: {sharing_time:.4f} seconds")

        # Phase 2: Circuit evaluation
        print("\n⚡ Phase 2: Circuit Evaluation")
        evaluation_start_time = time.time()

        party1_output_shares = self.party1.evaluate_circuit()
        party2_output_shares = self.party2.evaluate_circuit()

        evaluation_time = time.time() - evaluation_start_time
        self.timing_stats["circuit_evaluation"] = evaluation_time
        print(f"⏱️  Circuit evaluation: {evaluation_time:.4f} seconds")

        # Phase 3: Output reconstruction
        print("\n🔍 Phase 3: Output Reconstruction")
        reconstruction_start_time = time.time()

        final_outputs = {}
        for wire in self.circuit.output_wires:
            share1 = party1_output_shares[wire]
            share2 = party2_output_shares[wire]
            final_value = XORSecretSharing.reconstruct_secret(share1, share2)
            final_outputs[wire] = final_value
            print(f"   {wire.wire_id}: {share1} ⊕ {share2} = {final_value}")

        reconstruction_time = time.time() - reconstruction_start_time
        self.timing_stats["output_reconstruction"] = reconstruction_time
        print(f"⏱️  Output reconstruction: {reconstruction_time:.4f} seconds")

        total_time = time.time() - total_start_time
        self.timing_stats["total_time"] = total_time

        print(f"\n🏁 Total execution time: {total_time:.4f} seconds")
        self._print_circuit_stats()
        self._print_timing_breakdown()

        return final_outputs

    def _print_circuit_stats(self):
        """Print circuit statistics."""
        and_gates = len(self.circuit.get_and_gates())
        xor_gates = len(self.circuit.get_xor_gates())
        not_gates = len(self.circuit.get_not_gates())
        total_gates = len(self.circuit.gates)

        print(f"\n📊 Circuit Statistics:")
        print(f"   Total gates: {total_gates}")
        print(f"   AND gates: {and_gates} (require OT communication)")
        print(f"   XOR gates: {xor_gates} (local evaluation)")
        print(f"   NOT gates: {not_gates} (local evaluation)")
        print(f"   Communication rounds: {and_gates}")

    def _print_timing_breakdown(self):
        """Print timing breakdown."""
        total = self.timing_stats["total_time"]

        print(f"\n⏱️  Timing Breakdown:")
        for phase, duration in self.timing_stats.items():
            if phase != "total_time":
                percentage = (duration / total) * 100
                print(
                    f"   {phase.replace('_', ' ').title()}: {duration:.4f}s ({percentage:.1f}%)"
                )


def test_not_gate_functionality():
    """Test NOT gate functionality in detail."""
    print("\n" + "=" * 60)
    print("TESTING NOT GATE FUNCTIONALITY")
    print("=" * 60)

    # Test 1: Simple NOT gate
    print("\n🔧 Test 1: Simple NOT Circuit")
    print("Function: output = NOT(party1_input)")

    not_circuit = create_gmw_not_circuit()

    test_cases = [
        (True, "NOT(1) = 0"),
        (False, "NOT(0) = 1"),
    ]

    for input_val, description in test_cases:
        print(f"\n   Testing: {description}")

        party1_inputs = {GMWWire("party1_input"): input_val}
        party2_inputs = {}

        protocol = TimedGMWProtocol(not_circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        # Verify correctness
        expected = not_circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})
        success = result == expected

        print(f"   📊 Result: {result}")
        print(f"   📊 Expected: {expected}")
        print(f"   ✅ Correct: {success}")


def test_nand_gate_functionality():
    """Test NAND gate (AND + NOT) functionality."""
    print("\n🔧 Test 2: NAND Circuit (AND + NOT)")
    print("Function: output = NOT(party1_input AND party2_input)")

    nand_circuit = create_gmw_nand_circuit()

    truth_table = [
        (False, False, "NAND(0,0) = 1"),
        (False, True, "NAND(0,1) = 1"),
        (True, False, "NAND(1,0) = 1"),
        (True, True, "NAND(1,1) = 0"),
    ]

    for p1_val, p2_val, description in truth_table:
        print(f"\n   Testing: {description}")

        party1_inputs = {GMWWire("party1_input"): p1_val}
        party2_inputs = {GMWWire("party2_input"): p2_val}

        protocol = TimedGMWProtocol(nand_circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        # Verify correctness
        expected = nand_circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})
        success = result == expected

        print(f"   📊 Result: {result}")
        print(f"   📊 Expected: {expected}")
        print(f"   ✅ Correct: {success}")


def test_circuit_with_mixed_gates():
    """Test a circuit that mixes all gate types."""
    print("\n🔧 Test 3: Mixed Gate Circuit")
    print("Function: Complex circuit with AND, XOR, and NOT gates")

    # Create a custom circuit: output = NOT(a XOR b) AND c
    # This should output 1 only when (a XOR b) is 0 AND c is 1
    # i.e., when a==b AND c==1

    a_wire = GMWWire("input_a")
    b_wire = GMWWire("input_b")
    c_wire = GMWWire("input_c")
    xor_out = GMWWire("xor_output")
    not_out = GMWWire("not_output")
    final_out = GMWWire("final_output")

    gates = [
        GMWGate("xor_ab", GMWGateType.XOR, [a_wire, b_wire], xor_out),
        GMWGate("not_xor", GMWGateType.NOT, [xor_out], not_out),
        GMWGate("and_final", GMWGateType.AND, [not_out, c_wire], final_out),
    ]

    mixed_circuit = GMWCircuit(
        gates=gates,
        input_wires=[a_wire, b_wire, c_wire],
        output_wires=[final_out],
        party1_input_wires=[a_wire, c_wire],
        party2_input_wires=[b_wire],
    )

    test_cases = [
        (False, False, True, "NOT(0⊕0) AND 1 = 1 AND 1 = 1"),
        (True, True, True, "NOT(1⊕1) AND 1 = 1 AND 1 = 1"),
        (False, True, True, "NOT(0⊕1) AND 1 = 0 AND 1 = 0"),
        (True, False, True, "NOT(1⊕0) AND 1 = 0 AND 1 = 0"),
        (False, False, False, "NOT(0⊕0) AND 0 = 1 AND 0 = 0"),
    ]

    for a_val, b_val, c_val, description in test_cases:
        print(f"\n   Testing: {description}")

        party1_inputs = {GMWWire("input_a"): a_val, GMWWire("input_c"): c_val}
        party2_inputs = {GMWWire("input_b"): b_val}

        protocol = TimedGMWProtocol(mixed_circuit)
        result = protocol.execute_protocol(party1_inputs, party2_inputs)

        # Verify correctness
        expected = mixed_circuit.evaluate_plaintext({**party1_inputs, **party2_inputs})
        success = result == expected

        print(f"   📊 Result: {result}")
        print(f"   📊 Expected: {expected}")
        print(f"   ✅ Correct: {success}")


def benchmark_circuits():
    """Benchmark different circuit types."""
    print("\n" + "=" * 60)
    print("CIRCUIT PERFORMANCE BENCHMARK")
    print("=" * 60)

    circuits = [
        (
            "AND Circuit",
            create_gmw_and_circuit(),
            {GMWWire("party1_input"): True},
            {GMWWire("party2_input"): False},
        ),
        (
            "XOR Circuit",
            create_gmw_xor_circuit(),
            {GMWWire("party1_input"): True},
            {GMWWire("party2_input"): False},
        ),
        ("NOT Circuit", create_gmw_not_circuit(), {GMWWire("party1_input"): True}, {}),
        (
            "NAND Circuit",
            create_gmw_nand_circuit(),
            {GMWWire("party1_input"): True},
            {GMWWire("party2_input"): False},
        ),
        (
            "Adder Circuit",
            create_gmw_adder_circuit(),
            {GMWWire("input_a"): True, GMWWire("input_cin"): False},
            {GMWWire("input_b"): True},
        ),
    ]

    results = []

    for name, circuit, p1_inputs, p2_inputs in circuits:
        print(f"\n🏃 Benchmarking {name}...")

        # Run multiple times and average
        times = []
        for i in range(3):
            protocol = TimedGMWProtocol(circuit)
            start = time.time()
            protocol.execute_protocol(p1_inputs, p2_inputs)
            end = time.time()
            times.append(end - start)

        avg_time = sum(times) / len(times)
        and_gates = len(circuit.get_and_gates())
        xor_gates = len(circuit.get_xor_gates())
        not_gates = len(circuit.get_not_gates())

        results.append((name, avg_time, and_gates, xor_gates, not_gates))

    # Print benchmark results
    print(f"\n📈 Benchmark Results (average of 3 runs):")
    print("-" * 70)
    print(f"{'Circuit':<15} {'Time (s)':<10} {'AND':<5} {'XOR':<5} {'NOT':<5}")
    print("-" * 70)

    for name, avg_time, and_gates, xor_gates, not_gates in results:
        print(
            f"{name:<15} {avg_time:<10.4f} {and_gates:<5} {xor_gates:<5} {not_gates:<5}"
        )

    print("-" * 70)


def main():
    """Main test runner."""
    print("🧪 GMW PROTOCOL WITH NOT GATES - COMPREHENSIVE TESTING")
    print("=" * 70)
    print("This test suite demonstrates:")
    print("• NOT gate implementation in GMW protocol")
    print("• NAND gate construction (AND + NOT)")
    print("• Mixed gate circuits with timing measurements")
    print("• Performance benchmarking")

    try:
        # Test NOT gate functionality
        test_not_gate_functionality()

        # Test NAND gate functionality
        test_nand_gate_functionality()

        # Test mixed gates
        test_circuit_with_mixed_gates()

        # Benchmark performance
        benchmark_circuits()

        print(f"\n🎉 All tests completed successfully!")
        print("=" * 70)

    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    main()
