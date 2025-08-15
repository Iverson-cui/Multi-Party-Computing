"""
GMW Protocol Package

This package implements the GMW protocol for secure two-party computation.

Modules:
- gmw_circuit: Circuit representation and example circuits
- gmw_shares: XOR secret sharing functionality
- gmw_protocol: Main protocol implementation

Usage:
    from GMW import GMWProtocol, create_gmw_and_circuit

    circuit = create_gmw_and_circuit()
    protocol = GMWProtocol(circuit)
    result = protocol.execute_protocol(party1_inputs, party2_inputs)
"""

from .gmw_circuit import (
    GMWCircuit,
    GMWWire,
    GMWGate,
    GMWGateType,
    create_gmw_and_circuit,
    create_gmw_xor_circuit,
    create_gmw_adder_circuit,
    create_gmw_4bit_equality_circuit,
)

from .gmw_shares import XORSecretSharing, GMWShareManager

from .gmw_protocol import GMWParty1, GMWParty2, GMWProtocol

__all__ = [
    "GMWCircuit",
    "GMWWire",
    "GMWGate",
    "GMWGateType",
    "create_gmw_and_circuit",
    "create_gmw_xor_circuit",
    "create_gmw_adder_circuit",
    "create_gmw_4bit_equality_circuit",
    "XORSecretSharing",
    "GMWShareManager",
    "GMWParty1",
    "GMWParty2",
    "GMWProtocol",
]
