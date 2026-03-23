import pytest
import os
import sys
from bsv import hash256
from anchorforge.core_defs import verify_merkle_path

def test_verify_merkle_path_valid():
    """
    Test Merkle path verification with a simple, constructed example.
    In a real scenario, these would be real TxIDs and Merkle Roots.
    """
    # Example data (simplified for functional testing)
    # We assume: TX_A (index 0) and TX_B (index 1) form a Merkle Root.
    tx_a = "00" * 32
    tx_b = "11" * 32
    
    # Manually calculate the expected root (Double-SHA256 of TX_A + TX_B)
    node_a = bytes.fromhex(tx_a)[::-1]
    node_b = bytes.fromhex(tx_b)[::-1]
    expected_root = hash256(node_a + node_b)[::-1].hex()
    
    # The path for TX_A is just TX_B
    path = [tx_b]
    
    assert verify_merkle_path(tx_a, 0, path, expected_root) is True

def test_verify_merkle_path_invalid_root():
    """
    Ensure that an incorrect root results in failure.
    """
    tx_a = "00" * 32
    path = ["11" * 32]
    wrong_root = "ff" * 32
    
    assert verify_merkle_path(tx_a, 0, path, wrong_root) is False

def test_verify_merkle_path_invalid_index():
    """
    Verify that an incorrect index causes a mismatch in hash order and failure.
    """
    tx_a = "00" * 32
    tx_b = "11" * 32
    path = [tx_b]
    
    # Calculate root for index 0
    node_a = bytes.fromhex(tx_a)[::-1]
    node_b = bytes.fromhex(tx_b)[::-1]
    expected_root_0 = hash256(node_a + node_b)[::-1].hex()
    
    # Try verifying with index 1 (which would assume TX_A is on the right)
    assert verify_merkle_path(tx_a, 1, path, expected_root_0) is False
