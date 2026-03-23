import pytest
from unittest.mock import MagicMock, patch
from bsv import PrivateKey, Signature
from anchorforge.publisher import build_audit_payload_prehashed, build_audit_payload
from anchorforge import core_defs

# A test WIF (Testnet) - No real funds here, just for logic testing
TEST_WIF = "cTnxoGvRS9pS7Y7YhXkG5XvGqKqGqKqGqKqGqKqGqKqGqKqGqKqG"

def test_build_audit_payload_prehashed_valid():
    """
    Test building an ECDSA audit payload from a precomputed hash.
    Verifies that the returned list contains the correct tags and data.
    Accepts both bytes and Signature objects as the SDK might return either.
    """
    test_hash = bytes.fromhex("00" * 32)
    
    # We need a valid WIF for the PrivateKey constructor
    priv = PrivateKey()
    test_wif = priv.to_wif()
    
    payload = build_audit_payload_prehashed(test_hash, test_wif)
    
    # Expected structure: [Mode, Hash, Signature, PubKey]
    assert len(payload) == 4
    assert payload[0] == core_defs.AUDIT_MODE_EC
    assert payload[1] == test_hash
    # Signature should be bytes or a Signature object (which the SDK serializes later)
    assert isinstance(payload[2], (bytes, Signature))
    # PubKey should be bytes and serialized
    assert isinstance(payload[3], bytes)

def test_build_audit_payload_integration():
    """
    Test the full flow from string data to payload.
    """
    data = "Test Audit Entry"
    priv = PrivateKey()
    test_wif = priv.to_wif()
    
    payload = build_audit_payload(data, test_wif)
    
    assert payload[0] == core_defs.AUDIT_MODE_EC
    # Verify that the hash in the payload matches the hash of our data
    from bsv.hash import sha256
    expected_hash = sha256(data.encode('utf-8'))
    assert payload[1] == expected_hash

def test_build_audit_payload_invalid_wif():
    """
    Ensure that an invalid WIF raises an appropriate error (or handled by bsv-sdk).
    """
    test_hash = bytes.fromhex("00" * 32)
    invalid_wif = "not-a-wif"
    
    with pytest.raises(Exception): # bsv-sdk usually raises ValueError or similar
        build_audit_payload_prehashed(test_hash, invalid_wif)

@patch("anchorforge.publisher.PrivateKey")
def test_build_audit_payload_mocked(mock_priv_class):
    """
    Example of how to mock the PrivateKey class to avoid actual cryptography 
    if we just want to test the payload assembly logic.
    """
    # Setup mocks
    mock_priv = MagicMock()
    mock_pub = MagicMock()
    mock_priv_class.return_value = mock_priv
    mock_priv.public_key.return_value = mock_pub
    
    mock_pub.serialize.return_value = b"mock-pubkey"
    mock_priv.sign.return_value = b"mock-signature"
    mock_pub.verify.return_value = True
    
    test_hash = b"123" * 10 + b"12" # 32 bytes
    payload = build_audit_payload_prehashed(test_hash, "some-wif")
    
    assert payload == [
        core_defs.AUDIT_MODE_EC,
        test_hash,
        b"mock-signature",
        b"mock-pubkey"
    ]
