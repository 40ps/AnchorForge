import pytest
import os
import hashlib
import json
from unittest.mock import patch, mock_open
from datetime import datetime
from anchorforge.utils import get_content_from_source, hash_file_async, read_api_usage

def test_get_content_from_source_direct_string():
    """
    Ensure that a simple string is returned as is.
    """
    content = "Hello AnchorForge"
    assert get_content_from_source(content) == content

def test_get_content_from_source_none():
    """
    Ensure that None input returns None.
    """
    assert get_content_from_source(None) is None

def test_get_content_from_source_file(tmp_path):
    """
    Verify that providing a file path (via @ or direct path) returns file content.
    """
    # Create a temporary file
    test_file = tmp_path / "test.txt"
    test_content = "File Content"
    test_file.write_text(test_content, encoding="utf-8")
    
    # Test with direct path
    assert get_content_from_source(str(test_file)) == test_content
    
    # Test with @ prefix
    assert get_content_from_source(f"@{test_file}") == test_content

@pytest.mark.asyncio
async def test_hash_file_async(tmp_path):
    """
    Verify that the async file hashing produces correct SHA-256 results.
    """
    test_file = tmp_path / "hash_me.bin"
    test_data = b"Some binary data to hash"
    test_file.write_bytes(test_data)
    
    expected_hash = hashlib.sha256(test_data).digest()
    
    result = await hash_file_async(str(test_file))
    assert result == expected_hash

@pytest.mark.asyncio
async def test_hash_file_async_not_found():
    """
    Ensure that hashing a non-existent file returns None.
    """
    result = await hash_file_async("non_existent_file.xyz")
    assert result is None

def test_read_api_usage_reset_behavior(tmp_path):
    """
    Test that API usage resets when a new month is detected.
    We mock the file path to use a temporary one.
    """
    api_file = tmp_path / "api_usage.json"
    
    # Setup data from an old month
    old_data = {
        "coingecko_monthly_count": 50,
        "last_reset_date": "2020-01-01" # Definitely in the past
    }
    api_file.write_text(json.dumps(old_data))
    
    # Patch the API_COUNTER_FILE in utils to point to our temp file
    with patch("anchorforge.utils.API_COUNTER_FILE", str(api_file)):
        data = read_api_usage()
        
        # Verify that counts are reset to 0
        assert data["coingecko_monthly_count"] == 0
        # Verify that date is updated to the first of the current month
        current_first = datetime.now().strftime('%Y-%m-01')
        assert data["last_reset_date"] == current_first
