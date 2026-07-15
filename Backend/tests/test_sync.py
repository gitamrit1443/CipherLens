"""Sync (non-async) unit tests for security/encryption module."""
import sys, os, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
os.environ['APP_ENV'] = 'testing'
os.environ['FIELD_ENCRYPTION_KEY'] = 'test-field-key-for-testing-min-32c!'
import pytest

def test_field_encryption_roundtrip():
    from security.encryption import encrypt_field, decrypt_field
    for p in ["hello", "JBSWY3DPEHPK3PXP", "user@example.com"]:
        assert decrypt_field(encrypt_field(p)) == p

def test_field_encryption_random_nonce():
    from security.encryption import encrypt_field
    assert len({encrypt_field("secret") for _ in range(5)}) == 5

def test_field_encryption_tamper_detection():
    from security.encryption import encrypt_field, decrypt_field
    enc = encrypt_field("sensitive")
    raw = bytearray(base64.b64decode(enc))
    raw[5] ^= 0xFF
    with pytest.raises(ValueError):
        decrypt_field(base64.b64encode(bytes(raw)).decode())

def test_constant_time_compare():
    from security.encryption import safe_compare
    assert safe_compare("abc","abc") and not safe_compare("abc","abd")


# ═══════════════════════════════════════════════════════════════════════════
# IMAGES CRUD
# ═══════════════════════════════════════════════════════════════════════════
