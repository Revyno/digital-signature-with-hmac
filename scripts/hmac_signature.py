#!/usr/bin/env python3
"""
Digital Signature with HMAC SHA512
Custom implementation for secure document signing and verification
"""

import hashlib
import base64
import json
import sys

class HMACSHA512:
    """Custom HMAC-SHA512 implementation for digital signatures"""

    def __init__(self, key):
        self.key = key.encode('utf-8') if isinstance(key, str) else key
        self.block_size = 128  # SHA512 block size
        self.opad = b'\x5c' * self.block_size
        self.ipad = b'\x36' * self.block_size

    def _hash(self, data):
        """SHA512 hash function"""
        return hashlib.sha512(data).digest()

    def _xor_bytes(self, a, b):
        """XOR two byte sequences"""
        return bytes(x ^ y for x, y in zip(a, b))

    def compute(self, message):
        """Compute HMAC-SHA512"""
        # Prepare key
        if len(self.key) > self.block_size:
            key_hash = self._hash(self.key)
            key_padded = key_hash + b'\x00' * (self.block_size - len(key_hash))
        else:
            key_padded = self.key + b'\x00' * (self.block_size - len(self.key))

        # Inner hash
        inner_key = self._xor_bytes(key_padded, self.ipad)
        inner_data = inner_key + message.encode('utf-8') if isinstance(message, str) else message
        inner_hash = self._hash(inner_data)

        # Outer hash
        outer_key = self._xor_bytes(key_padded, self.opad)
        outer_data = outer_key + inner_hash
        outer_hash = self._hash(outer_data)

        return outer_hash

def generate_signature(message, secret_key):
    """Generate HMAC-SHA512 signature for digital document"""
    hmac_instance = HMACSHA512(secret_key)
    signature_bytes = hmac_instance.compute(message)
    return base64.b64encode(signature_bytes).decode('utf-8')

def verify_signature(message, signature, secret_key):
    """Verify HMAC-SHA512 signature for digital document"""
    try:
        hmac_instance = HMACSHA512(secret_key)
        expected_signature = hmac_instance.compute(message)
        expected_b64 = base64.b64encode(expected_signature).decode('utf-8')

        # Use constant-time comparison to prevent timing attacks
        return hmac_compare_digest(expected_b64, signature)
    except Exception:
        return False

def hmac_compare_digest(a, b):
    """Constant-time comparison function"""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No action provided"}))
        sys.exit(1)

    action = sys.argv[1]

    try:
        if action == "generate":
            data = json.loads(sys.argv[2])
            message = data.get("message", "")
            secret = data.get("secret", "")
            if not message or not secret:
                print(json.dumps({"error": "Message and secret are required"}))
                sys.exit(1)
            sig = generate_signature(message, secret)
            print(json.dumps({"signature": sig}))

        elif action == "verify":
            data = json.loads(sys.argv[2])
            message = data.get("message", "")
            secret = data.get("secret", "")
            signature = data.get("signature", "")
            if not message or not secret or not signature:
                print(json.dumps({"error": "Message, secret, and signature are required"}))
                sys.exit(1)
            is_valid = verify_signature(message, signature, secret)
            print(json.dumps({"valid": is_valid}))

        else:
            print(json.dumps({"error": "Invalid action. Use 'generate' or 'verify'"}))
            sys.exit(1)

    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid JSON input"}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
