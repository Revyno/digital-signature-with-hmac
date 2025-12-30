#!/usr/bin/env python3
"""
RSA Digital Signature with SHA-512
Python implementation for secure document signing and verification
"""

import hashlib
import base64
import json
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import os

class RSASHA512:
    """RSA-SHA512 digital signature implementation"""

    def __init__(self):
        self.key_size = 2048
        self.backend = default_backend()

    def generate_keypair(self):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def private_key_to_pem(self, private_key):
        """Convert private key to PEM format"""
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        return pem.decode('utf-8')

    def public_key_to_pem(self, public_key):
        """Convert public key to PEM format"""
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')

    def pem_to_private_key(self, pem_data):
        """Convert PEM to private key object"""
        private_key = serialization.load_pem_private_key(
            pem_data.encode('utf-8'),
            password=None,
            backend=self.backend
        )
        return private_key

    def pem_to_public_key(self, pem_data):
        """Convert PEM to public key object"""
        public_key = serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=self.backend
        )
        return public_key

    def sign_message(self, message, private_key_pem):
        """Sign message with RSA-SHA512"""
        private_key = self.pem_to_private_key(private_key_pem)

        # Create signature
        signature = private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA512()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA512()
        )

        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message, signature_b64, public_key_pem):
        """Verify RSA-SHA512 signature"""
        try:
            public_key = self.pem_to_public_key(public_key_pem)
            signature = base64.b64decode(signature_b64)

            # Verify signature
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA512()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA512()
            )
            return True
        except Exception:
            return False

# Global RSA instance
rsa_instance = RSASHA512()

# Key storage (in production, use secure key management)
rsa_keys = {}

def generate_rsa_keys(key_id):
    """Generate and store RSA key pair"""
    private_key, public_key = rsa_instance.generate_keypair()

    private_pem = rsa_instance.private_key_to_pem(private_key)
    public_pem = rsa_instance.public_key_to_pem(public_key)

    rsa_keys[key_id] = {
        'private_key': private_pem,
        'public_key': public_pem
    }

    return {
        'private_key': private_pem,
        'public_key': public_pem
    }

def sign_with_rsa(message, key_id):
    """Sign message using stored RSA private key"""
    if key_id not in rsa_keys:
        raise ValueError(f"RSA key pair with ID '{key_id}' not found. Generate keys first.")

    private_key_pem = rsa_keys[key_id]['private_key']
    signature = rsa_instance.sign_message(message, private_key_pem)

    return {
        'signature': signature,
        'public_key': rsa_keys[key_id]['public_key']
    }

def verify_with_rsa(message, signature, public_key_pem):
    """Verify RSA signature"""
    return rsa_instance.verify_signature(message, signature, public_key_pem)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No action provided"}))
        sys.exit(1)

    action = sys.argv[1]

    try:
        if action == "generate-keys":
            data = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
            key_id = data.get("key_id", "default")

            keys = generate_rsa_keys(key_id)
            print(json.dumps({
                "success": True,
                "key_id": key_id,
                "public_key": keys["public_key"],
                "message": "RSA key pair generated successfully"
            }))

        elif action == "sign":
            data = json.loads(sys.argv[2])
            message = data.get("message", "")
            key_id = data.get("key_id", "default")

            if not message:
                print(json.dumps({"error": "Message is required"}))
                sys.exit(1)

            result = sign_with_rsa(message, key_id)
            print(json.dumps(result))

        elif action == "verify":
            data = json.loads(sys.argv[2])
            message = data.get("message", "")
            signature = data.get("signature", "")
            public_key = data.get("public_key", "")

            if not message or not signature or not public_key:
                print(json.dumps({"error": "Message, signature, and public_key are required"}))
                sys.exit(1)

            is_valid = verify_with_rsa(message, signature, public_key)
            print(json.dumps({
                "valid": is_valid,
                "status": "RSA signature verified successfully!" if is_valid else "RSA signature verification failed"
            }))

        else:
            print(json.dumps({"error": "Invalid action. Use 'generate-keys', 'sign', or 'verify'"}))
            sys.exit(1)

    except json.JSONDecodeError:
        print(json.dumps({"error": "Invalid JSON input"}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
