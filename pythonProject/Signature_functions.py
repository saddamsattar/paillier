import pickle
import hmac
import hashlib

class Signature_add_ver:
    def __init__(self):
        pass

    def sign_key(self,private_key, key):
        self.key_bytes = pickle.dumps(key)
        self.signature = hmac.new(bytes(str(private_key), 'utf-8'), self.key_bytes, hashlib.sha256).digest()
        return self.key_bytes, self.signature

    def verify_signature(self,public_key, key_bytes, signature):
        self.expected_signature = hmac.new(bytes(str(public_key), 'utf-8'), key_bytes, hashlib.sha256).digest()
        return hmac.compare_digest(self.expected_signature, signature)