import random
class EncryptionDecryption:
    def __init__(self):
        self.key = "<KEY>"
        self.message = ""

    def encrypt_paillier(self,public_key, plaintext):
        # Perform Paillier encryption on a plaintext using the provided public key
        self.n, self.g = public_key
        self.r = random.randint(1, self.n - 1)
        self.ciphertext = (pow(self.g, plaintext, self.n * self.n) * pow(self.r, self.n, self.n * self.n)) % (self.n * self.n)
        return self.ciphertext

    def decrypt_paillier(self,private_key, public_key, ciphertext):
        # Perform Paillier decryption on a ciphertext using the provided public and private keys
        self.n, _ = public_key
        self.lambda_n, self.mu = private_key
        self.plaintext = (self.L(pow(ciphertext, self.lambda_n, self.n * self.n), self.n) * self.mu) % self.n
        return self.plaintext

    def L(self,x, n):  # The L function in the context of the Paillier cryptosystem is often referred
        # to as the "lifting function" or "decoding function
        # Define the L function used in Paillier cryptosystem
        return (x - 1) // n
