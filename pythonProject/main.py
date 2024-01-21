import random  # Import the 'random' module for generating random numbers
import pickle  # Import the 'pickle' module for serializing and deserializing objects
import hashlib  # Import the 'hashlib' module for secure hash and message digest algorithms
import hmac     # Import the 'hmac' module for generating keyed-hashes
import phe      # Import the 'phe' module for the Paillier cryptosystem

from Deffie_hellman import Deffie_Hellman
from Encryption_Decryption import EncryptionDecryption
from Signature_functions import Signature_add_ver

Deffie_obj = Deffie_Hellman() # object of deffie hellman classs
enc_dec_obj = EncryptionDecryption() # object of encryption class
Sig_obj = Signature_add_ver()

def generate_paillier_keypair(bits=2048):
    p = get_prime(bits)
    q = get_prime(bits)
    n = p * q
    g = n + 1
    lambda_n = (p - 1) * (q - 1)
    mu = mod_inverse(L(pow(g, lambda_n, n * n), n), n)

    public_key = (n, g)
    private_key = (lambda_n, mu)

    return public_key, private_key


def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        pickle.dump(key, file)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = pickle.load(file)
    return key

def get_prime(bits):
    while True:
        p = random.getrandbits(bits)
        if is_prime(p):
            return p

def is_prime(n, k=5):
    if n <= 1 or n % 2 == 0:
        return False
    for _ in range(k):
        a = random.randint(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True

def L(x, n):
    return (x - 1) // n

def mod_inverse(a, m):
    m0, x0, x1 = m, 0, 1
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    return x1 + m0 if x1 < 0 else x1

if __name__ == "__main__":
    # Generate key pairs for Alice
    alice_public_key, alice_private_key = generate_paillier_keypair()
    save_key_to_file(alice_public_key, 'alice_public_key.pkl')
    save_key_to_file(alice_private_key, 'alice_private_key.pkl')

    # Generate key pairs for Bob
    bob_public_key, bob_private_key = generate_paillier_keypair()
    save_key_to_file(bob_public_key, 'bob_public_key.pkl')
    save_key_to_file(bob_private_key, 'bob_private_key.pkl')

    # Diffie-Hellman key exchange
    alice_partial_key, alice_secret_key = Deffie_obj.diffie_hellman_key_exchange(bob_public_key, alice_private_key, bob_public_key[1])
    bob_partial_key, bob_secret_key = Deffie_obj.diffie_hellman_key_exchange(alice_public_key, bob_private_key, alice_public_key[1])

    # Save partial keys for each user
    alice_partial_key_bytes, alice_partial_key_signature = Sig_obj.sign_key(alice_private_key, alice_partial_key)
    bob_partial_key_bytes, bob_partial_key_signature = Sig_obj.sign_key(bob_private_key, bob_partial_key)
    save_key_to_file(alice_partial_key_bytes, 'alice_partial_key_bytes.pkl')
    save_key_to_file(alice_partial_key_signature, 'alice_partial_key_signature.pkl')
    save_key_to_file(bob_partial_key_bytes, 'bob_partial_key_bytes.pkl')
    save_key_to_file(bob_partial_key_signature, 'bob_partial_key_signature.pkl')

    # Load and verify partial keys for each user
    loaded_alice_partial_key_bytes = load_key_from_file('alice_partial_key_bytes.pkl')
    loaded_alice_partial_key_signature = load_key_from_file('alice_partial_key_signature.pkl')
    is_valid_alice_signature = Sig_obj.verify_signature(alice_public_key, loaded_alice_partial_key_bytes, loaded_alice_partial_key_signature)
    print("Is Alice's Partial Key Signature InValid?", is_valid_alice_signature)

    loaded_bob_partial_key_bytes = load_key_from_file('bob_partial_key_bytes.pkl')
    loaded_bob_partial_key_signature = load_key_from_file('bob_partial_key_signature.pkl')
    is_valid_bob_signature = Sig_obj.verify_signature(bob_public_key, loaded_bob_partial_key_bytes, loaded_bob_partial_key_signature)
    print("Is Bob's Partial Key Signature InValid?", is_valid_bob_signature)

    #assert is_valid_alice_signature and is_valid_bob_signature, "Invalid signature for partial keys"

    # Example plaintext
    plaintext = 42

    # Paillier Encryption for Alice
    ciphertext_alice = enc_dec_obj.encrypt_paillier(bob_public_key, plaintext)
    print("Alice - Encrypted:", ciphertext_alice)

    # Paillier Decryption for Bob
    decrypted_text_bob = enc_dec_obj.decrypt_paillier(bob_private_key, bob_public_key, ciphertext_alice)
    print("Bob - Decrypted:", decrypted_text_bob)

    # Paillier Encryption for Bob
    ciphertext_bob = enc_dec_obj.encrypt_paillier(alice_public_key, plaintext)
    print("Bob - Encrypted:", ciphertext_bob)

    # Paillier Decryption for Alice
    decrypted_text_alice = enc_dec_obj.decrypt_paillier(alice_private_key, alice_public_key, ciphertext_bob)
    print("Alice - Decrypted:", decrypted_text_alice)

    # Verify shared secret keys
    assert alice_secret_key == bob_secret_key, "Shared secret keys do not match!"
    print("Shared Secret Key:", alice_secret_key)
