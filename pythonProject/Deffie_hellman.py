import  random
import sys
import phe

class Deffie_Hellman:
    def __init__(self):
        pass

    def diffie_hellman_key_exchange(self,public_key, private_key, peer_partial_key):
        self.n, _ = public_key
        self.x = random.randint(1, self.n - 1)
        self.partial_key = pow(public_key[1], self.x, self.n)
        self.secret_key = pow(peer_partial_key, private_key[0], self.n)
        return self.partial_key, self.secret_key