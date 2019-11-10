from cryptography.hazmat.primitives.ciphers import algorithms


class CIPHERS:
    def __init__(self, cipher):
        self.cipher = cipher
        self.available_ciphers = ["ChaCha20", "AES", "TripleDES"]

    def get_cipher(self):
        if self.cipher not in self.available_ciphers:
            raise Exception("Invalid Cipher mode")
        return getattr(algorithms, self.cipher)
