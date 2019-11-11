import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes, hashes
from .Symmetric_key_generation import symmetric_key_generation
import binascii
import pickle


class CIPHERS:
    def __init__(self, cipher):
        self.cipher = cipher
        self.available_ciphers = ["ChaCha20", "AES", "TripleDES"]

    def get_cipher(self):
        if self.cipher not in self.available_ciphers:
            raise Exception("Invalid Cipher mode")
        return getattr(algorithms, self.cipher)


class HASHES:
    def __init__(self, algorithm):
        self.algorithm = algorithm.upper()
        self.availables_algorithm = ["SHA256", "SHA512", "MD5"]

    def get_hash(self):
        if self.algorithm not in self.availables_algorithm:
            raise Exception("Invalid Encryption Algorithm")
        return getattr(hashes, self.algorithm)

class Symmetric_protocol:
    def __init__(self, iv, salt, padding, content):
        self.iv = iv
        self.salt = salt
        self.padding = padding
        self.content = content

    def unpacking(self):
        return self.iv, self.salt, self.padding, self.content


def write_protocol(object_, writable_file):
    pickle.dump(object_, writable_file)


def read_protocol(readable_file):
    return pickle.load(readable_file)


def prettier(blob):
    return binascii.hexlify(blob)




def cipher_params(cipher_algorithm, key):

    algorithm = None
    iv = None
    iv_length = 16  # defaul value

    cipher_mode = CIPHERS(cipher_algorithm).get_cipher()

    #TODO -> ChaCha20
    if cipher_mode.name == "ChaCha20":
        pass
        # Nonce
    else:
        algorithm = cipher_mode(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)

    return algorithm,iv

