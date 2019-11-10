import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from Symmetric_key_generation import symmetric_key_generation
import binascii
import pickle


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


def cipher_params(encryption_algorithm, hash_algorithm, salt=None):

    algorithm = None
    key = None
    iv_length = 16  # default value
    iv = None
    algorithms_names = ["ChaCha20", "AES", "3DES"]

    if encryption_algorithm not in algorithms_names:
        raise Exception("Invalid Encryption Algorithm")

    if encryption_algorithm == "ChaCha20":
        key, salt = symmetric_key_generation(
            hash_algorithm, getpass.getpass(), 32, salt
        )
        algorithm = algorithms.ChaCha20(key, os.urandom(16))

    elif encryption_algorithm == "AES":
        key, salt = symmetric_key_generation(
            hash_algorithm, getpass.getpass(), 32, salt
        )
        algorithm = algorithms.AES(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)

    elif encryption_algorithm == "3DES":
        key, salt = symmetric_key_generation(
            hash_algorithm, getpass.getpass(), 24, salt
        )
        algorithm = algorithms.TripleDES(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)

    return {"algorithm": algorithm, "iv_length": iv_length, "iv": iv, "salt": salt}
