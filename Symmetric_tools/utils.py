import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .Symmetric_key_generation import symmetric_key_generation
from .cipher_algorithms import CIPHERS
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

