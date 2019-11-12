import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import binascii
import pickle


AVAILABLE_CIPHERS = ["ChaCha20", "AES", "TripleDES"]
AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]

def symmetric_key_generation(hash_algorithm, key, length, salt_value=None):

    backend = default_backend()
    salt = os.urandom(16) if salt_value is None else salt_value
    number_iterations = 100000

    upper_hash_alg = hash_algorithm.upper()
    if upper_hash_alg in AVAILABLE_HASHES:
        kdf = PBKDF2HMAC(
            algorithm=getattr(hashes, upper_hash_alg),
            length=length,
            salt=salt,
            iterations=number_iterations,
            backend=backend,
        )

    return kdf.derive(str.encode(key)), salt

def encryption(user_file, encrypted_file, cipher_algorithm, iv, salt):

    f = open(user_file, "r")
    file_content = f.read()
    file_length = len(file_content)
    f.close()

    cipher = Cipher(cipher_algorithm, modes.CBC(iv), backend=default_backend())


    iv_length = len(iv)
    padding_length = (iv_length - (file_length % iv_length)) % iv_length
    file_content += padding_length * "\x00"


    block_size = 1024 * 1024 * 4096  # 4MB

    encryptor = cipher.encryptor()

    ct = str.encode("")
    for padding in range(0, len(file_content), block_size):
        ct += encryptor.update(str.encode(file_content[padding : padding + block_size]))
    ct += encryptor.finalize()
    
    symmetric_protocol = Symmetric_protocol(iv, salt, padding_length, ct)
    
    cryptogram_file = open(encrypted_file, "wb")
    write_protocol(symmetric_protocol, cryptogram_file)
    cryptogram_file.close()


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

    cipher_mode = getattr(algorithms, cipher_algorithm)

    #TODO -> ChaCha20
    if cipher_mode.name == "ChaCha20":
        pass
    elif cipher_mode.name in AVAILABLE_CIPHERS:
        algorithm = cipher_mode(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)
    else:
        # TODO -> depois tratar desta exceção em concreto no servidor/cliente com um except
        raise Exception("Invalid Cipher mode")

    return algorithm,iv

