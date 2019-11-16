import getpass
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.backends.openssl.backend import DHBackend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import binascii
import pickle
import random

AVAILABLE_CIPHERS = ["ChaCha20", "AES", "TripleDES"]
AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]
#AVAILABLE_MODES = ["CBC", "GCM"]
AVAILABLE_MODES = ["CBC"]
length_by_cipher = {'ChaCha20': 32, 'AES': 32, 'TripleDES': 24}


def cipher_params(cipher_algorithm, key):

    algorithm = None
    iv = None
    iv_length = 16  # defaul value

    nonce = None  #Just used for ChaCha20

    cipher_mode = getattr(
        algorithms, cipher_algorithm
    )  #verificar quando um algoritmo nao existe (isto da uma exception)

    #TODO -> ChaCha20
    if cipher_mode.name == "ChaCha20":
        '''
            IMPORTANT !!!!!!!!!!!!!!
            nonce – Should be unique, a nonce. 
            It is critical to never reuse a nonce with a given key. 
            Any reuse of a nonce with the same key compromises the security of every message encrypted with that key. 
            The nonce does not need to be kept secret and may be included with the ciphertext. This must be 128 bits in length.
        '''
        nonce = os.urandom(16)
        algorithm = cipher_mode(key, nonce)

    elif cipher_algorithm in AVAILABLE_CIPHERS:
        algorithm = cipher_mode(key)
        iv_length = algorithm.block_size // 8
        iv = os.urandom(iv_length)
    else:
        # TODO -> depois tratar desta exceção em concreto no servidor/cliente com um except
        raise Exception("Invalid Cipher mode")

    return algorithm, iv


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


def key_derivation(hash_algorithm, length, key):
    backend = default_backend()
    #salt = os.urandom(16)

    #melhorar isto passando um salt diferente de None, mas depois tem que se passar este valor para o server

    upper_hash_alg = hash_algorithm.upper()
    #getattr(hashes, upper_hash_alg) -> ver pq esta a dar erro
    return HKDF(algorithm=hashes.SHA512(),
                length=length,
                salt=None,
                info=b'handshake data',
                backend=backend).derive(key)


def encryption(data, key, cipher_algorithm, mode):

    algorithm, iv = cipher_params(cipher_algorithm, key)

    if iv is None:  #For ChaCha20
        iv_length = 16
    else:
        iv_length = len(iv)

    padding_length = (iv_length - (len(data) % iv_length)) % iv_length
    data += (padding_length * "\x00").encode()

    if iv is None:  # For ChaCha20
        cipher = Cipher(algorithm, None, backend=default_backend())
        iv = algorithm.nonce
    else:
        cipher = Cipher(
            algorithm,
            getattr(modes, mode)(
                iv
            ),  #verificar erros disto ( ou ter a certeza que o parametro passado é sempre correto)
            backend=default_backend())

    encryptor = cipher.encryptor()

    return encryptor.update(data) + encryptor.finalize(), padding_length, iv


def decryption(data, key, cipher_algorithm, mode, padding_length, iv):

    cipher_mode = getattr(algorithms, cipher_algorithm)
    if cipher_algorithm != 'ChaCha20':
        algorithm = cipher_mode(key)
    else:
        algorithm = cipher_mode(key, iv)

    if cipher_algorithm == 'ChaCha20':  # For ChaCha20
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
    else:
        cipher = Cipher(
            algorithm,
            mode=modes.CBC(iv)
            if mode == 'CBC' else modes.GCM(iv, tag),  #tentar melhorar isto
            backend=default_backend())

    decryptor = cipher.decryptor()

    output = decryptor.update(data) + decryptor.finalize()

    if padding_length == 0:
        return output

    return output[:-padding_length]


def encryption_file(user_file, encrypted_file, cipher_algorithm, mode, iv,
                    salt):

    f = open(user_file, "r")
    with open(user_file, 'r'):
        file_content = f.read()

    if iv is None:  #For ChaCha20
        iv_length = 16
    else:
        iv_length = len(iv)

    padding_length = (iv_length - (len(file_content) % iv_length)) % iv_length
    file_content += padding_length * "\x00"

    block_size = 1024 * 1024 * 4096  # 4MB

    if iv is None:  # For ChaCha20
        cipher = Cipher(cipher_algorithm, None, backend=default_backend())
    else:
        cipher = Cipher(
            cipher_algorithm,
            getattr(modes, mode)(
                iv
            ),  #verificar erros disto ( ou ter a certeza que o parametro passado é sempre correto)
            backend=default_backend())

    encryptor = cipher.encryptor()

    ct = str.encode("")
    for padding in range(0, len(file_content), block_size):
        ct += encryptor.update(
            str.encode(file_content[padding:padding + block_size]))
    ct += encryptor.finalize()

    symmetric_protocol = Symmetric_protocol(
        iv, salt, padding_length, encryptor.tag if mode == 'GCM' else None, ct)

    # TODO -> talvez possa ser melhorado
    cryptogram_file = open(encrypted_file, "wb")
    write_protocol(symmetric_protocol, cryptogram_file)
    cryptogram_file.close()


def decryption_file(encrypted_file, decrypted_file, algorithm, mode):

    symmetric_protocol = read_protocol(open(encrypted_file, "rb"))

    iv, salt, end_file_padding, tag, file_content = symmetric_protocol.unpacking(
    )

    if iv is None:  # For ChaCha20
        cipher = Cipher(algorithm, mode=None, backend=default_backend())
    else:
        cipher = Cipher(
            algorithm,
            mode=modes.CBC(iv)
            if mode == 'CBC' else modes.GCM(iv, tag),  #tentar melhorar isto
            backend=default_backend())

    decryptor = cipher.decryptor()

    output = decryptor.update(file_content) + decryptor.finalize()
    decryption_result = output[:-end_file_padding].decode()

    # TODO -> talvez possa ser melhorado
    f = open(decrypted_file, "w")
    f.write(decryption_result)
    f.close()


class Symmetric_protocol:
    def __init__(self, iv, salt, padding, tag, content):
        self.iv = iv
        self.salt = salt
        self.padding = padding
        self.tag = tag  #For GCM
        self.content = content

    def unpacking(self):
        return self.iv, self.salt, self.padding, self.tag, self.content


def write_protocol(object_, writable_file):
    pickle.dump(object_, writable_file)


def read_protocol(readable_file):
    return pickle.load(readable_file)


def prettier(blob):
    return binascii.hexlify(blob)


class ProtoAlgorithm:
    def __init__(self, cipher, mode, synthesis_algorithm):
        self.algorithm = "DH"  #Diffie-Hellman
        self.cipher = cipher
        self.mode = mode
        self.synthesis_algorithm = synthesis_algorithm

    def packing(self):
        return f"{self.algorithm}_{self.cipher}_{self.mode}_{self.synthesis_algorithm}"

    def __str__(self):
        return self.packing().replace('_', '\t')


def unpacking(pack_string):
    splitted_string = pack_string.split('_')
    return splitted_string[0], splitted_string[1], splitted_string[
        2], splitted_string[3]


def DH_parameters():
    return dh.generate_parameters(generator=2,
                                  key_size=1024,
                                  backend=default_backend())


def DH_parametersNumbers(p, g):
    pn = dh.DHParameterNumbers(p, g)
    return pn.parameters(default_backend())


def MAC(key, synthesis_algorithm):
    picked_hash = getattr(hashes, synthesis_algorithm)
    return hmac.HMAC(key, picked_hash(), backend=default_backend())
