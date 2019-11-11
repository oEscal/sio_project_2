from .utils import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


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
