from .utils import *
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


def decryption(
    encrypted_file, decrypted_file,algorithm):

    symmetric_protocol = read_protocol(open(encrypted_file, "rb"))

    iv, salt, end_file_padding, file_content = symmetric_protocol.unpacking()
    
    
    cipher = Cipher(algorithm, mode=modes.CBC(iv), backend=default_backend())

    decryptor = cipher.decryptor()

    output = decryptor.update(file_content) + decryptor.finalize()

    decryption_result = output[:-end_file_padding].decode()

    f = open(decrypted_file, "w")
    f.write(decryption_result)
    f.close()
