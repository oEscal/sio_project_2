from utils import *
import getpass


def main():
    "GCM->This mode does not require padding.(Apesar de nao ser preciso , meto na msm o padding para nao 'estragar' muito o code)"

    '''
        AVAILABLE_CIPHERS = ["ChaCha20", "AES", "TripleDES"]
        AVAILABLE_HASHES = ["SHA256", "SHA512", "MD5"]
        AVAILABLE_MODES = ["CBC", "GCM"]
        Todos estes algoritmos ja estao implementados
    '''

    mode = "GCM"

    length_by_cipher = {'ChaCha20': 32, 'AES': 32, 'TripleDES': 24}

    cipher_algorithm = "AES"  #AES OR TripleDES

    length = length_by_cipher[cipher_algorithm]

    key, salt = symmetric_key_generation("SHA512", getpass.getpass(), length)

    algorithm, iv = cipher_params(cipher_algorithm, key)

    encryption("README.md", "encrypted.txt", algorithm, mode, iv, salt)

    with open("file_key.bin", 'wb') as file:
        file.write(key)

    decryption("encrypted.txt", "READMEDecrypted.txt", algorithm, mode)


if __name__ == "__main__":
    main()
