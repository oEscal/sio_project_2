from File_encryption import file_encryption
from File_decryption import file_decryption


def main():
    file_encryption("data.txt", "encrypted.txt", "3DES", "MD5")
    file_decryption("encrypted.txt", "decrypted_file.out", "3DES", "MD5")


if __name__ == "__main__":
    main()
