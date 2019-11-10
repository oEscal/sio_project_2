from cryptography.hazmat.primitives import hashes


class HASHES:
    def __init__(self, algorithm):
        self.algorithm = algorithm.upper()
        self.availables_algorithm = ["SHA256", "SHA512", "MD5"]

    def get_hash(self):
        if self.algorithm not in self.availables_algorithm:
            raise Exception("Invalid Encryption Algorithm")
        return getattr(hashes, self.algorithm)
