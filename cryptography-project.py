import os
import base64
import random
import string
import traceback
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


class AdvancedCryptographyTool:
    def __init__(self):
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.generate_rsa_keys()

    def generate_rsa_keys(self):
        """Generate RSA key pair and save to files"""
        # Generate private key
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        # Save private key
        private_pem = self.rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open("private_key.pem", "wb") as f:
            f.write(private_pem)

        # Save public key
        public_pem = self.rsa_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        with open("public_key.pem", "wb") as f:
            f.write(public_pem)

        print(
            "RSA key pair generated and saved as 'private_key.pem' and 'public_key.pem'"
        )

    def monoalphabetic_encrypt(self, text):
        """Monoalphabetic substitution cipher"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        alphabet = string.ascii_lowercase
        shifted_alphabet = alphabet[3:] + alphabet[:3]
        trans_table = str.maketrans(alphabet, shifted_alphabet)
        return text.lower().translate(trans_table)

    def monoalphabetic_decrypt(self, text):
        """Monoalphabetic substitution cipher decryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        alphabet = string.ascii_lowercase
        shifted_alphabet = alphabet[3:] + alphabet[:3]
        trans_table = str.maketrans(shifted_alphabet, alphabet)
        return text.lower().translate(trans_table)

    def vigenere_encrypt(self, text, key="SECRET"):
        """Vigenère cipher encryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        text = text.lower()
        key = key.lower()
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord("a")
                encrypted_char = chr((ord(char) - ord("a") + shift) % 26 + ord("a"))
                result.append(encrypted_char)
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    def vigenere_decrypt(self, text, key="SECRET"):
        """Vigenère cipher decryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        text = text.lower()
        key = key.lower()
        result = []
        key_index = 0
        for char in text:
            if char.isalpha():
                shift = ord(key[key_index % len(key)]) - ord("a")
                decrypted_char = chr((ord(char) - ord("a") - shift) % 26 + ord("a"))
                result.append(decrypted_char)
                key_index += 1
            else:
                result.append(char)
        return "".join(result)

    def vernam_encrypt(self, text):
        """Vernam cipher (One-Time Pad) encryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        # Generate a shorter, fixed-length key
        key = "".join(
            random.choice(string.ascii_letters + string.digits) for _ in range(16)
        )

        # Truncate or pad the key to match text length
        key = (key * ((len(text) // len(key)) + 1))[: len(text)]

        encrypted = "".join(chr(ord(t) ^ ord(k)) for t, k in zip(text, key))
        return base64.b64encode(encrypted.encode()).decode(), key

    def vernam_decrypt(self, encrypted_text, key):
        """Vernam cipher (One-Time Pad) decryption"""
        if not isinstance(encrypted_text, str) or not isinstance(key, str):
            raise ValueError("Inputs must be strings")

        encrypted_text = base64.b64decode(encrypted_text.encode()).decode()
        decrypted = "".join(chr(ord(e) ^ ord(k)) for e, k in zip(encrypted_text, key))
        return decrypted

    def transpositional_encrypt(self, text):
        """Transpositional (Column Transposition) cipher encryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        key_length = 5
        columns = [""] * key_length
        for i, char in enumerate(text):
            columns[i % key_length] += char
        return "".join(columns)

    def transpositional_decrypt(self, text):
        """Transpositional (Column Transposition) cipher decryption"""
        if not isinstance(text, str):
            raise ValueError("Input must be a string")

        key_length = 5
        column_lengths = [
            len(text) // key_length + (1 if i < len(text) % key_length else 0)
            for i in range(key_length)
        ]

        columns = []
        start = 0
        for length in column_lengths:
            columns.append(text[start : start + length])
            start += length

        result = []
        for i in range(max(column_lengths)):
            for column in columns:
                if i < len(column):
                    result.append(column[i])

        return "".join(result)

    def rsa_encrypt(self, data):
        """RSA encryption of a symmetric key"""
        try:
            max_key_size = 190
            if len(data) > max_key_size:
                data = data[:max_key_size]

            encrypted = self.rsa_public_key.encrypt(
                data.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"RSA Encryption error: {e}")
            raise

    def rsa_decrypt(self, encrypted_data):
        """RSA decryption of a symmetric key"""
        decrypted = self.rsa_private_key.decrypt(
            base64.b64decode(encrypted_data.encode()),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return decrypted.decode()

    def encrypt_file(self, filename):
        """Comprehensive file encryption process"""
        try:
            # Check file exists and is readable
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File {filename} does not exist")

            # Read file with error handling for encoding
            try:
                with open(filename, "r", encoding="utf-8") as file:
                    content = file.read()
            except UnicodeDecodeError:
                # Try reading with different encodings if UTF-8 fails
                encodings = ["latin-1", "iso-8859-1", "cp1252"]
                for enc in encodings:
                    try:
                        with open(filename, "r", encoding=enc) as file:
                            content = file.read()
                        break
                    except UnicodeDecodeError:
                        continue
                else:
                    raise ValueError(
                        f"Could not decode file {filename} with any standard encoding"
                    )

            # Validate content is not empty
            if not content:
                raise ValueError("File is empty")

            # Apply multiple encryption layers
            monoalphabetic = self.monoalphabetic_encrypt(content)
            vigenere = self.vigenere_encrypt(monoalphabetic)
            vernam, vernam_key = self.vernam_encrypt(vigenere)
            transpositional = self.transpositional_encrypt(vernam)
            rsa_encrypted_key = self.rsa_encrypt(vernam_key)

            # Combine all encryption details
            encryption_metadata = {
                "algorithms": [
                    "Monoalphabetic",
                    "Vigenère",
                    "Vernam",
                    "Transpositional",
                    "RSA",
                ],
                "rsa_encrypted_key": rsa_encrypted_key,
            }

            # Write encrypted file
            output_filename = filename.rsplit(".", 1)[0] + ".enc"
            with open(output_filename, "w", encoding="utf-8") as outfile:
                outfile.write(transpositional + "\n")
                outfile.write(
                    base64.b64encode(str(encryption_metadata).encode()).decode()
                )

            print(f"File encrypted successfully: {output_filename}")
            return output_filename

        except Exception as e:
            print(f"Encryption error: {e}")
            print("Detailed traceback:")
            traceback.print_exc()
            return None

    def decrypt_file(self, filename):
        """Comprehensive file decryption process"""
        try:
            # Check file exists
            if not os.path.exists(filename):
                raise FileNotFoundError(f"File {filename} does not exist")

            # Read encrypted file
            with open(filename, "r", encoding="utf-8") as file:
                encrypted_content = file.readline().strip()
                metadata_base64 = file.readline().strip()

            # Decode metadata
            encryption_metadata = eval(base64.b64decode(metadata_base64).decode())

            # Retrieve RSA decrypted key
            vernam_key = self.rsa_decrypt(encryption_metadata["rsa_encrypted_key"])

            # Reverse encryption steps
            transpositional = self.transpositional_decrypt(encrypted_content)
            vernam = self.vernam_decrypt(transpositional, vernam_key)
            vigenere = self.vigenere_decrypt(vernam)
            monoalphabetic = self.monoalphabetic_decrypt(vigenere)

            # Always write to a fixed filename 'decrypted.txt'
            output_filename = "decrypted.txt"
            with open(output_filename, "w", encoding="utf-8") as outfile:
                outfile.write(monoalphabetic)

            print(f"File decrypted successfully: {output_filename}")
            return output_filename

        except Exception as e:
            print(f"Decryption error: {e}")
            print("Detailed traceback:")
            traceback.print_exc()
            return None


def main():
    crypto_tool = AdvancedCryptographyTool()

    while True:
        print("\nAdvanced Cryptography Tool")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("Enter your choice (1/2/3): ")

        if choice == "1":
            filename = input("Enter the filename to encrypt: ")
            if os.path.exists(filename):
                crypto_tool.encrypt_file(filename)
            else:
                print("File not found!")

        elif choice == "2":
            filename = input("Enter the filename to decrypt: ")
            if os.path.exists(filename):
                crypto_tool.decrypt_file(filename)
            else:
                print("File not found!")

        elif choice == "3":
            break

        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
