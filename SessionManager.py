import base64
import json
import os

import cryptography
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from JSONManager import JSONManager


class UserSession:
    def __init__(self, username, password):
        self.username = username
        self.private_key, self.public_key = self.load_keys(password)
        print(f"Session started for {username}.")

    def load_keys(self, password):
        user_data = JSONManager.load_user_data()
        user_info = user_data.get(self.username)

        if not user_info:
            raise ValueError("User not found.")

        # Load the public key from JSONManager
        public_key_pem = JSONManager.load_public_key(self.username)
        if not public_key_pem:
            raise ValueError("Public key not found.")

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        # Decrypt and load the private key
        private_key_pem = user_info["private_key"]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode(),
            backend=default_backend()
        )

        return private_key, public_key

    def load_public_key(self, other_username):
        public_key_pem = JSONManager.load_public_key(other_username)
        if not public_key_pem:
            raise ValueError(
                f"No public key found for user '{other_username}'. Please ensure they are registered correctly.")

        # Load the public key from PEM format
        return serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

    def encrypt_message(self, receiver_username, message):
        receiver_public_key = self.load_public_key(receiver_username)

        # Generate a shared secret using ECDH
        shared_secret = self.private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)

        # ChaCha20-Poly1305 encryption
        chacha = ChaCha20Poly1305(derived_key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, message.encode('utf-8'), None)

        with open(f"messages_{receiver_username}.txt", "ab") as f:
            f.write(json.dumps({
                "sender_public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8')
            }).encode() + b"\n")
        print(f"Message encrypted and stored for {receiver_username}.")

    def decrypt_message(self):
        try:
            with open(f"messages_{self.username}.txt", "rb") as f:
                for line in f:
                    msg = json.loads(line)

                    # Load sender's public key from the message
                    sender_public_key = serialization.load_pem_public_key(
                        msg["sender_public_key"].encode('utf-8'),
                        backend=default_backend()
                    )

                    # Generate the shared secret
                    shared_secret = self.private_key.exchange(ec.ECDH(),
                                                              sender_public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data'
                    ).derive(shared_secret)

                    # ChaCha20-Poly1305 decryption
                    chacha = ChaCha20Poly1305(derived_key)
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["ciphertext"])
                    plaintext = chacha.decrypt(nonce, ciphertext, None)
                    print(f"Decrypted message: {plaintext.decode('utf-8')}")
        except FileNotFoundError:
            print("No messages found.")
        except cryptography.exceptions.InvalidTag:
            print(
                "Failed to decrypt: Invalid tag (data may be corrupted or the key/nonce is incorrect).")

    def end_session(self):
        self.private_key = None
        print(f"Session ended for {self.username}.")