import base64
import json
import os

import cryptography
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509 import load_pem_x509_certificate

from JSONManager import JSONManager
from guiManager import GUIManager

#Clase que se encarga de la gestion de la sesion de un usuario.
class UserSession:
    def __init__(self, username, password):
        self.username = username
        self.private_key, self.public_key = self.load_keys(password)
        print(f"Session started for {username}.")

    #Carga las claves del usuario.
    def load_keys(self, password):
        user_data = JSONManager.load_user_data()
        user_info = user_data.get(self.username)

        #Comprueba si el usuario existe.
        if not user_info:
            raise ValueError("User not found.")

        #Carga la clave publica del usuario.
        public_key_pem = JSONManager.load_public_key(self.username)
        if not public_key_pem:
            raise ValueError("Public key not found.")

        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

        #Carga la clave privada del usuario.
        private_key_pem = user_info["private_key"]
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode('utf-8'),
            password=password.encode(),
            backend=default_backend()
        )

        return private_key, public_key

    #Carga la clave publica de otro usuario.
    def load_public_key(self, other_username):
        public_key_pem = JSONManager.load_public_key(other_username)
        if not public_key_pem:
            raise ValueError(
                f"No public key found for user '{other_username}'. Please ensure they are registered correctly.")

        return serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )

    #Encripta un mensaje para otro usuario.
    def encrypt_message(self, receiver_username, message):
        receiver_public_key = self.load_public_key(receiver_username)

        # Generate shared secret
        shared_secret = self.private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)

        # Encrypt message
        chacha = ChaCha20Poly1305(derived_key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, message.encode('utf-8'), None)

        # Sign the plaintext message
        signature = self.sign_message(message)
        print(f"Generated signature: {base64.b64encode(signature).decode('utf-8')}")

        # Attach sender's certificate
        with open(f"{self.username}_cert.pem", "rb") as cert_file:
            cert_data = cert_file.read()

        # Store encrypted message, nonce, signature, and certificate
        with open(f"messages_{receiver_username}.txt", "ab") as f:
            f.write(json.dumps({
                "plaintext": message,  # Store the plaintext for signature verification
                "sender_public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "signature": base64.b64encode(signature).decode('utf-8'),
                "certificate": cert_data.decode('utf-8')
            }).encode() + b"\n")
        print("Message encrypted, signed, and stored successfully.")

    #Desencripta los mensajes recibidos.
    def decrypt_message(self):
        try:
            with open(f"messages_{self.username}.txt", "rb") as f:
                for line in f:
                    msg = json.loads(line)

                    # Debugging: Log details about the loaded message
                    # Debugging: Log details about the loaded message
                    print(f"Debugging - Loaded Message:")
                    print(f"Ciphertext: {msg['ciphertext']}")
                    print(f"Nonce: {msg['nonce']}")
                    print(f"Signature: {msg['signature']}")
                    print(f"Certificate: {msg['certificate']}")
                    print(f"Plaintext for verification: {msg['plaintext']}")

                    # Load sender's certificate
                    print("Loading sender's certificate...")
                    sender_cert = x509.load_pem_x509_certificate(
                        msg["certificate"].encode('utf-8'), backend=default_backend()
                    )

                    # Validate the certificate
                    print("Validating sender's certificate...")
                    with open("root_cert.pem", "rb") as root_cert_file:
                        root_cert = x509.load_pem_x509_certificate(root_cert_file.read())
                    if sender_cert.issuer != root_cert.subject:
                        print("Certificate validation failed: Issuer mismatch.")
                        continue
                    print("Certificate validated successfully.")

                    # Verify the signature
                    print("Verifying message signature...")
                    sender_public_key = sender_cert.public_key()
                    signature = base64.b64decode(msg["signature"])
                    try:
                        sender_public_key.verify(
                            signature,
                            msg["plaintext"].encode('utf-8'),
                            # Verify against the plaintext
                            ec.ECDSA(hashes.SHA256())
                        )
                        print("Signature verified successfully.")
                    except InvalidSignature:
                        print(f"Invalid signature for message: {msg['plaintext']}")
                        continue

                    # Decrypt the message
                    shared_secret = self.private_key.exchange(ec.ECDH(),
                                                              sender_public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data'
                    ).derive(shared_secret)

                    chacha = ChaCha20Poly1305(derived_key)
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["ciphertext"])
                    plaintext = chacha.decrypt(nonce, ciphertext, None)
                    print(f"Decrypted message: {plaintext.decode('utf-8')}")

        except FileNotFoundError:
            print("No messages found.")
        except cryptography.exceptions.InvalidTag:
            print("Failed to decrypt: Invalid tag.")
    
    #Finaliza la sesion del usuario.
    def end_session(self):
        self.private_key = None
        gui = GUIManager 
        gui.print_msg(f"Session ended for {self.username}.", "red")


    # metodo para firmar mensajes
    def sign_message(self, message):
        signature = self.private_key.sign(
            message.encode('utf-8'),  # Use consistent encoding
            ec.ECDSA(hashes.SHA256())
        )
        print(f"Generated signature: {base64.b64encode(signature).decode('utf-8')}")
        return signature

    # metodo para verificar firmas de mensajes
    def verify_signature(self, message, signature, sender_cert_path):
        print(f"Verifying message: {message}")
        print(f"Using signature: {base64.b64encode(signature).decode('utf-8')}")

        with open(sender_cert_path, "rb") as f:
            sender_cert = load_pem_x509_certificate(f.read())

        sender_public_key = sender_cert.public_key()
        try:
            sender_public_key.verify(
                signature,
                message.encode('utf-8'),  # Use consistent encoding
                ec.ECDSA(hashes.SHA256())
            )
            print("Signature verified successfully.")
        except InvalidSignature:
            print("Signature verification failed.")
            raise

