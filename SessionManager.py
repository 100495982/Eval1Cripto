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

        #Genera la clave compartida.
        shared_secret = self.private_key.exchange(ec.ECDH(), receiver_public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)

        #Encripta el mensaje con ChaCha20-Poly1305.
        chacha = ChaCha20Poly1305(derived_key)
        nonce = os.urandom(12)
        ciphertext = chacha.encrypt(nonce, message.encode('utf-8'), None)
        
        # Firma el mensaje
        signature = self.sign_message(message)

        #Guarda el mensaje en un archivo.
        with open(f"messages_{receiver_username}.txt", "ab") as f:
            f.write(json.dumps({
                "sender_public_key": self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
                "sender_singature": base64.b64encode(signature).decode('utf-8')
            }).encode() + b"\n")
        print(f"Message encrypted and stored for {receiver_username}.")

    #Desencripta los mensajes recibidos.
    def decrypt_message(self):
        try:
            with open(f"messages_{self.username}.txt", "rb") as f:
                for line in f:
                    msg = json.loads(line)

                    # Cargar la clave publica del remitente.
                    sender_public_key = serialization.load_pem_public_key(
                        msg["sender_public_key"].encode('utf-8'),
                        backend=default_backend()
                    )

                    #Genera la clave compartida que deberia ser igual a la del remitente.
                    shared_secret = self.private_key.exchange(ec.ECDH(),
                                                              sender_public_key)
                    derived_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=None,
                        info=b'handshake data'
                    ).derive(shared_secret)

                    #Desencripta el mensaje con ChaCha20-Poly1305.
                    chacha = ChaCha20Poly1305(derived_key)
                    nonce = base64.b64decode(msg["nonce"])
                    ciphertext = base64.b64decode(msg["ciphertext"])
                    sender_sig = base64.b64decode(msg["sender_signature"])
                    plaintext = chacha.decrypt(nonce, ciphertext, None)

                    # Verificar firma
                    self.verify_signature(plaintext.decode('utf-8'), sender_sig, "certificate.pem")

                    print(f"Decrypted message: {plaintext.decode('utf-8')}")
        except FileNotFoundError:
            print("No messages found.")
        except cryptography.exceptions.InvalidTag:
            print(
                "Failed to decrypt: Invalid tag (data may be corrupted or the key/nonce is incorrect).")
    
    #Finaliza la sesion del usuario.
    def end_session(self):
        self.private_key = None
        gui = GUIManager 
        gui.print_msg(f"Session ended for {self.username}.", "red")

    
    # metodo para firmar mensajes
    def sign_message(self, message):
        signature = self.private_key.sign(
                message.encode(),
                ec.ECDSA(hashes.SHA256())
        )
        return signature
    
    # metodo para verificar firmas de mensajes
    def verify_signature(self, message, signature, sender_cert_path):
        with open(sender_cert_path, "rb") as f:
            sender_cert = load_pem_x509_certificate(f.read())

        sender_public_key = sender_cert.public_key()

        # Verificar firma
        try:
            sender_public_key.verify(
                    signature,
                    message.encode(),
                    ec.ECDSA(hashes.SHA256())
            )
            print("Firma válida.")
        except InvalidSignature:
            print("Firma inválida.")

