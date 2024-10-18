import socket
import threading

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from functions import (
    decrypt_message,
    ecdh_shared_secret,
    encrypt_message,
)

PORT = 1234  # Puerto del cliente
SERVER = "127.0.0.1"  # Dirección IP del servidor
ADDR = (SERVER, PORT)  # Dirección del servidor

HEADER_SIZE = 64  # Tamaño del encabezado
ENCODING_FORMAT = "utf-8"  # Formato de codificación
AES_BLOCK_SIZE = 16  # Tamaño del bloque de AES para CBC

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(ADDR)

# Generar clave privada y pública ECC (curva P-256)
client_private_key = ECC.generate(curve="P-256")
client_public_key = client_private_key.public_key()

# Enviar la clave pública serializada (en formato DER) al servidor
client_public_key_bytes = client_public_key.export_key(format="DER")
client_public_key_length = str(len(client_public_key_bytes)).encode(ENCODING_FORMAT)
client_public_key_length += b" " * (HEADER_SIZE - len(client_public_key_length))
client.send(client_public_key_length)  # Enviar la longitud primero
client.send(client_public_key_bytes)  # Luego enviar la clave pública

# Recibir la longitud de la clave pública del servidor
server_public_key_length = int(client.recv(HEADER_SIZE).decode(ENCODING_FORMAT))
server_public_key_bytes = client.recv(
    server_public_key_length
)  # Recibir la clave pública del servidor
server_public_key = ECC.import_key(
    server_public_key_bytes
)  # Importar la clave pública del servidor

# Generar el secreto compartido usando el intercambio manual
shared_secret = ecdh_shared_secret(client_private_key, server_public_key)

# Derivar clave AES usando HKDF
derived_key = HKDF(
    str(shared_secret).encode(), 32, b"", SHA256
)  # Clave AES de 256 bits


# Recepción de mensajes del servidor
def receive_messages(aes_key):
    while True:
        try:
            message_length = client.recv(HEADER_SIZE).decode(ENCODING_FORMAT)
            if message_length:
                message_length = int(message_length)
                encrypted_message = client.recv(message_length)

                # Descifrar el mensaje recibido
                decrypted_message = decrypt_message(aes_key, encrypted_message).decode(
                    ENCODING_FORMAT
                )
                print(f"[📩] Mensaje del servidor: {decrypted_message}")
        except:
            print("[⚠️] La conexión se ha cerrado.")
            client.close()
            break


# Enviar mensajes al servidor
def send_messages(message, aes_key):
    encrypted_message = encrypt_message(aes_key, message.encode(ENCODING_FORMAT))
    message_length = len(encrypted_message)
    send_length = str(message_length).encode(ENCODING_FORMAT)
    send_length += b" " * (HEADER_SIZE - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)


# Iniciar hilo para manejar la recepción de mensajes
receive_thread = threading.Thread(target=receive_messages, args=(derived_key,))
receive_thread.start()

# Bucle para enviar mensajes
while True:
    user_input = input("[Escribe tu mensaje]: ")
    send_messages(user_input, derived_key)
    if user_input == "exit":
        break

client.close()
