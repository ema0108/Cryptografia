import socket
import threading
from math import e

from Crypto.PublicKey import ECC
from functions import (
    decrypt_message,
    derive_symmetric_key,
    ecdh_shared_secret,
    encrypt_message,
    generate_ecc_keys,
)

PORT = 4321  # Puerto del servidor
SERVER = "127.0.0.1"  # Dirección IP del servidor
ADDR = (SERVER, PORT)  # Dirección del servidor


HEADER_SIZE = 64
ENCODING_FORMAT = "utf-8"
AES_BLOCK_SIZE = 16

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDR)

clients = []
shared_secrets = {}


# Manejar la comunicación con los clientes
def handle_client(connection, address):
    print(f"[🔗] Nueva conexión desde {address}.")
    clients.append(connection)

    # Intercambio de llaves Diffie-Hellman (ECC P-256)
    server_private_key, server_public_key = generate_ecc_keys()

    # Enviar la clave pública del servidor al cliente
    server_public_key_bytes = server_public_key.export_key(format="DER")
    server_public_key_length = str(len(server_public_key_bytes)).encode(ENCODING_FORMAT)
    server_public_key_length += b" " * (HEADER_SIZE - len(server_public_key_length))
    connection.send(server_public_key_length)
    connection.send(server_public_key_bytes)

    # Recibir la clave pública del cliente
    client_public_key_length = int(connection.recv(HEADER_SIZE).decode(ENCODING_FORMAT))
    client_public_key_bytes = connection.recv(client_public_key_length)
    client_public_key = ECC.import_key(client_public_key_bytes)

    # Generar el secreto compartido usando el intercambio manual
    shared_secret = ecdh_shared_secret(server_private_key, client_public_key)
    symmetric_key = derive_symmetric_key(str(shared_secret).encode())
    shared_secrets[connection] = symmetric_key

    print(f"[🔑] Secreto compartido generado con {address}")

    connected = True
    while connected:
        try:
            message_length = connection.recv(HEADER_SIZE).decode(ENCODING_FORMAT)
            if message_length:
                message_length = int(message_length)
                encrypted_message = connection.recv(message_length)
                message = decrypt_message(symmetric_key, encrypted_message).decode(
                    ENCODING_FORMAT
                )

                if message == "exit":
                    connected = False

                print(f"\n[📨] Mensaje de {address}: {message}")
                broadcast(message, connection)
        except:
            break

    connection.close()
    clients.remove(connection)
    shared_secrets.pop(connection, None)
    print(f"[❌] Cliente {address} desconectado.")


# Envía un mensaje cifrado a todos los clientes conectados excepto al actual
def broadcast(message, current_connection):
    for client in clients:
        if client != current_connection:
            try:
                send_message(client, message)
            except:
                client.close()
                clients.remove(client)


# Envía un mensaje cifrado a un cliente específico
def send_message(client, message):
    key = shared_secrets[client]
    encrypted_message = encrypt_message(key, message.encode(ENCODING_FORMAT))
    message_length = len(encrypted_message)
    send_length = str(message_length).encode(ENCODING_FORMAT)
    send_length += b" " * (HEADER_SIZE - len(send_length))
    client.send(send_length)
    client.send(encrypted_message)


# Envía mensajes desde el servidor a los clientes
def send_messages_from_server():
    while True:
        message = input("Escribe un mensaje para los clientes: ")
        if message:
            broadcast(f"[Servidor] {message}", None)
        if message == "exit":
            break

    for client in clients:
        send_message(client, "exit")
        client.close()
    server.close()


# Iniciar el servidor
def start():
    server.listen()
    print(f"Servidor operativo en {SERVER}:{PORT}")

    server_message_thread = threading.Thread(target=send_messages_from_server)
    server_message_thread.start()

    while True:
        connection, address = server.accept()
        thread = threading.Thread(target=handle_client, args=(connection, address))
        thread.start()
        print(f"[🔢] Conexiones activas: {threading.active_count() - 1}")


print("[🚀] Iniciando servidor...")
start()
