from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generar_llaves_rsa():
    try:
        with open('rsa_oaep_sk.pem', 'rb') as f:
            print("Cargando llaves RSA_OAEP.")
    except FileNotFoundError:
        key = RSA.generate(1024)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        with open('rsa_oaep_sk.pem', 'wb') as f:
            f.write(private_key)

        with open('rsa_oaep_pk.pem', 'wb') as f:
            f.write(public_key)

def cargar_llave_privada():
    with open('rsa_oaep_sk.pem', 'rb') as f:
        return RSA.import_key(f.read())

def cargar_llave_publica():
    with open('rsa_oaep_pk.pem', 'rb') as f:
        return RSA.import_key(f.read())

def cifrar_rsa_oaep(mensaje):
    public_key = cargar_llave_publica()
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(mensaje)

def descifrar_rsa_oaep(ciphertext):
    private_key = cargar_llave_privada()
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(ciphertext)

if __name__ == "__main__":
    generar_llaves_rsa()

    mensaje = b'Hello RSA_OAEP supongo que sabes cifrar'
    ciphertext = cifrar_rsa_oaep(mensaje)
    print("Mensaje cifrado:", ciphertext)

    mensaje_descifrado = descifrar_rsa_oaep(ciphertext)
    print("Mensaje descifrado:", mensaje_descifrado.decode())