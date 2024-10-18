from Crypto.Util import number
from Crypto.Random import random

def generate_keys(bits=1024):
    p = number.getPrime(bits)
    g = random.randint(2, p-1)
    x = random.randint(1, p-2)
    y = pow(g, x, p)
    return (p, g, y), x

def generar_llaves_elgamal():
    try:
        with open('elgamal_sk.pem', 'r') as f:
            print("Cargando llaves ElGamal.")
    except FileNotFoundError:
        public_key, private_key = generate_keys()
        guardar_llaves(public_key, private_key)

def guardar_llaves(public_key, private_key, pub_key_file='elgamal_pk.pem', priv_key_file='elgamal_sk.pem'):
    p, g, y = public_key
    with open(pub_key_file, 'w') as pub_file:
        pub_file.write(f"{p:x}\n{g:x}\n{y:x}")
    with open(priv_key_file, 'w') as priv_file:
        priv_file.write(f"{private_key:x}")

def cargar_llave_privada(priv_key_file='elgamal_sk.pem'):
    with open(priv_key_file, 'r') as priv_file:
        x = int(priv_file.readline(), 16)
    return x

def cargar_llave_publica(pub_key_file='elgamal_pk.pem'):
    with open(pub_key_file, 'r') as pub_file:
        p = int(pub_file.readline(), 16)
        g = int(pub_file.readline(), 16)
        y = int(pub_file.readline(), 16)
    return (p, g, y)

def cifrar_elgamal(public_key, plaintext):
    p, g, y = public_key
    plaintext_number = text_to_number(plaintext)
    k = random.randint(1, p-2)
    a = pow(g, k, p)
    b = (pow(y, k, p) * plaintext_number) % p
    return a, b

def descifrar_elgamal(private_key, ciphertext, public_key):
    p, g, y = public_key
    a, b = ciphertext
    x = private_key
    s = pow(a, x, p)
    plaintext_number = (b * number.inverse(s, p)) % p
    return number_to_text(plaintext_number)

def text_to_number(text):
    return int.from_bytes(text.encode('utf-8'), 'big')

def number_to_text(number):
    byte_data = number.to_bytes((number.bit_length() + 7) // 8, 'big')
    return byte_data.rstrip(b'\x00').decode('utf-8')

if __name__ == "__main__":
    generar_llaves_elgamal()
    public_key = cargar_llave_publica()
    private_key = cargar_llave_privada()

    plaintext = 'Este es el mensaje para cifrar con ElGamal'
    ciphertext = cifrar_elgamal(public_key, plaintext)
    a, b = ciphertext

    a_bytes = a.to_bytes((a.bit_length() + 7) // 8, 'big')
    b_bytes = b.to_bytes((b.bit_length() + 7) // 8, 'big')
    print("Parte pública (a):", a_bytes)
    print("Mensaje cifrado (b):", b_bytes)

    decrypted = descifrar_elgamal(private_key, ciphertext, public_key)
    print("Mensaje descifrado:", decrypted)