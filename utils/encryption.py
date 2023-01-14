from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64


def encrypt_note(note: str, password: str):
    note = note.encode()
    password = password.encode()
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    init_vector = get_random_bytes(16)
    aes = AES.new(key, AES.MODE_CBC, init_vector)
    note_base64 = base64.b64encode(note)
    note_ready = note_base64 + b'='*(16-(len(note_base64) % 16))
    return base64.b64encode(aes.encrypt(note_ready)).decode(), base64.b64encode(salt).decode(), base64.b64encode(init_vector).decode()


def decrypt_note(note_base64: str, password: str, salt_base64: str, init_vector_base64: str):
    note = base64.b64decode(note_base64)
    salt = base64.b64decode(salt_base64)
    password = password.encode()
    init_vector = base64.b64decode(init_vector_base64)

    key = PBKDF2(password, salt, 32, count=1000000, hmac_hash_module=SHA512)
    aes = AES.new(key, AES.MODE_CBC, init_vector)
    return base64.b64decode(aes.decrypt(note)).decode()
