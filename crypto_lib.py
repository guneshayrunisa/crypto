# crypto_lib.py
import base64
from dataclasses import dataclass
from Crypto.Cipher import AES, DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Padding hatası (blok boyutu).")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding hatası (pad_len).")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding hatası (içerik).")
    return data[:-pad_len]

# ---------- AES (CBC) ----------
def aes_encrypt_cbc(plaintext: str, key_16: bytes) -> dict:
    iv = get_random_bytes(16)
    cipher = AES.new(key_16, AES.MODE_CBC, iv=iv)
    pt = pkcs7_pad(plaintext.encode("utf-8"), 16)
    ct = cipher.encrypt(pt)
    return {"iv_b64": b64e(iv), "ct_b64": b64e(ct)}

def aes_decrypt_cbc(iv_b64: str, ct_b64: str, key_16: bytes) -> str:
    iv = b64d(iv_b64)
    ct = b64d(ct_b64)
    cipher = AES.new(key_16, AES.MODE_CBC, iv=iv)
    pt = pkcs7_unpad(cipher.decrypt(ct), 16)
    return pt.decode("utf-8", errors="replace")

# ---------- DES (CBC) ----------
def des_encrypt_cbc(plaintext: str, key_8: bytes) -> dict:
    iv = get_random_bytes(8)
    cipher = DES.new(key_8, DES.MODE_CBC, iv=iv)
    pt = pkcs7_pad(plaintext.encode("utf-8"), 8)
    ct = cipher.encrypt(pt)
    return {"iv_b64": b64e(iv), "ct_b64": b64e(ct)}

def des_decrypt_cbc(iv_b64: str, ct_b64: str, key_8: bytes) -> str:
    iv = b64d(iv_b64)
    ct = b64d(ct_b64)
    cipher = DES.new(key_8, DES.MODE_CBC, iv=iv)
    pt = pkcs7_unpad(cipher.decrypt(ct), 8)
    return pt.decode("utf-8", errors="replace")

# ---------- RSA (OAEP) ----------
@dataclass
class RSAKeyPair:
    private_pem: bytes
    public_pem: bytes

def rsa_generate_keypair(bits: int = 2048) -> RSAKeyPair:
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()
    return RSAKeyPair(private_pem=priv, public_pem=pub)

def rsa_encrypt_bytes(public_pem: bytes, data: bytes) -> bytes:
    pub = RSA.import_key(public_pem)
    cipher = PKCS1_OAEP.new(pub)
    return cipher.encrypt(data)

def rsa_decrypt_bytes(private_pem: bytes, data: bytes) -> bytes:
    priv = RSA.import_key(private_pem)
    cipher = PKCS1_OAEP.new(priv)
    return cipher.decrypt(data)

def rsa_encrypt_text(public_pem: bytes, text: str) -> str:
    # RSA ile direkt mesaj şifreleme: mesaj kısa olmalı (OAEP sınırı var)
    ct = rsa_encrypt_bytes(public_pem, text.encode("utf-8"))
    return b64e(ct)

def rsa_decrypt_text(private_pem: bytes, ct_b64: str) -> str:
    pt = rsa_decrypt_bytes(private_pem, b64d(ct_b64))
    return pt.decode("utf-8", errors="replace")
