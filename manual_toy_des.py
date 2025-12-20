# manual_toy_des.py
import base64
from Crypto.Random import get_random_bytes

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Padding hatası.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding hatası.")
    return data[:-pad_len]

# 4-bit S-box benzeri (0..15 -> 0..15)
SBOX = [0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7]

def sbox32(x: int) -> int:
    # 32-bit değeri nibble nibble SBOX'tan geçir
    out = 0
    for i in range(8):
        nib = (x >> (i*4)) & 0xF
        out |= (SBOX[nib] << (i*4))
    return out

def rotl32(x: int, r: int) -> int:
    return ((x << r) & 0xFFFFFFFF) | (x >> (32 - r))

def round_f(r: int, subkey: int) -> int:
    # basit F fonksiyonu: XOR -> SBOX -> rotate
    x = (r ^ subkey) & 0xFFFFFFFF
    x = sbox32(x)
    x = rotl32(x, 3)
    return x

def derive_subkeys(key8: bytes, rounds: int = 8) -> list[int]:
    # 8 byte key -> 64-bit -> round subkey'ler (32-bit)
    k = int.from_bytes(key8, "big")
    subs = []
    for i in range(rounds):
        k = ((k << 7) & ((1<<64)-1)) | (k >> (64-7))  # 64-bit rotate
        subs.append((k ^ (0x9E3779B97F4A7C15 + i)) & 0xFFFFFFFF)
    return subs

def feistel_encrypt_block(block8: bytes, key8: bytes, rounds: int = 8) -> bytes:
    x = int.from_bytes(block8, "big")
    L = (x >> 32) & 0xFFFFFFFF
    R = x & 0xFFFFFFFF
    sub = derive_subkeys(key8, rounds)
    for i in range(rounds):
        L, R = R, (L ^ round_f(R, sub[i])) & 0xFFFFFFFF
    y = ((L & 0xFFFFFFFF) << 32) | (R & 0xFFFFFFFF)
    return y.to_bytes(8, "big")

def feistel_decrypt_block(block8: bytes, key8: bytes, rounds: int = 8) -> bytes:
    x = int.from_bytes(block8, "big")
    L = (x >> 32) & 0xFFFFFFFF
    R = x & 0xFFFFFFFF
    sub = derive_subkeys(key8, rounds)
    for i in reversed(range(rounds)):
        L, R = (R ^ round_f(L, sub[i])) & 0xFFFFFFFF, L
    y = ((L & 0xFFFFFFFF) << 32) | (R & 0xFFFFFFFF)
    return y.to_bytes(8, "big")

def toy_des_encrypt_cbc(plaintext: str, key8: bytes) -> dict:
    iv = get_random_bytes(8)
    pt = pkcs7_pad(plaintext.encode("utf-8"), 8)
    out = b""
    prev = iv
    for i in range(0, len(pt), 8):
        blk = pt[i:i+8]
        x = bytes(a ^ b for a, b in zip(blk, prev))
        c = feistel_encrypt_block(x, key8)
        out += c
        prev = c
    return {"iv_b64": b64e(iv), "ct_b64": b64e(out), "rounds": 8}

def toy_des_decrypt_cbc(iv_b64: str, ct_b64: str, key8: bytes) -> str:
    iv = b64d(iv_b64)
    ct = b64d(ct_b64)
    if len(ct) % 8 != 0:
        raise ValueError("Ciphertext blok boyutu hatası.")
    out = b""
    prev = iv
    for i in range(0, len(ct), 8):
        c = ct[i:i+8]
        x = feistel_decrypt_block(c, key8)
        p = bytes(a ^ b for a, b in zip(x, prev))
        out += p
        prev = c
    pt = pkcs7_unpad(out, 8)
    return pt.decode("utf-8", errors="replace")
