"""
Basitleştirilmiş AES-128 Implementasyonu (Manuel)
CBC (Cipher Block Chaining) modu ile
"""
import base64
from Crypto.Random import get_random_bytes

# AES S-Box (Rijndael S-Box)
S_BOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-Box
INV_S_BOX = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Rcon (Round Constant) - Key expansion için
RCON = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a
]


def xor_bytes(a, b):
    """İki byte dizisini XOR'la"""
    return bytes(x ^ y for x, y in zip(a, b))


def sub_bytes(state):
    """S-Box substitution"""
    return [[S_BOX[byte] for byte in row] for row in state]


def inv_sub_bytes(state):
    """Inverse S-Box substitution"""
    return [[INV_S_BOX[byte] for byte in row] for row in state]


def shift_rows(state):
    """Shift Rows transformation"""
    state[1] = state[1][1:] + state[1][:1]  # 1 sola kaydır
    state[2] = state[2][2:] + state[2][:2]  # 2 sola kaydır
    state[3] = state[3][3:] + state[3][:3]  # 3 sola kaydır
    return state


def inv_shift_rows(state):
    """Inverse Shift Rows"""
    state[1] = state[1][-1:] + state[1][:-1]  # 1 sağa kaydır
    state[2] = state[2][-2:] + state[2][:-2]  # 2 sağa kaydır
    state[3] = state[3][-3:] + state[3][:-3]  # 3 sağa kaydır
    return state


def gmul(a, b):
    """Galois Field (2^8) çarpma"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x1b  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p & 0xFF


def mix_columns(state):
    """Mix Columns transformation"""
    for i in range(4):
        s0, s1, s2, s3 = state[0][i], state[1][i], state[2][i], state[3][i]
        state[0][i] = gmul(s0, 2) ^ gmul(s1, 3) ^ s2 ^ s3
        state[1][i] = s0 ^ gmul(s1, 2) ^ gmul(s2, 3) ^ s3
        state[2][i] = s0 ^ s1 ^ gmul(s2, 2) ^ gmul(s3, 3)
        state[3][i] = gmul(s0, 3) ^ s1 ^ s2 ^ gmul(s3, 2)
    return state


def inv_mix_columns(state):
    """Inverse Mix Columns"""
    for i in range(4):
        s0, s1, s2, s3 = state[0][i], state[1][i], state[2][i], state[3][i]
        state[0][i] = gmul(s0, 14) ^ gmul(s1, 11) ^ gmul(s2, 13) ^ gmul(s3, 9)
        state[1][i] = gmul(s0, 9) ^ gmul(s1, 14) ^ gmul(s2, 11) ^ gmul(s3, 13)
        state[2][i] = gmul(s0, 13) ^ gmul(s1, 9) ^ gmul(s2, 14) ^ gmul(s3, 11)
        state[3][i] = gmul(s0, 11) ^ gmul(s1, 13) ^ gmul(s2, 9) ^ gmul(s3, 14)
    return state


def add_round_key(state, round_key):
    """Round key ile XOR"""
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]
    return state


def key_expansion(key):
    """128-bit key'den 11 round key üret (AES-128 için 10 round + 1 başlangıç)"""
    key_symbols = [list(key[i:i+4]) for i in range(0, 16, 4)]
    
    for i in range(4, 44):  # 44 kelime = 11 round key
        temp = key_symbols[i-1][:]
        if i % 4 == 0:
            # RotWord
            temp = temp[1:] + temp[:1]
            # SubWord
            temp = [S_BOX[b] for b in temp]
            # Rcon
            temp[0] ^= RCON[i // 4]
        
        key_symbols.append([key_symbols[i-4][j] ^ temp[j] for j in range(4)])
    
    # 11 round key'e dönüştür (her biri 4x4 state)
    round_keys = []
    for i in range(11):
        round_key = [[key_symbols[i*4 + j][k] for j in range(4)] for k in range(4)]
        round_keys.append(round_key)
    
    return round_keys


def bytes_to_state(block):
    """16 byte'ı 4x4 state matrix'e çevir (column-major)"""
    return [[block[i + 4*j] for j in range(4)] for i in range(4)]


def state_to_bytes(state):
    """4x4 state matrix'i 16 byte'a çevir"""
    return bytes(state[i][j] for j in range(4) for i in range(4))


def aes_encrypt_block(plaintext_block, round_keys):
    """Tek bir 16-byte bloğu şifrele"""
    state = bytes_to_state(plaintext_block)
    
    # Initial round
    state = add_round_key(state, round_keys[0])
    
    # 9 main rounds
    for round_num in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_num])
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[10])
    
    return state_to_bytes(state)


def aes_decrypt_block(ciphertext_block, round_keys):
    """Tek bir 16-byte bloğu deşifre et"""
    state = bytes_to_state(ciphertext_block)
    
    # Initial round
    state = add_round_key(state, round_keys[10])
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    # 9 main rounds
    for round_num in range(9, 0, -1):
        state = add_round_key(state, round_keys[round_num])
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    
    # Final round
    state = add_round_key(state, round_keys[0])
    
    return state_to_bytes(state)


def pkcs7_pad(data, block_size=16):
    """PKCS#7 padding"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """PKCS#7 unpadding"""
    pad_len = data[-1]
    return data[:-pad_len]


def manual_aes_encrypt_cbc(plaintext: str, key: bytes) -> dict:
    """
    Manuel AES-128 CBC şifreleme
    Returns: {'iv_b64': str, 'ct_b64': str}
    """
    if len(key) != 16:
        raise ValueError("AES-128 key 16 byte olmalı")
    
    # Round key'leri üret
    round_keys = key_expansion(key)
    
    # Plaintext'i bytes'a çevir ve padding ekle
    pt_bytes = plaintext.encode('utf-8')
    pt_padded = pkcs7_pad(pt_bytes, 16)
    
    # IV oluştur (16 byte = 128 bit)
    iv = get_random_bytes(16)
    
    # CBC mode encryption
    ct_bytes = b''
    prev_block = iv
    
    for i in range(0, len(pt_padded), 16):
        block = pt_padded[i:i+16]
        
        # XOR with previous ciphertext (or IV)
        xored = xor_bytes(block, prev_block)
        
        # AES encrypt
        ct_block = aes_encrypt_block(xored, round_keys)
        ct_bytes += ct_block
        prev_block = ct_block
    
    return {
        'iv_b64': base64.b64encode(iv).decode('utf-8'),
        'ct_b64': base64.b64encode(ct_bytes).decode('utf-8')
    }


def manual_aes_decrypt_cbc(iv_b64: str, ct_b64: str, key: bytes) -> str:
    """
    Manuel AES-128 CBC deşifreleme
    """
    if len(key) != 16:
        raise ValueError("AES-128 key 16 byte olmalı")
    
    # Round key'leri üret
    round_keys = key_expansion(key)
    
    # Base64 decode
    iv = base64.b64decode(iv_b64)
    ct_bytes = base64.b64decode(ct_b64)
    
    # CBC mode decryption
    pt_bytes = b''
    prev_block = iv
    
    for i in range(0, len(ct_bytes), 16):
        ct_block = ct_bytes[i:i+16]
        
        # AES decrypt
        decrypted = aes_decrypt_block(ct_block, round_keys)
        
        # XOR with previous ciphertext (or IV)
        pt_block = xor_bytes(decrypted, prev_block)
        pt_bytes += pt_block
        prev_block = ct_block
    
    # Padding kaldır
    pt_unpadded = pkcs7_unpad(pt_bytes)
    
    return pt_unpadded.decode('utf-8')


# Test
if __name__ == "__main__":
    key = b"MySecretKey12345"  # 16 byte
    plaintext = "Merhaba AES-128!"
    
    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")
    
    # Encrypt
    result = manual_aes_encrypt_cbc(plaintext, key)
    print(f"\nIV: {result['iv_b64']}")
    print(f"Ciphertext: {result['ct_b64']}")
    
    # Decrypt
    decrypted = manual_aes_decrypt_cbc(result['iv_b64'], result['ct_b64'], key)
    print(f"\nDecrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")