"""
Manuel DES (Data Encryption Standard) Implementasyonu
CBC (Cipher Block Chaining) modu ile
"""
import base64
from Crypto.Random import get_random_bytes

# DES Permütasyon Tabloları
# Initial Permutation (IP)
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Final Permutation (IP^-1)
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Expansion (E) - 32 bit -> 48 bit
E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# Permutation (P)
P = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

# S-Boxes (8 adet, her biri 4x16)
S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Key Schedule Permutations
PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

# Shift schedule for key generation
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


def permute(block, table):
    """Permütasyon işlemi"""
    return ''.join(block[i - 1] for i in table)


def left_shift(bits, n):
    """n pozisyon sola kaydırma"""
    return bits[n:] + bits[:n]


def xor(bits1, bits2):
    """XOR işlemi"""
    return ''.join('1' if b1 != b2 else '0' for b1, b2 in zip(bits1, bits2))


def s_box_lookup(bits, s_box_index):
    """S-Box lookup"""
    row = int(bits[0] + bits[5], 2)
    col = int(bits[1:5], 2)
    val = S_BOXES[s_box_index][row][col]
    return format(val, '04b')


def generate_round_keys(key_bits):
    """16 round key üretimi"""
    # PC1 permütasyonu
    key_56 = permute(key_bits, PC1)
    
    # C ve D'ye böl (her biri 28 bit)
    C = key_56[:28]
    D = key_56[28:]
    
    round_keys = []
    for round_num in range(16):
        # Shift
        C = left_shift(C, SHIFT_SCHEDULE[round_num])
        D = left_shift(D, SHIFT_SCHEDULE[round_num])
        
        # PC2 permütasyonu (48 bit round key)
        round_key = permute(C + D, PC2)
        round_keys.append(round_key)
    
    return round_keys


def f_function(right_32, round_key_48):
    """DES F fonksiyonu"""
    # Expansion (32 -> 48 bit)
    expanded = permute(right_32, E)
    
    # XOR with round key
    xored = xor(expanded, round_key_48)
    
    # S-Box substitution (48 -> 32 bit)
    s_output = ''
    for i in range(8):
        s_input = xored[i * 6:(i + 1) * 6]
        s_output += s_box_lookup(s_input, i)
    
    # Permutation P
    result = permute(s_output, P)
    return result


def des_block_encrypt(block_64_bits, round_keys):
    """Tek bir 64-bit bloğu şifrele"""
    # Initial Permutation
    block = permute(block_64_bits, IP)
    
    # L ve R'ye böl
    L = block[:32]
    R = block[32:]
    
    # 16 round
    for round_key in round_keys:
        new_R = xor(L, f_function(R, round_key))
        L = R
        R = new_R
    
    # Son swap (R16, L16)
    combined = R + L
    
    # Final Permutation
    ciphertext = permute(combined, FP)
    return ciphertext


def des_block_decrypt(block_64_bits, round_keys):
    """Tek bir 64-bit bloğu deşifre et (round key'ler ters sırada)"""
    return des_block_encrypt(block_64_bits, round_keys[::-1])


def bytes_to_bits(data):
    """Bytes'ı bit string'e çevir"""
    return ''.join(format(byte, '08b') for byte in data)


def bits_to_bytes(bits):
    """Bit string'i bytes'a çevir"""
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def pkcs7_pad(data, block_size=8):
    """PKCS#7 padding"""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data):
    """PKCS#7 unpadding"""
    pad_len = data[-1]
    return data[:-pad_len]


def manual_des_encrypt_cbc(plaintext: str, key: bytes) -> dict:
    """
    Manuel DES CBC şifreleme
    Returns: {'iv_b64': str, 'ct_b64': str}
    """
    if len(key) != 8:
        raise ValueError("DES key 8 byte olmalı")
    
    # Key'i bit string'e çevir
    key_bits = bytes_to_bits(key)
    
    # Round key'leri üret
    round_keys = generate_round_keys(key_bits)
    
    # Plaintext'i bytes'a çevir ve padding ekle
    pt_bytes = plaintext.encode('utf-8')
    pt_padded = pkcs7_pad(pt_bytes, 8)
    
    # IV oluştur (8 byte = 64 bit)
    iv = get_random_bytes(8)
    iv_bits = bytes_to_bits(iv)
    
    # CBC mode encryption
    ct_bits = ''
    prev_block = iv_bits
    
    for i in range(0, len(pt_padded), 8):
        block = pt_padded[i:i+8]
        block_bits = bytes_to_bits(block)
        
        # XOR with previous ciphertext (or IV)
        xored = xor(block_bits, prev_block)
        
        # DES encrypt
        ct_block = des_block_encrypt(xored, round_keys)
        ct_bits += ct_block
        prev_block = ct_block
    
    # Bits'i bytes'a çevir
    ct_bytes = bits_to_bytes(ct_bits)
    
    return {
        'iv_b64': base64.b64encode(iv).decode('utf-8'),
        'ct_b64': base64.b64encode(ct_bytes).decode('utf-8')
    }


def manual_des_decrypt_cbc(iv_b64: str, ct_b64: str, key: bytes) -> str:
    """
    Manuel DES CBC deşifreleme
    """
    if len(key) != 8:
        raise ValueError("DES key 8 byte olmalı")
    
    # Key'i bit string'e çevir
    key_bits = bytes_to_bits(key)
    
    # Round key'leri üret
    round_keys = generate_round_keys(key_bits)
    
    # Base64 decode
    iv = base64.b64decode(iv_b64)
    ct_bytes = base64.b64decode(ct_b64)
    
    iv_bits = bytes_to_bits(iv)
    ct_bits = bytes_to_bits(ct_bytes)
    
    # CBC mode decryption
    pt_bits = ''
    prev_block = iv_bits
    
    for i in range(0, len(ct_bits), 64):
        ct_block = ct_bits[i:i+64]
        
        # DES decrypt
        decrypted = des_block_decrypt(ct_block, round_keys)
        
        # XOR with previous ciphertext (or IV)
        pt_block = xor(decrypted, prev_block)
        pt_bits += pt_block
        prev_block = ct_block
    
    # Bits'i bytes'a çevir
    pt_padded = bits_to_bytes(pt_bits)
    
    # Padding kaldır
    pt_bytes = pkcs7_unpad(pt_padded)
    
    return pt_bytes.decode('utf-8')


# Test
if __name__ == "__main__":
    key = b"secret12"  # 8 byte
    plaintext = "Merhaba DES!"
    
    print(f"Key: {key}")
    print(f"Plaintext: {plaintext}")
    
    # Encrypt
    result = manual_des_encrypt_cbc(plaintext, key)
    print(f"\nIV: {result['iv_b64']}")
    print(f"Ciphertext: {result['ct_b64']}")
    
    # Decrypt
    decrypted = manual_des_decrypt_cbc(result['iv_b64'], result['ct_b64'], key)
    print(f"\nDecrypted: {decrypted}")
    print(f"Match: {decrypted == plaintext}")