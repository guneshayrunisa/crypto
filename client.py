# client.py
import socket
import base64
import ast
from Crypto.Random import get_random_bytes
from protocol import send_packet, recv_packet
from crypto_lib import (
    rsa_encrypt_bytes, rsa_encrypt_text,
    aes_encrypt_cbc, des_encrypt_cbc, b64e
)
from manual_toy_des import toy_des_encrypt_cbc

# KLASİK ŞİFRELER
from algorithms import (
    CaesarCipherTR, VigenereCipherTR, AffineCipherTR, SubstitutionCipherTR,
    RailFenceCipherTR, RouteCipherTR, ColumnarCipherTR, PolybiusCipherTR,
    PlayfairCipherTR, HillCipherTR
)

HOST = "127.0.0.1"
PORT = 9000


def choose(prompt: str, options: list[str]) -> str:
    while True:
        val = input(f"{prompt} {options}: ").strip().upper()
        if val in options:
            return val
        print("Geçersiz seçim.")


CLASSIC_MAP = {
    "CAESAR": CaesarCipherTR(),
    "VIGENERE": VigenereCipherTR(),
    "AFFINE": AffineCipherTR(),
    "SUBSTITUTION": SubstitutionCipherTR(),
    "RAILFENCE": RailFenceCipherTR(),
    "ROUTE": RouteCipherTR(),
    "COLUMNAR": ColumnarCipherTR(),
    "POLYBIUS": PolybiusCipherTR(),
    "PLAYFAIR": PlayfairCipherTR(),
    "HILL": HillCipherTR(),
}


def input_key_for_classic(alg: str):
    """
    Klasik algoritmalar için key1/key2 alır.
    Dönen değerler JSON-serialize edilebilir olmalı.
    """
    alg = alg.upper()

    if alg == "CAESAR":
        key1 = int(input("Kaydırma (örn 3): ").strip())
        return key1, None

    if alg == "VIGENERE":
        key1 = input("Anahtar kelime (örn KRIPTO): ").strip()
        return key1, None

    if alg == "AFFINE":
        a = int(input("a (29 ile aralarında asal olmalı, örn 5): ").strip())
        b = int(input("b (örn 8): ").strip())
        return a, b

    if alg == "SUBSTITUTION":
        key1 = input("29 harflik permütasyon anahtarı (Türkçe alfabe): ").strip()
        return key1, None

    if alg == "RAILFENCE":
        rails = int(input("Ray sayısı (örn 3): ").strip())
        return rails, None

    if alg == "ROUTE":
        cols = int(input("Sütun sayısı (örn 5): ").strip())
        return cols, None

    if alg == "COLUMNAR":
        key1 = input("Anahtar kelime (örn KRIPTO): ").strip()
        return key1, None

    if alg == "POLYBIUS":
        # Anahtar yok
        return None, None

    if alg == "PLAYFAIR":
        key1 = input("Anahtar kelime (EN Playfair, örn SECURITY): ").strip()
        return key1, None

    if alg == "HILL":
        print("Hill matrisi gir (örn [[3,3],[2,5]] veya [[6,24,1],[13,16,10],[20,17,15]])")
        mat_str = input("Matris: ").strip()
        key1 = ast.literal_eval(mat_str)  # [[...],[...]]
        return key1, None

    # default
    return None, None


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))

        hello = recv_packet(s)
        server_pub_pem = base64.b64decode(hello["rsa_public_pem_b64"].encode("ascii"))
        print("[CLIENT] Server RSA public key alındı.")

        # Anahtarları üret (ödev izin veriyor: başlangıçta üretilebilir)
        aes_key = get_random_bytes(16)
        des_key = get_random_bytes(8)
        toy_key = get_random_bytes(8)

        # Key exchange: AES, DES, TOYDES anahtarlarını RSA ile gönder
        for which, key in [("AES", aes_key), ("DES", des_key), ("TOYDES", toy_key)]:
            enc = rsa_encrypt_bytes(server_pub_pem, key)
            send_packet(s, {"type": "key_exchange", "which": which, "enc_key_b64": b64e(enc)})
            ack = recv_packet(s)
            print(f"[CLIENT] {ack['msg']}")

        all_algs = ["AES", "DES", "RSA", "TOYDES"] + list(CLASSIC_MAP.keys())

        while True:
            alg = choose("Algoritma seç", all_algs)
            msg = input("Mesaj: ")
            if msg.strip().lower() == "/quit":
                send_packet(s, {"type": "quit"})
                break

            # --- KLASİK ŞİFRELER ---
            if alg in CLASSIC_MAP:
                cipher = CLASSIC_MAP[alg]
                key1, key2 = input_key_for_classic(alg)

                ct_text = cipher.encrypt(msg, key1, key2)
                pkt = {
                    "type": "message",
                    "algorithm": alg,
                    "mode": "classic",
                    "ct_text": ct_text,
                    "key1": key1,
                    "key2": key2,
                }

            # --- AES / DES / TOYDES / RSA (mevcut sistem) ---
            elif alg == "AES":
                out = aes_encrypt_cbc(msg, aes_key)
                pkt = {"type": "message", "algorithm": "AES", "mode": "lib", **out}

            elif alg == "DES":
                out = des_encrypt_cbc(msg, des_key)
                pkt = {"type": "message", "algorithm": "DES", "mode": "lib", **out}

            elif alg == "TOYDES":
                out = toy_des_encrypt_cbc(msg, toy_key)
                pkt = {"type": "message", "algorithm": "TOYDES", "mode": "manual", **out}

            elif alg == "RSA":
                # RSA ile direkt mesaj (kısa olmalı)
                ct_b64 = rsa_encrypt_text(server_pub_pem, msg)
                pkt = {"type": "message", "algorithm": "RSA", "mode": "lib", "ct_b64": ct_b64}

            else:
                continue

            send_packet(s, pkt)
            ack = recv_packet(s)
            print(f"[CLIENT] ACK: {ack['msg']}")
            if "pt" in ack:
                print(f"[CLIENT] SERVER ÇÖZÜM: {ack['pt']}")

if __name__ == "__main__":
    main()
