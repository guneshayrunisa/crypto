# server.py
import socket
import base64

from crypto_lib import (
    rsa_generate_keypair, rsa_decrypt_bytes, b64d,
    aes_decrypt_cbc, des_decrypt_cbc, rsa_decrypt_text
)
from protocol import send_packet, recv_packet

# KLASİK ŞİFRELER
from algorithms import (
    CaesarCipherTR, VigenereCipherTR, AffineCipherTR, SubstitutionCipherTR,
    RailFenceCipherTR, RouteCipherTR, ColumnarCipherTR, PolybiusCipherTR,
    PlayfairCipherTR, HillCipherTR
)

HOST = "127.0.0.1"
PORT = 9000


# algorithms/ içindekileri burada map'liyoruz
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


def main():
    kp = rsa_generate_keypair(2048)
    aes_key = None
    des_key = None

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        print(f"[SERVER] Dinleniyor: {HOST}:{PORT}")

        conn, addr = s.accept()
        with conn:
            print(f"[SERVER] Bağlandı: {addr}")

            # 1) Sunucu public key gönderir
            send_packet(conn, {
                "type": "server_hello",
                "rsa_public_pem_b64": base64.b64encode(kp.public_pem).decode("ascii")
            })

            while True:
                pkt = recv_packet(conn)
                ptype = pkt.get("type")

                if ptype == "key_exchange":
                    # istemci AES/DES key'i RSA public ile şifreleyip gönderir
                    which = pkt["which"]  # "AES" / "DES"
                    enc_key_b64 = pkt["enc_key_b64"]
                    enc_key = b64d(enc_key_b64)
                    key = rsa_decrypt_bytes(kp.private_pem, enc_key)

                    if which == "AES":
                        if len(key) != 16:
                            raise ValueError("AES anahtarı 16 byte olmalı.")
                        aes_key = key
                        print("[SERVER] AES anahtarı alındı.")

                    elif which == "DES":
                        if len(key) != 8:
                            raise ValueError("DES anahtarı 8 byte olmalı.")
                        des_key = key
                        print("[SERVER] DES anahtarı alındı.")

                    else:
                        raise ValueError("Bilinmeyen key türü.")

                    send_packet(conn, {"type": "ack", "msg": f"{which} key OK"})

                elif ptype == "message":
                    alg = pkt["algorithm"]     # "AES" "DES" "RSA"  veya klasik şifreler
                    mode = pkt.get("mode")     # "lib" / "manual" / "classic" (opsiyonel)
                    alg_u = str(alg).upper()

                    print(f"[SERVER] Mesaj geldi -> alg={alg_u}, mode={mode}")

                    # --- KLASİK ŞİFRELER ---
                    if alg_u in CLASSIC_MAP:
                        cipher = CLASSIC_MAP[alg_u]
                        # Klasik şifrelerde şifreli metni düz string bekliyoruz
                        ct_text = pkt.get("ct_text")
                        if ct_text is None:
                            ct_text = pkt.get("text", "")
                        key1 = pkt.get("key1")
                        key2 = pkt.get("key2")

                        text = cipher.decrypt(ct_text, key1, key2)

                    # --- AES / DES / RSA (mevcut sistem) ---
                    elif alg_u == "AES":
                        if not aes_key:
                            raise ValueError("Önce AES key_exchange yapılmalı.")
                        text = aes_decrypt_cbc(pkt["iv_b64"], pkt["ct_b64"], aes_key)

                    elif alg_u == "DES":
                        if not des_key:
                            raise ValueError("Önce DES key_exchange yapılmalı.")
                        text = des_decrypt_cbc(pkt["iv_b64"], pkt["ct_b64"], des_key)

                    elif alg_u == "RSA":
                        # RSA ile direkt mesaj (kısa olmalı)
                        text = rsa_decrypt_text(kp.private_pem, pkt["ct_b64"])

                    else:
                        raise ValueError("Bilinmeyen algoritma.")

                    print(f"[SERVER] Çözülmüş metin: {text}")
                    # İstersen plaintext'i de geri yollayalım (debug kolay olur)
                    send_packet(conn, {"type": "ack", "msg": "OK", "pt": text})

                elif ptype == "quit":
                    print("[SERVER] Çıkış.")
                    break

                else:
                    raise ValueError(f"Bilinmeyen paket tipi: {ptype}")

if __name__ == "__main__":
    main()
