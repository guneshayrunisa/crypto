from flask import Flask, request, render_template_string
from Crypto.Random import get_random_bytes
import json

from crypto_lib import (
    aes_encrypt_cbc, aes_decrypt_cbc,
    des_encrypt_cbc, des_decrypt_cbc,
    rsa_generate_keypair,
    rsa_encrypt_bytes, rsa_decrypt_bytes,
)
from algorithms.manual_aes import manual_aes_encrypt_cbc, manual_aes_decrypt_cbc
from algorithms.manual_des import manual_des_encrypt_cbc, manual_des_decrypt_cbc

# ECC - Arka planda mevcut ama UI'da kullanılmıyor
from ecc_lib import (
    ecc_generate_keypair,
    ecdsa_sign, ecdsa_verify,
)

# KLASİK ŞİFRELER
from algorithms import (
    CaesarCipherTR, VigenereCipherTR, AffineCipherTR, SubstitutionCipherTR,
    RailFenceCipherTR, RouteCipherTR, ColumnarCipherTR, PolybiusCipherTR,
    PlayfairCipherTR, HillCipherTR
)

app = Flask(__name__)

# ----------------------------
# SERVER tarafı: RSA + ECC keypair + saklanan simetrik anahtarlar
# ----------------------------
SERVER_RSA = rsa_generate_keypair(2048)
SERVER_ECC = ecc_generate_keypair("P256")  # ECC arka planda mevcut

SERVER_AES_KEY = None
SERVER_DES_KEY = None
SERVER_TOY_KEY = None

# ----------------------------
# CLIENT tarafı: simetrik anahtarları üretir
# ----------------------------
CLIENT_AES_KEY = get_random_bytes(16)
CLIENT_DES_KEY = get_random_bytes(8)
CLIENT_TOY_KEY = get_random_bytes(8)

KEY_EXCHANGE_OK = False

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


def do_rsa_key_exchange() -> None:
    """
    RSA ile Anahtar Dağıtımı:
    CLIENT: simetrik key'leri üretir ve SERVER_RSA.public ile şifreler
    SERVER: private ile çözer ve bellekte saklar
    """
    global SERVER_AES_KEY, SERVER_DES_KEY, SERVER_TOY_KEY, KEY_EXCHANGE_OK

    try:
        enc_aes = rsa_encrypt_bytes(SERVER_RSA.public_pem, CLIENT_AES_KEY)
        enc_des = rsa_encrypt_bytes(SERVER_RSA.public_pem, CLIENT_DES_KEY)
        enc_toy = rsa_encrypt_bytes(SERVER_RSA.public_pem, CLIENT_TOY_KEY)

        SERVER_AES_KEY = rsa_decrypt_bytes(SERVER_RSA.private_pem, enc_aes)
        SERVER_DES_KEY = rsa_decrypt_bytes(SERVER_RSA.private_pem, enc_des)
        SERVER_TOY_KEY = rsa_decrypt_bytes(SERVER_RSA.private_pem, enc_toy)

        if len(SERVER_AES_KEY) != 16 or len(SERVER_DES_KEY) != 8 or len(SERVER_TOY_KEY) != 8:
            raise ValueError("Anahtar uzunluğu hatası.")

        KEY_EXCHANGE_OK = True
        print("[KEY-EXCHANGE] RSA ile AES/DES/TOY anahtarları başarıyla dağıtıldı ✅")

    except Exception as e:
        KEY_EXCHANGE_OK = False
        print("[KEY-EXCHANGE] HATA ❌:", e)


def parse_key(key_str: str, expected_len: int) -> bytes:
    """
    Kullanıcı düz metin veya hex girebilir.
    AES için expected_len=16 (16 karakter veya 32 hex)
    DES/TOYDES için expected_len=8 (8 karakter veya 16 hex)
    """
    s = (key_str or "").strip()
    if not s:
        return b""
    
    # Önce hex mi kontrol et (sadece 0-9a-f içeriyorsa)
    cleaned = s.lower().replace(" ", "")
    if all(c in '0123456789abcdef' for c in cleaned):
        # Hex olabilir
        if len(cleaned) == expected_len * 2:
            try:
                return bytes.fromhex(cleaned)
            except:
                pass
    
    # Normal metin olarak al
    key_bytes = s.encode('utf-8')
    if len(key_bytes) < expected_len:
        raise ValueError(f"Key en az {expected_len} karakter olmalı.")
    elif len(key_bytes) > expected_len:
        # Fazlaysa kes
        key_bytes = key_bytes[:expected_len]
    
    return key_bytes

def parse_key_for_classic_single_input(alg: str, key_raw: str):
    """
    Tek Key alanı kullanılır.
    - AFFINE: 'a,b' veya 'a b' veya 'a;b'
    - HILL: JSON matris: [[3,3],[2,5]]
    Diğerleri: tek değer/kelime
    """
    alg = alg.upper()
    k = (key_raw or "").strip()

    if alg == "POLYBIUS":
        return None, None  # anahtar yok

    if alg == "CAESAR":
        if not k:
            raise ValueError("Caesar için Key gerekli. (örn 3)")
        return int(k), None

    if alg == "VIGENERE":
        if not k:
            raise ValueError("Vigenere için Key gerekli. (örn KRIPTO)")
        return k, None

    if alg == "AFFINE":
        if not k:
            raise ValueError("Affine için Key gerekli. Format: a,b (örn 5,8)")
        sep = "," if "," in k else (";" if ";" in k else None)
        if sep:
            parts = [p.strip() for p in k.split(sep) if p.strip()]
        else:
            parts = [p for p in k.split() if p.strip()]
        if len(parts) != 2:
            raise ValueError("Affine key formatı: a,b (örn 5,8)")
        return int(parts[0]), int(parts[1])

    if alg == "SUBSTITUTION":
        if not k:
            raise ValueError("Substitution için Key gerekli (29 harflik permütasyon).")
        return k, None

    if alg == "RAILFENCE":
        if not k:
            raise ValueError("RailFence için Key gerekli (örn 3).")
        return int(k), None

    if alg == "ROUTE":
        if not k:
            raise ValueError("Route için Key gerekli (sütun sayısı, örn 5).")
        return int(k), None

    if alg == "COLUMNAR":
        if not k:
            raise ValueError("Columnar için Key gerekli (anahtar kelime).")
        return k, None

    if alg == "PLAYFAIR":
        if not k:
            raise ValueError("Playfair için Key gerekli (örn SECURITY).")
        return k, None

    if alg == "HILL":
        if not k:
            raise ValueError("Hill için Key gerekli. Örn: [[3,3],[2,5]]")
        try:
            mat = json.loads(k)
        except Exception:
            import ast
            mat = ast.literal_eval(k)
        return mat, None

    # bilinmeyen ama klasik listede olan olursa:
    return k, None

# -------- UI --------
HTML = r"""
<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Crypto Lab</title>
  <style>
    :root{
      --bg:#0b1020; --text:#e9ecff; --muted:#a8b0d6; --line:rgba(255,255,255,.08);
      --accent:#7c5cff; --accent2:#2ee59d; --shadow: 0 20px 60px rgba(0,0,0,.45); --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      color:var(--text);
      background:
        radial-gradient(900px 500px at 15% 10%, rgba(124,92,255,.25), transparent 60%),
        radial-gradient(900px 500px at 85% 20%, rgba(46,229,157,.20), transparent 60%),
        radial-gradient(700px 420px at 50% 85%, rgba(255,84,112,.12), transparent 60%),
        var(--bg);
      min-height:100vh;
    }
    .wrap{ max-width:1100px; margin:38px auto; padding:0 18px; }
    .top{ display:flex; align-items:flex-start; justify-content:space-between; gap:16px; margin-bottom:18px; }
    .brand{ display:flex; flex-direction:column; gap:8px; }
    .brand h1{ font-size:28px; margin:0; letter-spacing:.2px; }
    .brand p{ margin:0; color:var(--muted); line-height:1.4; }
    .pill{
      display:inline-flex; align-items:center; gap:8px;
      padding:10px 12px; background:rgba(255,255,255,.06);
      border:1px solid var(--line); border-radius:999px;
      color:var(--muted); font-size:13px; backdrop-filter: blur(10px);
      box-shadow: 0 10px 30px rgba(0,0,0,.18);
    }
    .grid{ display:grid; grid-template-columns: 1fr 1fr; gap:16px; }
    @media (max-width: 900px){ .grid{ grid-template-columns:1fr; } }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border:1px solid var(--line);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      overflow:hidden;
    }
    .cardHead{
      padding:16px 16px 10px 16px;
      border-bottom:1px solid var(--line);
      display:flex; align-items:center; justify-content:space-between;
      background: linear-gradient(180deg, rgba(255,255,255,.06), transparent);
    }
    .title{ display:flex; align-items:center; gap:10px; font-weight:700; letter-spacing:.2px; }
    .dot{ width:10px;height:10px;border-radius:99px;background:var(--accent); box-shadow:0 0 20px rgba(124,92,255,.6); }
    .dot.green{ background:var(--accent2); box-shadow:0 0 20px rgba(46,229,157,.6); }
    .cardBody{ padding:16px; }
    label{ display:block; font-size:13px; color:var(--muted); margin-bottom:6px; }
    select, textarea, input{
      width:100%;
      background: rgba(15,23,48,.75);
      border:1px solid var(--line);
      border-radius: 14px;
      color:var(--text);
      padding:12px 12px;
      outline:none;
    }
    textarea{ min-height:120px; resize: vertical; }
    .row{ display:grid; grid-template-columns: 1fr 1fr; gap:10px; }
    @media (max-width: 520px){ .row{ grid-template-columns:1fr; } }
    .btn{
      display:inline-flex; align-items:center; justify-content:center;
      gap:10px; padding:12px 14px; border-radius: 14px;
      border:1px solid rgba(255,255,255,.14);
      background: linear-gradient(180deg, rgba(124,92,255,.95), rgba(124,92,255,.78));
      color:white; font-weight:700; cursor:pointer; width:100%;
    }
    .btn.secondary{ background: rgba(255,255,255,.06); border:1px solid var(--line); }
    .btn.green{ background: linear-gradient(180deg, rgba(46,229,157,.95), rgba(46,229,157,.70)); color:#081223; }
    .copyRow{ display:flex; gap:10px; align-items:center; justify-content:space-between; margin-top:10px; }
    .tiny{ font-size:12px; color:var(--muted); }
    .hint{ margin-top:10px; color:var(--muted); font-size:12.8px; line-height:1.45; }
    .box{
      margin-top:12px; padding:12px; border-radius: 14px;
      border:1px solid var(--line); background: rgba(0,0,0,.18);
    }
    .box h4{ margin:0 0 8px 0; font-size:13px; color:var(--muted); font-weight:600;}
    .mono{
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size:12.7px; line-height:1.5; white-space: pre-wrap; word-break: break-word;
      color:#dfe5ff;
    }
    .status{
      margin-top:10px; padding:10px 12px; border-radius: 14px;
      border:1px solid var(--line); background: rgba(255,255,255,.05); font-size:13px;
    }
    .err{ border-color: rgba(255,84,112,.40); background: rgba(255,84,112,.10); }
    .success{ border-color: rgba(46,229,157,.40); background: rgba(46,229,157,.10); }
    .footer{
      margin-top:16px; padding:14px 16px; border-radius: var(--radius);
      border:1px solid var(--line); background: rgba(255,255,255,.04); color:var(--muted); font-size:13px;
    }
    .help{
      margin-top:8px;
      font-size:12px;
      color: var(--muted);
      line-height:1.4;
    }
    .kbd{
      font-family: ui-monospace, Menlo, Consolas, monospace;
      font-size: 12px;
      padding: 2px 6px;
      border-radius: 8px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,.05);
      color: #dfe5ff;
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="top">
      <div class="brand">
        <h1>🔐 Crypto Lab</h1>
        <p>Modern & Klasik Kriptografi | RSA Key Exchange, AES-128, DES</p>
      </div>
    </div>

    {% if debug %}
    <div class="footer">
      <b>Debug - RSA Key Exchange</b><br>
      Key Exchange: <span class="mono">{{ "OK ✅" if key_ok else "FAIL ❌" }}</span><br><br>
      <b>Simetrik Anahtarlar:</b><br>
      CLIENT_AES_KEY: <span class="mono">{{client_aes}}</span><br>
      SERVER_AES_KEY: <span class="mono">{{server_aes}}</span><br><br>
      CLIENT_DES_KEY: <span class="mono">{{client_des}}</span><br>
      SERVER_DES_KEY: <span class="mono">{{server_des}}</span><br><br>
      <span class="tiny">Debug kapatmak için URL'den <code>?debug=1</code> kaldır.</span>
    </div>
    {% endif %}

    <!-- ŞİFRELEME KARTLARI -->
    <div class="grid">
      <div class="card">
        <div class="cardHead">
          <div class="title"><span class="dot"></span>Şifrele</div>
          <span class="tiny">Çıktı: Şifreli Metin</span>
        </div>
        <div class="cardBody">
          <form method="post" action="/encrypt">
            <div class="row">
              <div>
                <label>Algoritma</label>
                <select name="alg" id="algSelect" onchange="syncKeyHints()">
                  <optgroup label="Modern">
                    <option value="AES_LIB" {{'selected' if alg_in=='AES_LIB' else ''}}>AES-128 (Kütüphaneli)</option>
                    <option value="AES_MANUAL" {{'selected' if alg_in=='AES_MANUAL' else ''}}>AES-128 (Manuel)</option>
                    <option value="DES_LIB" {{'selected' if alg_in=='DES_LIB' else ''}}>DES (Kütüphaneli)</option>
                    <option value="DES_MANUAL" {{'selected' if alg_in=='DES_MANUAL' else ''}}>DES (Manuel)</option>
                  </optgroup>
                  <optgroup label="Klasik">
                    <option value="CAESAR" {{'selected' if alg_in=='CAESAR' else ''}}>Caesar</option>
                    <option value="VIGENERE" {{'selected' if alg_in=='VIGENERE' else ''}}>Vigenere</option>
                    <option value="AFFINE" {{'selected' if alg_in=='AFFINE' else ''}}>Affine</option>
                    <option value="SUBSTITUTION" {{'selected' if alg_in=='SUBSTITUTION' else ''}}>Substitution</option>
                    <option value="RAILFENCE" {{'selected' if alg_in=='RAILFENCE' else ''}}>RailFence</option>
                    <option value="ROUTE" {{'selected' if alg_in=='ROUTE' else ''}}>Route</option>
                    <option value="COLUMNAR" {{'selected' if alg_in=='COLUMNAR' else ''}}>Columnar</option>
                    <option value="POLYBIUS" {{'selected' if alg_in=='POLYBIUS' else ''}}>Polybius</option>
                    <option value="PLAYFAIR" {{'selected' if alg_in=='PLAYFAIR' else ''}}>Playfair (EN 5x5)</option>
                    <option value="HILL" {{'selected' if alg_in=='HILL' else ''}}>Hill (TR, mod 29)</option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label>İpucu</label>
                <input id="hintBox" value="Şifrele → Şifreli metni kopyala" readonly />
              </div>
            </div>

            <div style="margin-top:10px;">
              <label>Key</label>
              <input name="key" id="key" placeholder="Seçilen algoritmaya göre key gir..." value="{{key_in or ''}}" />
              <div class="help" id="help1"></div>
            </div>

            <div style="margin-top:10px;">
              <label>Düz Metin</label>
              <textarea name="plaintext" placeholder="Şifrelenecek metni yaz...">{{plain_in or ""}}</textarea>
            </div>

            <div class="copyRow">
              <button class="btn" type="submit">🔒 Şifrele</button>
              <button class="btn secondary" type="button" onclick="window.location.href='/'">Temizle</button>
            </div>
          </form>

          {% if enc_error %}
            <div class="status err"><b>Hata:</b> {{enc_error}}</div>
          {% endif %}

          {% if enc_text %}
            <div class="box">
              <h4>Şifreli Metin</h4>
              <div class="mono">{{ enc_text }}</div>
            </div>
          {% endif %}
        </div>
      </div>

      <div class="card">
        <div class="cardHead">
          <div class="title"><span class="dot green"></span>Deşifre</div>
          <span class="tiny">Girdi: Şifreli Metin</span>
        </div>
        <div class="cardBody">
          <form method="post" action="/decrypt">
            <div class="row">
              <div>
                <label>Algoritma</label>
                <select name="alg" id="decAlgSelect" onchange="syncDecKeyHints()">
                  <optgroup label="Modern">
                    <option value="AES_LIB">AES-128 (Kütüphaneli)</option>
                    <option value="AES_MANUAL">AES-128 (Manuel)</option>
                    <option value="DES_LIB">DES (Kütüphaneli)</option>
                    <option value="DES_MANUAL">DES (Manuel)</option>
                  </optgroup>
                  <optgroup label="Klasik">
                    <option value="CAESAR">Caesar</option>
                    <option value="VIGENERE">Vigenere</option>
                    <option value="AFFINE">Affine</option>
                    <option value="SUBSTITUTION">Substitution</option>
                    <option value="RAILFENCE">RailFence</option>
                    <option value="ROUTE">Route</option>
                    <option value="COLUMNAR">Columnar</option>
                    <option value="POLYBIUS">Polybius</option>
                    <option value="PLAYFAIR">Playfair</option>
                    <option value="HILL">Hill</option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label>Key</label>
                <input name="key" id="decKey" placeholder="Gerekliyse gir..." value="{{dec_key_in or ''}}" />
                <div class="help" id="decHelp"></div>
              </div>
            </div>

            <div style="margin-top:10px;">
              <label>Şifreli Metin</label>
              <textarea name="ciphertext" placeholder="Şifreli metni buraya yapıştır...">{{cipher_in or ""}}</textarea>
            </div>

            <div class="copyRow">
              <button class="btn green" type="submit">🔓 Deşifre Et</button>
              <button class="btn secondary" type="button" onclick="window.location.href='/'">Temizle</button>
            </div>
          </form>

          {% if dec_error %}
            <div class="status err"><b>Hata:</b> {{dec_error}}</div>
          {% endif %}

          {% if dec_plain %}
            <div class="box">
              <h4>Çözülmüş Metin</h4>
              <div class="mono">{{dec_plain}}</div>
            </div>
          {% endif %}
        </div>
      </div>
    </div>
  </div>

<script>
  function syncKeyHints(){
    const alg = document.getElementById("algSelect").value;
    const key = document.getElementById("key");
    const help1 = document.getElementById("help1");

    key.disabled = false;
    help1.textContent = "";

    if (alg === "AES_LIB" || alg === "AES_MANUAL"){
      help1.textContent = "Opsiyonel: 16 karakter anahtar. Boş bırak → RSA key exchange key'i kullanılır.";
      key.placeholder = "Opsiyonel 16 karakter (örn MySecretKey12345)";
    } else if (alg === "DES_LIB" || alg === "DES_MANUAL"){
      help1.textContent = "Opsiyonel: 8 karakter anahtar. Boş bırak → RSA key exchange key'i kullanılır.";
      key.placeholder = "Opsiyonel 8 karakter (örn Secret12)";
    } else if (alg === "CAESAR"){
      help1.textContent = "Key = kaydırma sayısı (0-28 arası). Örn: 3";
      key.placeholder = "örn 3";
    } else if (alg === "VIGENERE"){
      help1.textContent = "Key = anahtar kelime (TR harfler). Örn: KRIPTO";
      key.placeholder = "örn KRIPTO";
    } else if (alg === "AFFINE"){
      help1.textContent = "Key = a,b şeklinde iki sayı. a ve 29 aralarında asal olmalı. Örn: 5,8";
      key.placeholder = "örn 5,8";
    } else if (alg === "SUBSTITUTION"){
      help1.textContent = "Key = 29 harflik TR alfabe permütasyonu (her harf bir kez).";
      key.placeholder = "29 harflik permütasyon";
    } else if (alg === "RAILFENCE"){
      help1.textContent = "Key = ray (satır) sayısı. Örn: 3";
      key.placeholder = "örn 3";
    } else if (alg === "ROUTE"){
      help1.textContent = "Key = sütun sayısı. Örn: 5";
      key.placeholder = "örn 5";
    } else if (alg === "COLUMNAR"){
      help1.textContent = "Key = anahtar kelime. Örn: KRIPTO";
      key.placeholder = "örn KRIPTO";
    } else if (alg === "POLYBIUS"){
      help1.textContent = "Bu algoritmada key yok (5x5 sabit tablo kullanılır).";
      key.value = "";
      key.placeholder = "Kullanılmaz";
      key.disabled = true;
    } else if (alg === "PLAYFAIR"){
      help1.textContent = "Key = anahtar kelime (İngilizce harfler). Örn: SECURITY";
      key.placeholder = "örn SECURITY";
    } else if (alg === "HILL"){
      help1.textContent = "Key = kare matris (JSON formatında). Örn: [[3,3],[2,5]]";
      key.placeholder = "örn [[3,3],[2,5]]";
    }

    if (key.disabled){
      key.value = "";
    }
  }

  syncKeyHints();
</script>
<script>
  function syncDecKeyHints(){
    const alg = document.getElementById("decAlgSelect").value;
    const key = document.getElementById("decKey");
    const help = document.getElementById("decHelp");

    key.disabled = false;
    help.textContent = "";

    if (alg === "AES_LIB" || alg === "AES_MANUAL"){
      help.textContent = "Boş bırak → server exchange key'i. Özel key kullandıysan 16 karakter gir.";
      key.placeholder = "Opsiyonel 16 karakter";
    } else if (alg === "DES_LIB" || alg === "DES_MANUAL"){
      help.textContent = "Boş bırak → server exchange key'i. Özel key kullandıysan 8 karakter gir.";
      key.placeholder = "Opsiyonel 8 karakter";
    } else if (alg === "CAESAR"){
      help.textContent = "Key = kaydırma sayısı (0-28). Örn: 3";
      key.placeholder = "örn 3";
    } else if (alg === "VIGENERE"){
      help.textContent = "Key = anahtar kelime. Örn: KRIPTO";
      key.placeholder = "örn KRIPTO";
    } else if (alg === "AFFINE"){
      help.textContent = "Key = a,b şeklinde. a ve 29 aralarında asal. Örn: 5,8";
      key.placeholder = "örn 5,8";
    } else if (alg === "SUBSTITUTION"){
      help.textContent = "Key = 29 harflik permütasyon.";
      key.placeholder = "29 harflik permütasyon";
    } else if (alg === "RAILFENCE"){
      help.textContent = "Key = ray sayısı. Örn: 3";
      key.placeholder = "örn 3";
    } else if (alg === "ROUTE"){
      help.textContent = "Key = sütun sayısı. Örn: 5";
      key.placeholder = "örn 5";
    } else if (alg === "COLUMNAR"){
      help.textContent = "Key = anahtar kelime. Örn: KRIPTO";
      key.placeholder = "örn KRIPTO";
    } else if (alg === "POLYBIUS"){
      help.textContent = "Key yok.";
      key.value = "";
      key.placeholder = "Kullanılmaz";
      key.disabled = true;
    } else if (alg === "PLAYFAIR"){
      help.textContent = "Key = anahtar kelime (EN). Örn: SECURITY";
      key.placeholder = "örn SECURITY";
    } else if (alg === "HILL"){
      help.textContent = "Key = matris (JSON). Örn: [[3,3],[2,5]]";
      key.placeholder = "örn [[3,3],[2,5]]";
    }

    if (key.disabled) key.value = "";
  }

  syncDecKeyHints();
</script>

</body>
</html>
"""
def render(**kwargs):
    debug = (request.args.get("debug") == "1")
    return render_template_string(
        HTML,
        debug=debug,
        key_ok=KEY_EXCHANGE_OK,
        client_aes=CLIENT_AES_KEY.hex(),
        client_des=CLIENT_DES_KEY.hex(),
        client_toy=CLIENT_TOY_KEY.hex(),
        server_aes=(SERVER_AES_KEY.hex() if SERVER_AES_KEY else "None"),
        server_des=(SERVER_DES_KEY.hex() if SERVER_DES_KEY else "None"),
        server_toy=(SERVER_TOY_KEY.hex() if SERVER_TOY_KEY else "None"),
        **kwargs
    )


@app.get("/")
def index():
    return render(
        alg_in="AES_LIB",
        key_in="",
        plain_in="",
        enc_text=None,
        enc_error=None,
        dec_alg_in="AES_LIB",
        dec_key_in="",
        cipher_in="",
        dec_plain=None,
        dec_error=None,
    )


@app.post("/encrypt")
def encrypt():
    alg = (request.form.get("alg") or "").strip().upper()
    plaintext = (request.form.get("plaintext") or "").strip()
    key_raw = request.form.get("key") or ""

    try:
        if not plaintext:
            raise ValueError("Düz metin boş olamaz.")

        # KLASİK ŞİFRELER
        if alg in CLASSIC_MAP:
            cipher = CLASSIC_MAP[alg]
            key1, key2 = parse_key_for_classic_single_input(alg, key_raw)
            ct_text = cipher.encrypt(plaintext, key1, key2)

            return render(
                alg_in=alg,
                key_in=key_raw,
                plain_in=plaintext,
                enc_text=ct_text,
                enc_error=None,
                dec_alg_in=alg,
                dec_key_in=key_raw,
                cipher_in=ct_text,
                dec_plain=None,
                dec_error=None,
            )

        # MODERN ŞİFRELER
        if alg == "AES_LIB":
            custom = parse_key(key_raw, 16)
            use_key = custom if custom else CLIENT_AES_KEY
            out = aes_encrypt_cbc(plaintext, use_key)
            enc_text = f"{out['iv_b64']}.{out['ct_b64']}"

        elif alg == "AES_MANUAL":
            custom = parse_key(key_raw, 16)
            use_key = custom if custom else CLIENT_AES_KEY
            out = manual_aes_encrypt_cbc(plaintext, use_key)
            enc_text = f"{out['iv_b64']}.{out['ct_b64']}"

        elif alg == "DES_LIB":
            custom = parse_key(key_raw, 8)
            use_key = custom if custom else CLIENT_DES_KEY
            out = des_encrypt_cbc(plaintext, use_key)
            enc_text = f"{out['iv_b64']}.{out['ct_b64']}"

        elif alg == "DES_MANUAL":
            custom = parse_key(key_raw, 8)
            use_key = custom if custom else CLIENT_DES_KEY
            out = manual_des_encrypt_cbc(plaintext, use_key)
            enc_text = f"{out['iv_b64']}.{out['ct_b64']}"

        else:
            raise ValueError("Bilinmeyen algoritma seçimi.")

        return render(
            alg_in=alg,
            key_in=key_raw,
            plain_in=plaintext,
            enc_text=enc_text,
            enc_error=None,
            dec_alg_in=alg,
            dec_key_in=key_raw,
            cipher_in=enc_text,
            dec_plain=None,
            dec_error=None,
        )

    except Exception as e:
        return render(
            alg_in=alg or "AES_LIB",
            key_in=key_raw,
            plain_in=plaintext,
            enc_text=None,
            enc_error=str(e),
            dec_alg_in="AES_LIB",
            dec_key_in="",
            cipher_in="",
            dec_plain=None,
            dec_error=None,
        )


@app.post("/decrypt")
def decrypt():
    alg = (request.form.get("alg") or "").strip().upper()
    ciphertext = (request.form.get("ciphertext") or "").strip()
    key_raw = request.form.get("key") or ""

    try:
        if not ciphertext:
            raise ValueError("Şifreli metin boş olamaz.")

        # KLASİK ŞİFRELER
        if alg in CLASSIC_MAP:
            cipher = CLASSIC_MAP[alg]
            key1, key2 = parse_key_for_classic_single_input(alg, key_raw)
            dec_plain = cipher.decrypt(ciphertext, key1, key2)

        # MODERN ŞİFRELER
        elif alg in ("AES_LIB", "AES_MANUAL", "DES_LIB", "DES_MANUAL"):
            if "." not in ciphertext:
                raise ValueError("Modern şifrelerde format: iv_b64.ct_b64 olmalı (araya nokta).")

            iv_b64, ct_b64 = ciphertext.split(".", 1)
            iv_b64 = iv_b64.strip()
            ct_b64 = ct_b64.strip()

            if alg in ("AES_LIB", "AES_MANUAL"):
                custom = parse_key(key_raw, 16)
                use_key = custom if custom else (SERVER_AES_KEY if KEY_EXCHANGE_OK else None)
            else:
                custom = parse_key(key_raw, 8)
                use_key = custom if custom else (SERVER_DES_KEY if KEY_EXCHANGE_OK else None)

            if not use_key:
                raise ValueError("Key exchange yapılmadı ve custom key de girilmedi.")

            if alg == "AES_LIB":
                dec_plain = aes_decrypt_cbc(iv_b64, ct_b64, use_key)
            elif alg == "AES_MANUAL":
                dec_plain = manual_aes_decrypt_cbc(iv_b64, ct_b64, use_key)
            elif alg == "DES_LIB":
                dec_plain = des_decrypt_cbc(iv_b64, ct_b64, use_key)
            elif alg == "DES_MANUAL":
                dec_plain = manual_des_decrypt_cbc(iv_b64, ct_b64, use_key)

        else:
            raise ValueError("Desteklenmeyen algoritma.")

        return render(
            alg_in="AES_LIB",
            key_in="",
            plain_in="",
            enc_text=None,
            enc_error=None,
            dec_alg_in=alg,
            dec_key_in=key_raw,
            cipher_in=ciphertext,
            dec_plain=dec_plain,
            dec_error=None,
        )

    except Exception as e:
        return render(
            alg_in="AES_LIB",
            key_in="",
            plain_in="",
            enc_text=None,
            enc_error=None,
            dec_alg_in=alg or "AES_LIB",
            dec_key_in=key_raw,
            cipher_in=ciphertext,
            dec_plain=None,
            dec_error=str(e),
        )


# Key exchange'i uygulama başında yap
do_rsa_key_exchange()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)