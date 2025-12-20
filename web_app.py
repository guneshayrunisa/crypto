from flask import Flask, request, render_template_string
from Crypto.Random import get_random_bytes
import base64, json

from crypto_lib import (
    aes_encrypt_cbc, aes_decrypt_cbc,
    des_encrypt_cbc, des_decrypt_cbc,
    rsa_generate_keypair, rsa_encrypt_text, rsa_decrypt_text,
    rsa_encrypt_bytes, rsa_decrypt_bytes,
)
from manual_toy_des import toy_des_encrypt_cbc, toy_des_decrypt_cbc

# KLASİK ŞİFRELER
from algorithms import (
    CaesarCipherTR, VigenereCipherTR, AffineCipherTR, SubstitutionCipherTR,
    RailFenceCipherTR, RouteCipherTR, ColumnarCipherTR, PolybiusCipherTR,
    PlayfairCipherTR, HillCipherTR
)

app = Flask(__name__)

# ----------------------------
# SERVER tarafı: RSA keypair + saklanan simetrik anahtarlar
# ----------------------------
SERVER_RSA = rsa_generate_keypair(2048)
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


def b64e_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def b64d_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def pack_token(obj: dict) -> str:
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    return b64e_bytes(raw)


def unpack_token(token: str) -> dict:
    raw = b64d_bytes(token.strip())
    return json.loads(raw.decode("utf-8"))


def do_rsa_key_exchange() -> None:
    """
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


def parse_hex_key(hex_str: str, expected_len: int) -> bytes:
    s = (hex_str or "").strip().lower().replace(" ", "")
    if not s:
        return b""
    try:
        b = bytes.fromhex(s)
    except Exception:
        raise ValueError("Key hex formatında olmalı. Örn: 001122aabb...")
    if len(b) != expected_len:
        raise ValueError(f"Key uzunluğu {expected_len} byte olmalı (hex uzunluğu {expected_len*2}).")
    return b


def parse_key_inputs_for_classic(alg: str, key1_raw: str, key2_raw: str):
    alg = alg.upper()
    k1 = (key1_raw or "").strip()
    k2 = (key2_raw or "").strip()

    if alg == "CAESAR":
        if not k1:
            raise ValueError("Caesar için Key1 (kaydırma) gerekli.")
        return int(k1), None

    if alg == "VIGENERE":
        if not k1:
            raise ValueError("Vigenere için Key1 (anahtar kelime) gerekli.")
        return k1, None

    if alg == "AFFINE":
        if not k1 or not k2:
            raise ValueError("Affine için Key1=a ve Key2=b gerekli.")
        return int(k1), int(k2)

    if alg == "SUBSTITUTION":
        if not k1:
            raise ValueError("Substitution için Key1 (29 harflik permütasyon) gerekli.")
        return k1, None

    if alg == "RAILFENCE":
        if not k1:
            raise ValueError("RailFence için Key1 (ray sayısı) gerekli.")
        return int(k1), None

    if alg == "ROUTE":
        if not k1:
            raise ValueError("Route için Key1 (sütun sayısı) gerekli.")
        return int(k1), None

    if alg == "COLUMNAR":
        if not k1:
            raise ValueError("Columnar için Key1 (anahtar kelime) gerekli.")
        return k1, None

    if alg == "POLYBIUS":
        return None, None

    if alg == "PLAYFAIR":
        if not k1:
            raise ValueError("Playfair için Key1 (anahtar kelime) gerekli.")
        return k1, None

    if alg == "HILL":
        if not k1:
            raise ValueError("Hill için Key1 (matris) gerekli. Örn: [[3,3],[2,5]]")
        # güvenli eval: json gibi yazarsan da olur
        try:
            mat = json.loads(k1)
        except Exception:
            # json değilse python listesi şeklinde olabilir
            import ast
            mat = ast.literal_eval(k1)
        return mat, None

    return None, None


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
        <h1>Crypto Lab</h1>
        <p>Algoritma seç → şifrele → token’ı kopyala → yapıştır → deşifre et. (AES/DES/Manuel + RSA + Klasikler)</p>
      </div>
      <div class="pill">RSA key exchange aktif • Wireshark için uygun</div>
    </div>

    {% if debug %}
    <div class="footer">
      <b>Debug</b><br>
      Key Exchange: <span class="mono">{{ "OK" if key_ok else "FAIL" }}</span><br><br>
      CLIENT_AES_KEY: <span class="mono">{{client_aes}}</span><br>
      SERVER_AES_KEY: <span class="mono">{{server_aes}}</span><br><br>
      CLIENT_DES_KEY: <span class="mono">{{client_des}}</span><br>
      SERVER_DES_KEY: <span class="mono">{{server_des}}</span><br><br>
      CLIENT_TOY_KEY: <span class="mono">{{client_toy}}</span><br>
      SERVER_TOY_KEY: <span class="mono">{{server_toy}}</span><br>
      <span class="tiny">Debug kapatmak için URL’den <code>?debug=1</code> kaldır.</span>
    </div>
    {% endif %}

    <div class="grid">
      <div class="card">
        <div class="cardHead">
          <div class="title"><span class="dot"></span>Şifrele</div>
          <span class="tiny">Çıktı: TOKEN</span>
        </div>
        <div class="cardBody">
          <form method="post" action="/encrypt">
            <div class="row">
              <div>
                <label>Algoritma</label>
                <select name="alg" id="algSelect" onchange="syncKeyHints()">
                  <optgroup label="Modern">
                    <option value="AES">AES-128 (CBC)</option>
                    <option value="DES">DES (CBC)</option>
                    <option value="TOYDES">Manuel (Toy-DES)</option>
                    <option value="RSA">RSA (OAEP) • kısa mesaj</option>
                  </optgroup>
                  <optgroup label="Klasik">
                    <option value="CAESAR">Caesar (TR alfabe)</option>
                    <option value="VIGENERE">Vigenere (TR alfabe)</option>
                    <option value="AFFINE">Affine (TR alfabe)</option>
                    <option value="SUBSTITUTION">Substitution (TR alfabe)</option>
                    <option value="RAILFENCE">RailFence</option>
                    <option value="ROUTE">Route</option>
                    <option value="COLUMNAR">Columnar</option>
                    <option value="POLYBIUS">Polybius (TR tablo)</option>
                    <option value="PLAYFAIR">Playfair (EN 5x5)</option>
                    <option value="HILL">Hill (TR, mod 29)</option>
                  </optgroup>
                </select>
              </div>
              <div>
                <label>İpucu</label>
                <input id="hintBox" value="Şifrele → token’ı kopyala" readonly />
              </div>
            </div>

            <div class="row" style="margin-top:10px;">
              <div>
                <label>Key 1</label>
                <input name="key1" id="key1" placeholder="Seçilen algoritmaya göre key gir..." value="{{key1_in or ''}}" />
                <div class="help" id="help1"></div>
              </div>
              <div>
                <label>Key 2</label>
                <input name="key2" id="key2" placeholder="Gerekliyse gir..." value="{{key2_in or ''}}" />
                <div class="help" id="help2"></div>
              </div>
            </div>

            <div style="margin-top:10px;">
              <label>Düz Metin</label>
              <textarea name="plaintext" placeholder="Şifrelenecek metni yaz...">{{plain_in or ""}}</textarea>
            </div>

            <div class="copyRow">
              <button class="btn" type="submit">Şifrele</button>
              <button class="btn secondary" type="button" onclick="window.location.href='/'">Temizle</button>
            </div>
          </form>

          {% if enc_error %}
            <div class="status err"><b>Hata:</b> {{enc_error}}</div>
          {% endif %}

          {% if enc_token %}
            <div class="box">
              <h4>Şifreli TOKEN</h4>
              <div class="mono" id="tokenBox">{{enc_token}}</div>
              <div class="copyRow">
                <button class="btn green" type="button" onclick="copyToken()">Kopyala</button>
                <span class="tiny" id="copyMsg"></span>
              </div>
            </div>
            {% if enc_classic %}
            <div class="box">
                <h4>Şifreli Metin</h4>
                <div class="mono">{{ enc_classic }}</div>
            </div>
            {% endif %}
          {% endif %}

          <div class="hint">
            <b>AES/DES/TOYDES:</b> Key1'e hex girersen token içine gömülür (exchange'e gerek kalmadan çözülür).
            Boş bırakırsan RSA key exchange ile dağıtılan sunucu anahtarı kullanılır.
          </div>
        </div>
      </div>

      <div class="card">
        <div class="cardHead">
          <div class="title"><span class="dot green"></span>Deşifre</div>
          <span class="tiny">Girdi: TOKEN</span>
        </div>
        <div class="cardBody">
          <form method="post" action="/decrypt">
            <label>Şifreli TOKEN</label>
            <textarea name="token" placeholder="Token’ı buraya yapıştır...">{{token_in or ""}}</textarea>

            <div class="copyRow">
              <button class="btn green" type="submit">Deşifre Et</button>
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

          <div class="hint">
            Token içindeki <span class="kbd">alg</span> alanına göre server otomatik çözer.
          </div>
        </div>
      </div>
    </div>

    <div class="footer">
      <b>Wireshark:</b> <code>tcp.port == 5000</code> filtrele → “Follow TCP Stream”.
    </div>
  </div>

<script>
  function copyToken(){
    const el = document.getElementById("tokenBox");
    if(!el) return;
    const text = el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const m = document.getElementById("copyMsg");
      if(m){ m.textContent = "Kopyalandı ✅"; }
      setTimeout(()=>{ if(m){m.textContent="";} }, 1200);
    });
  }

  function syncKeyHints(){
    const alg = document.getElementById("algSelect").value;
    const key2 = document.getElementById("key2");
    const help1 = document.getElementById("help1");
    const help2 = document.getElementById("help2");

    // default
    key2.disabled = false;
    help1.textContent = "";
    help2.textContent = "";

    if (alg === "AES"){
      help1.textContent = "Opsiyonel: 16 byte key (32 hex). Boş bırak → RSA key exchange key’i.";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "DES"){
      help1.textContent = "Opsiyonel: 8 byte key (16 hex). Boş bırak → RSA key exchange key’i.";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "TOYDES"){
      help1.textContent = "Opsiyonel: 8 byte key (16 hex). Boş bırak → RSA key exchange key’i.";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "RSA"){
      help1.textContent = "RSA’da key girilmez (public key zaten server tarafında).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "CAESAR"){
      help1.textContent = "Key1 = kaydırma (örn 3).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "VIGENERE"){
      help1.textContent = "Key1 = anahtar kelime (örn KRIPTO).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "AFFINE"){
      help1.textContent = "Key1 = a (29 ile aralarında asal). Örn 5";
      help2.textContent = "Key2 = b. Örn 8";
      key2.disabled = false;
    } else if (alg === "SUBSTITUTION"){
      help1.textContent = "Key1 = 29 harflik TR alfabe permütasyonu.";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "RAILFENCE"){
      help1.textContent = "Key1 = ray sayısı (örn 3).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "ROUTE"){
      help1.textContent = "Key1 = sütun sayısı (örn 5).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "COLUMNAR"){
      help1.textContent = "Key1 = anahtar kelime (örn KRIPTO).";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "POLYBIUS"){
      help1.textContent = "Anahtar yok.";
      help2.textContent = "Anahtar yok.";
      key2.disabled = true;
    } else if (alg === "PLAYFAIR"){
      help1.textContent = "Key1 = anahtar kelime (EN). Örn SECURITY";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    } else if (alg === "HILL"){
      help1.textContent = "Key1 = matris. Örn [[3,3],[2,5]] veya [[6,24,1],[13,16,10],[20,17,15]]";
      help2.textContent = "Kullanılmaz.";
      key2.disabled = true;
    }

    if (key2.disabled){
      key2.value = "";
    }
  }

  // sayfa yüklenince seçime göre hintleri ayarla
  syncKeyHints();
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
    return render(enc_token=None, enc_classic=None, enc_error=None, dec_plain=None, dec_error=None,
                  plain_in=None, token_in=None, key1_in=None, key2_in=None)


@app.post("/encrypt")
def encrypt():
    alg = (request.form.get("alg") or "").strip().upper()
    plaintext = (request.form.get("plaintext") or "").strip()
    key1_raw = request.form.get("key1") or ""
    key2_raw = request.form.get("key2") or ""

    try:
        if not plaintext:
            raise ValueError("Düz metin boş olamaz.")

        # --- KLASİK ŞİFRELER ---
        if alg in CLASSIC_MAP:
            cipher = CLASSIC_MAP[alg]
            key1, key2 = parse_key_inputs_for_classic(alg, key1_raw, key2_raw)
            ct_text = cipher.encrypt(plaintext, key1, key2)

            return render(
            enc_token=None,
            enc_classic=ct_text,   # 👈 klasiklerde direkt metin
            enc_error=None,
            dec_plain=None,
            dec_error=None,
            plain_in=plaintext,
            token_in=None,
            key1_in=key1_raw,
            key2_in=key2_raw,
        )


        # --- MODERN ŞİFRELER ---
        elif alg == "AES":
            # Key girildiyse onu kullan (hex), yoksa CLIENT_AES_KEY
            custom = parse_hex_key(key1_raw, 16)
            use_key = custom if custom else CLIENT_AES_KEY
            out = aes_encrypt_cbc(plaintext, use_key)
            token_obj = {"alg": "AES", "mode": "lib", **out}
            if custom:
                token_obj["key_hex"] = custom.hex()

        elif alg == "DES":
            custom = parse_hex_key(key1_raw, 8)
            use_key = custom if custom else CLIENT_DES_KEY
            out = des_encrypt_cbc(plaintext, use_key)
            token_obj = {"alg": "DES", "mode": "lib", **out}
            if custom:
                token_obj["key_hex"] = custom.hex()

        elif alg == "TOYDES":
            custom = parse_hex_key(key1_raw, 8)
            use_key = custom if custom else CLIENT_TOY_KEY
            out = toy_des_encrypt_cbc(plaintext, use_key)
            token_obj = {"alg": "TOYDES", "mode": "manual", **out}
            if custom:
                token_obj["key_hex"] = custom.hex()

        elif alg == "RSA":
            ct_b64 = rsa_encrypt_text(SERVER_RSA.public_pem, plaintext)
            token_obj = {"alg": "RSA", "mode": "lib", "ct_b64": ct_b64}

        else:
            raise ValueError("Bilinmeyen algoritma seçimi.")

        enc_token = pack_token(token_obj)
        return render(enc_token=enc_token, enc_error=None, dec_plain=None, dec_error=None,
                      plain_in=plaintext, token_in=None, key1_in=key1_raw, key2_in=key2_raw)

    except Exception as e:
        return render(enc_token=None, enc_error=str(e), dec_plain=None, dec_error=None,
                      plain_in=plaintext, token_in=None, key1_in=key1_raw, key2_in=key2_raw)


@app.post("/decrypt")
def decrypt():
    token = (request.form.get("token") or "").strip()

    try:
        if not token:
            raise ValueError("Token boş olamaz.")

        obj = unpack_token(token)
        alg = (obj.get("alg") or "").upper()

        # --- KLASİK ŞİFRELER ---
        if alg in CLASSIC_MAP:
            cipher = CLASSIC_MAP[alg]
            ct_text = obj.get("ct_text", "")
            key1 = obj.get("key1")
            key2 = obj.get("key2")
            dec_plain = cipher.decrypt(ct_text, key1, key2)

        # --- MODERN ŞİFRELER ---
        elif alg == "AES":
            # token içinde custom key varsa onu kullan
            if "key_hex" in obj:
                use_key = bytes.fromhex(obj["key_hex"])
            else:
                if not KEY_EXCHANGE_OK or SERVER_AES_KEY is None:
                    raise ValueError("Key exchange yapılmadı.")
                use_key = SERVER_AES_KEY
            dec_plain = aes_decrypt_cbc(obj["iv_b64"], obj["ct_b64"], use_key)

        elif alg == "DES":
            if "key_hex" in obj:
                use_key = bytes.fromhex(obj["key_hex"])
            else:
                if not KEY_EXCHANGE_OK or SERVER_DES_KEY is None:
                    raise ValueError("Key exchange yapılmadı.")
                use_key = SERVER_DES_KEY
            dec_plain = des_decrypt_cbc(obj["iv_b64"], obj["ct_b64"], use_key)

        elif alg == "TOYDES":
            if "key_hex" in obj:
                use_key = bytes.fromhex(obj["key_hex"])
            else:
                if not KEY_EXCHANGE_OK or SERVER_TOY_KEY is None:
                    raise ValueError("Key exchange yapılmadı.")
                use_key = SERVER_TOY_KEY
            dec_plain = toy_des_decrypt_cbc(obj["iv_b64"], obj["ct_b64"], use_key)

        elif alg == "RSA":
            dec_plain = rsa_decrypt_text(SERVER_RSA.private_pem, obj["ct_b64"])

        else:
            raise ValueError("Token içinden algoritma okunamadı / desteklenmiyor.")

        return render(enc_token=None, enc_error=None, dec_plain=dec_plain, dec_error=None,
                      plain_in=None, token_in=token, key1_in=None, key2_in=None)

    except Exception as e:
        return render(enc_token=None, enc_error=None, dec_plain=None, dec_error=str(e),
                      plain_in=None, token_in=token, key1_in=None, key2_in=None)


# Key exchange'i uygulama başında yap
do_rsa_key_exchange()

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
