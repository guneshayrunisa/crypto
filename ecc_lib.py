"""
ECC (Elliptic Curve Cryptography) işlemleri
- ECDSA: Dijital imzalama
- ECDH: Anahtar değişimi
"""

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import base64


class ECCKeyPair:
    """ECC anahtar çifti tutucu sınıf"""
    def __init__(self, private_pem, public_pem):
        self.private_pem = private_pem
        self.public_pem = public_pem


def ecc_generate_keypair(curve_name="P256"):
    """
    ECC anahtar çifti üretir
    
    Args:
        curve_name: Eğri adı (P256, P384, P521, SECP256K1)
    
    Returns:
        ECCKeyPair nesnesi
    """
    # Eğri seçimi
    curves = {
        "P256": ec.SECP256R1(),      # NIST P-256 (en yaygın)
        "P384": ec.SECP384R1(),      # NIST P-384 (daha güvenli)
        "P521": ec.SECP521R1(),      # NIST P-521 (en güvenli)
        "SECP256K1": ec.SECP256K1(), # Bitcoin eğrisi
    }
    
    curve = curves.get(curve_name.upper(), ec.SECP256R1())
    
    # Private key üret
    private_key = ec.generate_private_key(curve, default_backend())
    
    # Public key çıkar
    public_key = private_key.public_key()
    
    # PEM formatına dönüştür
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return ECCKeyPair(private_pem, public_pem)


# ============================================
# ECDSA - Dijital İmzalama
# ============================================

def ecdsa_sign(private_pem, message):
    """
    ECDSA ile mesaj imzalar
    
    Args:
        private_pem: Private key (bytes veya str)
        message: İmzalanacak mesaj (str)
    
    Returns:
        Base64 encoded imza string
    """
    if isinstance(private_pem, str):
        private_pem = private_pem.encode()
    
    # Private key yükle
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    
    # İmzala
    signature = private_key.sign(
        message.encode('utf-8'),
        ec.ECDSA(hashes.SHA256())
    )
    
    # Base64'e çevir
    return base64.b64encode(signature).decode('utf-8')


def ecdsa_verify(public_pem, message, signature_b64):
    """
    ECDSA imza doğrular
    
    Args:
        public_pem: Public key (bytes veya str)
        message: Orijinal mesaj (str)
        signature_b64: Base64 encoded imza
    
    Returns:
        bool: İmza geçerliyse True
    """
    if isinstance(public_pem, str):
        public_pem = public_pem.encode()
    
    # Public key yükle
    public_key = serialization.load_pem_public_key(
        public_pem,
        backend=default_backend()
    )
    
    # Signature decode
    signature = base64.b64decode(signature_b64)
    
    # Doğrula
    try:
        public_key.verify(
            signature,
            message.encode('utf-8'),
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except Exception:
        return False


# ============================================
# ECDH - Anahtar Değişimi (Key Exchange)
# ============================================

def ecdh_generate_shared_secret(my_private_pem, their_public_pem):
    """
    ECDH ile paylaşılan gizli anahtar üretir
    
    Args:
        my_private_pem: Kendi private key'imiz
        their_public_pem: Karşı tarafın public key'i
    
    Returns:
        32 byte paylaşılan gizli (AES-256 için kullanılabilir)
    """
    if isinstance(my_private_pem, str):
        my_private_pem = my_private_pem.encode()
    if isinstance(their_public_pem, str):
        their_public_pem = their_public_pem.encode()
    
    # Key'leri yükle
    my_private = serialization.load_pem_private_key(
        my_private_pem,
        password=None,
        backend=default_backend()
    )
    
    their_public = serialization.load_pem_public_key(
        their_public_pem,
        backend=default_backend()
    )
    
    # Paylaşılan gizli üret
    shared_secret = my_private.exchange(ec.ECDH(), their_public)
    
    # SHA256 ile hash'le (32 byte AES key için)
    from cryptography.hazmat.primitives import hashes
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_secret)
    
    return digest.finalize()  # 32 bytes


# ============================================
# Yardımcı Fonksiyonlar
# ============================================

def get_public_key_from_private(private_pem):
    """Private key'den public key çıkarır"""
    if isinstance(private_pem, str):
        private_pem = private_pem.encode()
    
    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
        backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def export_public_key_base64(public_pem):
    """Public key'i base64 string olarak döndürür (paylaşım için)"""
    if isinstance(public_pem, bytes):
        public_pem = public_pem.decode()
    
    # PEM header/footer'ları kaldır
    lines = public_pem.strip().split('\n')
    base64_lines = [line for line in lines if not line.startswith('-----')]
    return ''.join(base64_lines)


def import_public_key_base64(base64_str):
    """Base64 string'den public key PEM oluşturur"""
    pem_str = f"-----BEGIN PUBLIC KEY-----\n{base64_str}\n-----END PUBLIC KEY-----"
    return pem_str.encode()