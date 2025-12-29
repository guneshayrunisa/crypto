# Crypto HW – Secure Communication & Cryptography Toolkit

Bu proje, simetrik ve asimetrik şifreleme algoritmalarını kullanarak güvenli veri iletimi sağlayan, **istemci–sunucu mimarisi** üzerinde çalışan bir kriptografi uygulamasıdır.

Proje; modern kriptografik algoritmaların **kütüphaneli** ve **manuel (öğretici)** implementasyonlarını bir arada sunarak, algoritmaların iç mantığını ve pratikteki davranışlarını karşılaştırmayı amaçlar.

---

## Temel Özellikler

- 🔐 **Simetrik Şifreleme**
  - AES (CBC modu)
  - DES (CBC modu)
- 🔑 **Asimetrik Şifreleme**
  - RSA (anahtar çifti üretimi, veri şifreleme)
- 🧠 **Manuel / Öğretici Implementasyonlar**
  - Basitleştirilmiş manuel AES-128 (CBC)
  - Manuel DES (CBC)
- 🧩 **Klasik Kriptografi Algoritmaları**
  - Caesar
  - Vigenere
  - Affine
  - Substitution
  - Rail Fence
  - Route Cipher
  - Columnar Transposition
  - Polybius
  - Playfair
  - Hill Cipher

---

## Projenin Amacı

Bu proje:

- Farklı şifreleme algoritmalarının **çalışma prensiplerini**
- Anahtar uzunluğu, IV kullanımı ve çıktı farklarını
- Simetrik ve asimetrik şifrelemenin **avantaj–dezavantajlarını**
- Manuel implementasyon ile kütüphane kullanımı arasındaki farkları

uygulamalı olarak göstermeyi hedefler.

---

## Kurulum

### Depoyu Klonla
```bash
git clone <https://github.com/guneshayrunisa/crypto>
cd crypto_hw

