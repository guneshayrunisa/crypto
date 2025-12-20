# algorithms/vigenere.py
from __future__ import annotations
from .base import BaseCipherTR

class VigenereCipherTR(BaseCipherTR):
    def _key_stream(self, anahtar: str):
        anahtar = (anahtar or "").strip()
        if not anahtar:
            raise ValueError("Vigenere anahtarı boş olamaz.")
        anahtar = "".join([c.upper() for c in anahtar if self._is_letter(c)])
        if not anahtar:
            raise ValueError("Vigenere anahtarı alfabe harfi içermiyor.")
        j = 0
        while True:
            yield self._index(anahtar[j % len(anahtar)])
            j += 1

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        ks = self._key_stream(str(key1))
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            i = self._index(ch.upper())
            k = next(ks)
            yeni = self._char(i + k)
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        ks = self._key_stream(str(key1))
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            i = self._index(ch.upper())
            k = next(ks)
            yeni = self._char(i - k)
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)
