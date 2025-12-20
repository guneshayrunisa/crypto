# algorithms/caesar.py
from __future__ import annotations
from .base import BaseCipherTR

class CaesarCipherTR(BaseCipherTR):
    def encrypt(self, text: str, key1=None, key2=None) -> str:
        kaydirma = int(key1 or 0)
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            h = ch.upper()
            i = self._index(h)
            yeni = self._char(i + kaydirma)
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        return self.encrypt(text, -(int(key1 or 0)))
