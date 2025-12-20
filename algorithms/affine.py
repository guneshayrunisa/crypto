# algorithms/affine.py
from __future__ import annotations
from math import gcd
from .base import BaseCipherTR, _modinv

class AffineCipherTR(BaseCipherTR):
    # Şifre: E(x) = (a*x + b) mod m
    def encrypt(self, text: str, key1=None, key2=None) -> str:
        a = int(key1)
        b = int(key2)
        m = len(self.alfabe)
        if gcd(a, m) != 1:
            raise ValueError(f"Affine için a ile m aralarında asal olmalı. a={a}, m={m}")
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            x = self._index(ch.upper())
            y = (a * x + b) % m
            yeni = self._char(y)
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        a = int(key1)
        b = int(key2)
        m = len(self.alfabe)
        a_ters = _modinv(a, m)
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            y = self._index(ch.upper())
            x = (a_ters * (y - b)) % m
            yeni = self._char(x)
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)
