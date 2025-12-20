# algorithms/substitution.py
from __future__ import annotations
from .base import BaseCipherTR

class SubstitutionCipherTR(BaseCipherTR):
    # key1: alfabenin birebir permütasyonu (29 harf)
    def _build_maps(self, anahtar: str):
        anahtar = (anahtar or "").upper().strip()
        anahtar = "".join([c for c in anahtar if c in self.alfabe])
        if len(anahtar) != len(self.alfabe) or len(set(anahtar)) != len(self.alfabe):
            raise ValueError("Substitution anahtarı alfabenin birebir permütasyonu olmalı (29 farklı harf).")
        enc = {self.alfabe[i]: anahtar[i] for i in range(len(self.alfabe))}
        dec = {anahtar[i]: self.alfabe[i] for i in range(len(self.alfabe))}
        return enc, dec

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        enc, _ = self._build_maps(str(key1))
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            yeni = enc[ch.upper()]
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        _, dec = self._build_maps(str(key1))
        out = []
        for ch in text:
            if not self._is_letter(ch):
                out.append(ch); continue
            buyuk = ch.isupper()
            yeni = dec[ch.upper()]
            out.append(yeni if buyuk else yeni.lower())
        return "".join(out)
