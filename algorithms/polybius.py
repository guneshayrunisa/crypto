# algorithms/polybius.py
from __future__ import annotations
from .base import BaseCipherTR

class PolybiusCipherTR(BaseCipherTR):
    """
    Türkçe alfabe 29 harf => 30 hücrelik 5x6 tablo (satır=1..5, sütun=1..6)
    Son hücre dolgu: 'X' (alfabede yok ama tabloyu tamamlar)
    Şifre formatı: her harf için iki basamak: satır+sütun (örn 11, 12, ...)
    Harf olmayan karakterler aynen kalır.
    """
    def __init__(self):
        super().__init__()
        self.satir = 5
        self.sutun = 6
        tablo_harfleri = list(self.alfabe) + ["X"]  # 30
        self.tablo = [tablo_harfleri[i*self.sutun:(i+1)*self.sutun] for i in range(self.satir)]
        self.harften_koda = {}
        self.koddan_harfe = {}
        for r in range(self.satir):
            for c in range(self.sutun):
                harf = self.tablo[r][c]
                kod = f"{r+1}{c+1}"
                self.harften_koda[harf] = kod
                self.koddan_harfe[kod] = harf

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        out = []
        for ch in text:
            if self._is_letter(ch):
                buyuk = ch.isupper()
                h = ch.upper()
                kod = self.harften_koda[h]
                out.append(kod if buyuk else kod)  # sayılar
            else:
                out.append(ch)
        return " ".join(out)  # okunur olsun diye aralıklı

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        # Aralıklı ya da aralıksız gelebilir: rakam ikililerini yakalayalım
        out = []
        i = 0
        while i < len(text):
            if i+1 < len(text) and text[i].isdigit() and text[i+1].isdigit():
                kod = text[i] + text[i+1]
                harf = self.koddan_harfe.get(kod)
                if harf is None:
                    raise ValueError(f"Geçersiz Polybius kodu: {kod}")
                out.append(harf)
                i += 2
            else:
                # boşluk vb.
                if text[i] != " ":
                    out.append(text[i])
                i += 1
        return "".join(out)
