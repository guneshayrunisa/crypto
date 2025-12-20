# algorithms/route.py
from __future__ import annotations
from .base import BaseCipherTR

class RouteCipherTR(BaseCipherTR):
    # Basit Route: tabloyu satır satır doldur, sütun sütun oku.
    # key1: sütun sayısı (int)
    # dolgu: 'X'
    def encrypt(self, text: str, key1=None, key2=None) -> str:
        sutun = int(key1)
        if sutun < 2:
            raise ValueError("Route için sütun sayısı >= 2 olmalı.")
        dolgu = "X"
        t = list(text)
        rows = []
        while t:
            row = t[:sutun]; t = t[sutun:]
            if len(row) < sutun:
                row += [dolgu] * (sutun - len(row))
            rows.append(row)

        out = []
        for c in range(sutun):
            for r in range(len(rows)):
                out.append(rows[r][c])
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        sutun = int(key1)
        if sutun < 2:
            raise ValueError("Route için sütun sayısı >= 2 olmalı.")
        n = len(text)
        if n % sutun != 0:
            raise ValueError("Şifreli metin uzunluğu sütun sayısına bölünmeli (dolgu bekleniyor).")
        satir = n // sutun

        table = [[""]*sutun for _ in range(satir)]
        idx = 0
        for c in range(sutun):
            for r in range(satir):
                table[r][c] = text[idx]
                idx += 1

        return "".join("".join(r) for r in table)
