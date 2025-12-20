# algorithms/railfence.py
from __future__ import annotations
from .base import BaseCipherTR

class RailFenceCipherTR(BaseCipherTR):
    def encrypt(self, text: str, key1=None, key2=None) -> str:
        ray_sayisi = int(key1)
        if ray_sayisi < 2:
            raise ValueError("RailFence için ray sayısı >= 2 olmalı.")
        # Boşlukları da dahil ederek şifreliyoruz (klasik)
        raylar = [[] for _ in range(ray_sayisi)]
        ray = 0
        yon = 1
        for ch in text:
            raylar[ray].append(ch)
            ray += yon
            if ray == 0 or ray == ray_sayisi - 1:
                yon *= -1
        return "".join("".join(r) for r in raylar)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        ray_sayisi = int(key1)
        if ray_sayisi < 2:
            raise ValueError("RailFence için ray sayısı >= 2 olmalı.")
        n = len(text)

        # 1) zigzag şablonu
        isaret = [[False]*n for _ in range(ray_sayisi)]
        ray, yon = 0, 1
        for i in range(n):
            isaret[ray][i] = True
            ray += yon
            if ray == 0 or ray == ray_sayisi - 1:
                yon *= -1

        # 2) şifreli metni raylara doldur
        idx = 0
        raylar = [[""]*n for _ in range(ray_sayisi)]
        for r in range(ray_sayisi):
            for c in range(n):
                if isaret[r][c]:
                    raylar[r][c] = text[idx]
                    idx += 1

        # 3) zigzag okuyarak çöz
        out = []
        ray, yon = 0, 1
        for i in range(n):
            out.append(raylar[ray][i])
            ray += yon
            if ray == 0 or ray == ray_sayisi - 1:
                yon *= -1
        return "".join(out)
