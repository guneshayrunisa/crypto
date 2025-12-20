# algorithms/columnar.py
from __future__ import annotations
from .base import BaseCipherTR

class ColumnarCipherTR(BaseCipherTR):
    # key1: anahtar kelime (ör: "KRIPTO")
    # Dolgu: 'X'
    def _order(self, anahtar: str):
        a = (anahtar or "").upper().strip()
        if not a:
            raise ValueError("Columnar anahtarı boş olamaz.")
        # sıralama: harfe göre, eşitlikte soldan sağa
        indexed = list(enumerate(a))
        indexed.sort(key=lambda t: (t[1], t[0]))
        # sıra numarası: orijinal index -> sıralı konum
        order = [0]*len(a)
        for pos, (orig_i, _) in enumerate(indexed):
            order[orig_i] = pos
        return order

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        anahtar = str(key1)
        order = self._order(anahtar)
        k = len(order)
        dolgu = "X"
        # tabloyu satır satır doldur
        rows = []
        t = list(text)
        while t:
            row = t[:k]; t = t[k:]
            if len(row) < k:
                row += [dolgu] * (k - len(row))
            rows.append(row)

        # sütunları sıralı sırayla oku
        out = []
        for target_rank in range(k):
            col = order.index(target_rank)
            for r in rows:
                out.append(r[col])
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        anahtar = str(key1)
        order = self._order(anahtar)
        k = len(order)
        n = len(text)
        if n % k != 0:
            raise ValueError("Şifreli metin uzunluğu anahtar uzunluğuna bölünmeli (dolgu bekleniyor).")
        satir_sayisi = n // k

        # boş tablo
        table = [[""]*k for _ in range(satir_sayisi)]

        idx = 0
        for target_rank in range(k):
            col = order.index(target_rank)
            for r in range(satir_sayisi):
                table[r][col] = text[idx]
                idx += 1

        return "".join("".join(r) for r in table)
