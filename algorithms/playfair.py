# algorithms/playfair.py
from __future__ import annotations

class PlayfairCipherTR:
    """
    Playfair klasik 5x5 olduğu için burada EN (A-Z, J yok) kullanıyoruz.
    Türkçe 29 harfle Playfair istersen 6x5 varyantını ayrıca yazarım.
    """
    ALF = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J yok

    def _hazirla(self, anahtar: str):
        anahtar = (anahtar or "").upper()
        anahtar = "".join([c for c in anahtar if c.isalpha()])
        anahtar = anahtar.replace("J", "I")
        seen = set()
        dizi = []
        for c in (anahtar + self.ALF):
            if c in self.ALF and c not in seen:
                seen.add(c); dizi.append(c)
        # 5x5
        mat = [dizi[i*5:(i+1)*5] for i in range(5)]
        pos = {mat[r][c]:(r,c) for r in range(5) for c in range(5)}
        return mat, pos

    def _ciftler(self, text: str):
        t = "".join([c for c in text.upper() if c.isalpha()]).replace("J","I")
        i = 0
        pairs = []
        while i < len(t):
            a = t[i]
            b = t[i+1] if i+1 < len(t) else "X"
            if a == b:
                pairs.append((a, "X"))
                i += 1
            else:
                pairs.append((a, b))
                i += 2
        if len(pairs) > 0 and pairs[-1][1] is None:
            pairs[-1] = (pairs[-1][0], "X")
        return pairs

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        mat, pos = self._hazirla(str(key1))
        out = []
        for a,b in self._ciftler(text):
            ra,ca = pos[a]; rb,cb = pos[b]
            if ra == rb:
                out.append(mat[ra][(ca+1)%5]); out.append(mat[rb][(cb+1)%5])
            elif ca == cb:
                out.append(mat[(ra+1)%5][ca]); out.append(mat[(rb+1)%5][cb])
            else:
                out.append(mat[ra][cb]); out.append(mat[rb][ca])
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        mat, pos = self._hazirla(str(key1))
        t = "".join([c for c in text.upper() if c.isalpha()]).replace("J","I")
        if len(t) % 2 != 0:
            raise ValueError("Playfair şifreli metin uzunluğu çift olmalı.")
        out = []
        for i in range(0, len(t), 2):
            a,b = t[i], t[i+1]
            ra,ca = pos[a]; rb,cb = pos[b]
            if ra == rb:
                out.append(mat[ra][(ca-1)%5]); out.append(mat[rb][(cb-1)%5])
            elif ca == cb:
                out.append(mat[(ra-1)%5][ca]); out.append(mat[(rb-1)%5][cb])
            else:
                out.append(mat[ra][cb]); out.append(mat[rb][ca])
        return "".join(out)
