# algorithms/base.py
from __future__ import annotations
from dataclasses import dataclass
from math import gcd

# Türkçe alfabe (29 harf) — Q, W, X yok
TURKCE_ALFABE = "ABCÇDEFGĞHIİJKLMNOÖPRSŞTUÜVYZ"
M = len(TURKCE_ALFABE)  # 29


def _modinv(a: int, m: int) -> int:
    a %= m
    if gcd(a, m) != 1:
        raise ValueError(f"Modüler ters yok: a={a}, mod={m}")
    # Extended Euclid
    t, newt = 0, 1
    r, newr = m, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    return t % m


def _normalize_tr(text: str) -> str:
    # Türkçe büyük/küçük harf dönüşümü için Python'un upper/lower'ı yeterli çoğu durumda.
    # Burada sadece tutarlı olsun diye dokunmuyoruz.
    return text


@dataclass
class BaseCipherTR:
    alfabe: str = TURKCE_ALFABE

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        raise NotImplementedError

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        raise NotImplementedError

    def _index(self, ch: str) -> int:
        return self.alfabe.index(ch)

    def _char(self, idx: int) -> str:
        return self.alfabe[idx % len(self.alfabe)]

    def _is_letter(self, ch: str) -> bool:
        return ch.upper() in self.alfabe
