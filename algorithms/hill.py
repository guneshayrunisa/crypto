# algorithms/hill.py
from __future__ import annotations
from .base import BaseCipherTR, _modinv
from math import gcd

def _det2(a):  # 2x2
    return a[0][0]*a[1][1] - a[0][1]*a[1][0]

def _det3(a):  # 3x3
    return (
        a[0][0]*(a[1][1]*a[2][2]-a[1][2]*a[2][1])
        - a[0][1]*(a[1][0]*a[2][2]-a[1][2]*a[2][0])
        + a[0][2]*(a[1][0]*a[2][1]-a[1][1]*a[2][0])
    )

def _adj2(a):
    return [
        [ a[1][1], -a[0][1]],
        [-a[1][0],  a[0][0]],
    ]

def _adj3(a):
    # kofaktör matrisi + transpoz
    c = [[0]*3 for _ in range(3)]
    c[0][0] =  (a[1][1]*a[2][2]-a[1][2]*a[2][1])
    c[0][1] = -(a[1][0]*a[2][2]-a[1][2]*a[2][0])
    c[0][2] =  (a[1][0]*a[2][1]-a[1][1]*a[2][0])

    c[1][0] = -(a[0][1]*a[2][2]-a[0][2]*a[2][1])
    c[1][1] =  (a[0][0]*a[2][2]-a[0][2]*a[2][0])
    c[1][2] = -(a[0][0]*a[2][1]-a[0][1]*a[2][0])

    c[2][0] =  (a[0][1]*a[1][2]-a[0][2]*a[1][1])
    c[2][1] = -(a[0][0]*a[1][2]-a[0][2]*a[1][0])
    c[2][2] =  (a[0][0]*a[1][1]-a[0][1]*a[1][0])

    # transpose
    return [[c[j][i] for j in range(3)] for i in range(3)]

def _matmul_mod(A, v, mod):
    n = len(A)
    out = [0]*n
    for i in range(n):
        s = 0
        for j in range(n):
            s += A[i][j]*v[j]
        out[i] = s % mod
    return out

class HillCipherTR(BaseCipherTR):
    """
    Hill (mod 29, Türkçe alfabe).
    key1: matris (liste) 2x2 veya 3x3 (örn [[3,3],[2,5]])
    Dolgu harfi: 'X' değil, Türkçe alfabede olan 'A' kullanıyoruz.
    """
    def _check_matrix(self, A):
        if not isinstance(A, list) or not A or not isinstance(A[0], list):
            raise ValueError("Hill key1 matris olmalı: [[...],[...]]")
        n = len(A)
        if n not in (2,3) or any(len(row)!=n for row in A):
            raise ValueError("Hill matrisi 2x2 veya 3x3 olmalı.")
        mod = len(self.alfabe)
        det = _det2(A) if n==2 else _det3(A)
        det %= mod
        if gcd(det, mod) != 1:
            raise ValueError(f"Hill matrisi terslenemez. det={det}, mod={mod}")
        return n, det, mod

    def _inverse_matrix(self, A):
        n, det, mod = self._check_matrix(A)
        det_inv = _modinv(det, mod)
        adj = _adj2(A) if n==2 else _adj3(A)
        inv = [[(det_inv * adj[i][j]) % mod for j in range(n)] for i in range(n)]
        return inv

    def encrypt(self, text: str, key1=None, key2=None) -> str:
        A = key1
        n, _, mod = self._check_matrix(A)

        # sadece harfleri blokla; diğer karakterleri aynen geçiriyoruz
        # (basit yaklaşım: metni harf harf işleyip blok biriktir)
        out = []
        blok = []

        def flush_block():
            nonlocal blok
            if not blok:
                return
            while len(blok) < n:
                blok.append(self._index("A"))  # dolgu
            y = _matmul_mod(A, blok, mod)
            for val in y:
                out.append(self._char(val))
            blok = []

        for ch in text:
            if self._is_letter(ch):
                blok.append(self._index(ch.upper()))
                if len(blok) == n:
                    y = _matmul_mod(A, blok, mod)
                    for val in y:
                        out.append(self._char(val))
                    blok = []
            else:
                flush_block()
                out.append(ch)

        flush_block()
        return "".join(out)

    def decrypt(self, text: str, key1=None, key2=None) -> str:
        A = key1
        A_inv = self._inverse_matrix(A)
        n = len(A_inv)
        mod = len(self.alfabe)

        out = []
        blok = []

        def flush_block():
            nonlocal blok
            if blok:
                raise ValueError("Hill şifreli metin blok boyutuna uymuyor (harf sayısı eksik).")

        for ch in text:
            if self._is_letter(ch):
                blok.append(self._index(ch.upper()))
                if len(blok) == n:
                    x = _matmul_mod(A_inv, blok, mod)
                    for val in x:
                        out.append(self._char(val))
                    blok = []
            else:
                flush_block()
                out.append(ch)

        flush_block()
        return "".join(out)
