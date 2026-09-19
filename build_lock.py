#!/usr/bin/env python3
"""
Baut aus _source/index.html die verschluesselte index.html mit Passwort-Abfrage.

Aufruf:   python3 build_lock.py
Passwort: steht in _source/password.txt  (beides wird von Git ignoriert)

Verfahren: PBKDF2-HMAC-SHA256 (200.000 Runden) leitet aus dem Passwort einen
Schluessel ab. Der Seiteninhalt wird mit AES-256-CBC verschluesselt und mit
HMAC-SHA256 signiert (Encrypt-then-MAC). Entschluesselt wird erst im Browser
des Gastes ueber die Web-Crypto-API.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "_source", "index.html")
PW_FILE = os.path.join(HERE, "_source", "password.txt")
OUT = os.path.join(HERE, "index.html")
GATE = os.path.join(HERE, "_gate_template.html")

ITERATIONS = 200_000


def normalize(pw: str) -> str:
    """Muss exakt der JS-Variante entsprechen: pw.trim().toLowerCase()"""
    return pw.strip().lower()


def derive(password: str, salt: bytes) -> tuple:
    dk = hashlib.pbkdf2_hmac("sha256", normalize(password).encode("utf-8"),
                             salt, ITERATIONS, dklen=64)
    return dk[:32], dk[32:]


def aes_cbc(key: bytes, iv: bytes, data: bytes, decrypt: bool = False) -> bytes:
    cmd = ["openssl", "enc", "-aes-256-cbc",
           "-K", key.hex(), "-iv", iv.hex()]
    if decrypt:
        cmd.append("-d")
    res = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if res.returncode != 0:
        sys.exit("openssl-Fehler: " + res.stderr.decode("utf-8", "replace"))
    return res.stdout


def main():
    for path in (SRC, PW_FILE, GATE):
        if not os.path.exists(path):
            sys.exit("Datei fehlt: " + path)

    with open(PW_FILE, encoding="utf-8") as fh:
        password = fh.read()
    if not normalize(password):
        sys.exit("_source/password.txt ist leer.")

    with open(SRC, "rb") as fh:
        plaintext = fh.read()

    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(16)
    enc_key, mac_key = derive(password, salt)

    ciphertext = aes_cbc(enc_key, iv, plaintext)
    mac = hmac.new(mac_key, iv + ciphertext, hashlib.sha256).digest()

    # Selbsttest: einmal komplett zurueckrechnen, bevor irgendetwas geschrieben wird.
    check_enc, check_mac = derive(password, salt)
    if not hmac.compare_digest(
            hmac.new(check_mac, iv + ciphertext, hashlib.sha256).digest(), mac):
        sys.exit("Selbsttest fehlgeschlagen: HMAC stimmt nicht.")
    if aes_cbc(check_enc, iv, ciphertext, decrypt=True) != plaintext:
        sys.exit("Selbsttest fehlgeschlagen: Entschluesselung weicht ab.")
    # Falsches Passwort muss zuverlaessig abgewiesen werden.
    _, wrong_mac = derive(normalize(password) + "x", salt)
    if hmac.compare_digest(
            hmac.new(wrong_mac, iv + ciphertext, hashlib.sha256).digest(), mac):
        sys.exit("Selbsttest fehlgeschlagen: falsches Passwort wurde akzeptiert.")

    payload = json.dumps({
        "v": 1,
        "it": ITERATIONS,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "mac": base64.b64encode(mac).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
    }, separators=(",", ":"))

    with open(GATE, encoding="utf-8") as fh:
        gate = fh.read()
    if "__PAYLOAD__" not in gate:
        sys.exit("Platzhalter __PAYLOAD__ fehlt in _gate_template.html")

    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(gate.replace("__PAYLOAD__", payload))

    print("OK  Quelle:        {:>7,} Bytes".format(len(plaintext)))
    print("OK  Verschluesselt: {:>7,} Bytes".format(len(ciphertext)))
    print("OK  index.html:     {:>7,} Bytes".format(os.path.getsize(OUT)))
    print("OK  Passwort:      '{}'  (Gross/Klein egal)".format(normalize(password)))


if __name__ == "__main__":
    main()
