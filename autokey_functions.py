import pandas as pd
import re

# ======================================================
# HELPER FUNCTIONS
# ======================================================
def charToNum(c):
    return ord(c) - ord("A")

def numToChar(n):
    return chr(n + ord("A"))

def normalizeText(s: str) -> str:
    s = s.replace("\r", "\n")
    s = re.sub(r"\s+", " ", s)
    return s.strip()

def onlyLettersUpper(s: str) -> str:
    return re.sub(r"[^A-Z]", "", s.upper())

# ======================================================
# TEXT ENCRYPTION (Autokey Cipher)
# ======================================================
def autokeyEncrypt(plaintext, key):
    plaintext = normalizeText(plaintext).upper()
    key = onlyLettersUpper(key)

    keyStream = list(key)
    ciphertext = ""

    table = {
        "PT": [], "n(PT)": [],
        "K": [], "n(K)": [],
        "(nPT+nK)%26": [],
        "CT": [], "n(CT)": [],
        "KeyStream": []
    }

    ki = 0
    for c in plaintext:
        if c == " ":
            ciphertext += " "
            table["PT"].append(" ")
            table["n(PT)"].append("")
            table["K"].append("")
            table["n(K)"].append("")
            table["(nPT+nK)%26"].append("")
            table["CT"].append(" ")
            table["n(CT)"].append("")
            table["KeyStream"].append("".join(keyStream))
            continue

        if not c.isalpha():
            continue

        while ki < len(keyStream) and not keyStream[ki].isalpha():
            ki += 1

        if ki < len(keyStream):
            k = keyStream[ki]
        else:
            k = "A"

        ptN = charToNum(c)
        kN = charToNum(k)
        ctN = (ptN + kN) % 26
        ct = numToChar(ctN)

        ciphertext += ct
        keyStream.append(c)
        ki += 1

        table["PT"].append(c)
        table["n(PT)"].append(ptN)
        table["K"].append(k)
        table["n(K)"].append(kN)
        table["(nPT+nK)%26"].append(ctN)
        table["CT"].append(ct)
        table["n(CT)"].append(ctN)
        table["KeyStream"].append("".join(keyStream))

    return ciphertext, pd.DataFrame(table)

# ======================================================
# TEXT DECRYPTION (Autokey Cipher)
# ======================================================
def autokeyDecrypt(ciphertext, key):
    ciphertext = normalizeText(ciphertext).upper()
    key = onlyLettersUpper(key)

    keyStream = list(key)
    plaintext = ""

    table = {
        "CT": [], "n(CT)": [],
        "K": [], "n(K)": [],
        "(nCT-nK)%26": [],
        "PT": [], "n(PT)": [],
        "KeyStream": []
    }

    ki = 0
    for c in ciphertext:
        if c == " ":
            plaintext += " "
            table["CT"].append(" ")
            table["n(CT)"].append("")
            table["K"].append("")
            table["n(K)"].append("")
            table["(nCT-nK)%26"].append("")
            table["PT"].append(" ")
            table["n(PT)"].append("")
            table["KeyStream"].append("".join(keyStream))
            continue

        if not c.isalpha():
            continue

        while ki < len(keyStream) and not keyStream[ki].isalpha():
            ki += 1

        if ki < len(keyStream):
            k = keyStream[ki]
        else:
            k = "A"

        ctN = charToNum(c)
        kN = charToNum(k)
        ptN = (ctN - kN) % 26
        pt = numToChar(ptN)

        plaintext += pt
        keyStream.append(pt)
        ki += 1

        table["CT"].append(c)
        table["n(CT)"].append(ctN)
        table["K"].append(k)
        table["n(K)"].append(kN)
        table["(nCT-nK)%26"].append(ptN)
        table["PT"].append(pt)
        table["n(PT)"].append(ptN)
        table["KeyStream"].append("".join(keyStream))

    return plaintext, pd.DataFrame(table)

# ======================================================
# FIND KEY (Key Recovery Attack)
# ======================================================
def findKey(plaintext, ciphertext):
    plaintext = normalizeText(plaintext).upper()
    ciphertext = normalizeText(ciphertext).upper()

    keystream = ""
    table = {
        "PT": [], "n(PT)": [],
        "CT": [], "n(CT)": [],
        "(nCT-nPT)%26": [],
        "Key": [], "n(Key)": []
    }

    for pt, ct in zip(plaintext, ciphertext):
        if not pt.isalpha() or not ct.isalpha():
            table["PT"].append(pt)
            table["n(PT)"].append("")
            table["CT"].append(ct)
            table["n(CT)"].append("")
            table["(nCT-nPT)%26"].append("")
            table["Key"].append(" ")
            table["n(Key)"].append("")
            continue

        ptN = charToNum(pt)
        ctN = charToNum(ct)
        kN = (ctN - ptN) % 26
        k = numToChar(kN)

        keystream += k

        table["PT"].append(pt)
        table["n(PT)"].append(ptN)
        table["CT"].append(ct)
        table["n(CT)"].append(ctN)
        table["(nCT-nPT)%26"].append(kN)
        table["Key"].append(k)
        table["n(Key)"].append(kN)

    plain_no_space = onlyLettersUpper(plaintext)
    idx = keystream.find(plain_no_space[:5])
    if idx != -1:
        real_key = keystream[:idx]
    else:
        real_key = keystream

    return real_key, pd.DataFrame(table)

# ======================================================
# BINARY FILE ENCRYPTION (File Biner Implementation)
# ======================================================
def autokeyEncryptBytes(data: bytes, key: str) -> bytes:
    """
    Enkripsi file biner byte-per-byte menggunakan Autokey Cipher.
    Header file ikut terenkripsi sehingga file tidak bisa dibuka.
    """
    if not key:
        raise ValueError("Key tidak boleh kosong!")
    
    key_bytes = key.encode("utf-8")
    keyStream = bytearray(key_bytes)
    result = bytearray()

    for i, b in enumerate(data):
        if i < len(keyStream):
            k = keyStream[i]
        else:
            k = keyStream[i % len(key_bytes)]
        
        ct = (b + k) % 256
        result.append(ct)
        keyStream.append(b)

    return bytes(result)

# ======================================================
# BINARY FILE DECRYPTION (File Biner Implementation)
# ======================================================
def autokeyDecryptBytes(data: bytes, key: str) -> bytes:
    """
    Dekripsi file biner byte-per-byte menggunakan Autokey Cipher.
    File akan kembali ke kondisi semula dan bisa dibuka.
    """
    if not key:
        raise ValueError("Key tidak boleh kosong!")
    
    key_bytes = key.encode("utf-8")
    keyStream = bytearray(key_bytes)
    result = bytearray()

    for i, b in enumerate(data):
        if i < len(keyStream):
            k = keyStream[i]
        else:
            k = keyStream[i % len(key_bytes)]
        
        pt = (b - k) % 256
        result.append(pt)
        keyStream.append(pt)

    return bytes(result)
