"""
Step 1: Extract the Binance-hack wallet addresses published by the FBI (alert of 31 Oct 2026)
and save them as a clean CSV with explorer links.

Usage (run on your own computer):
    pip install requests
    python extract_fbi_addresses.py                      # downloads the FBI page itself
    python extract_fbi_addresses.py fbi_page.html        # or use a page you saved (Ctrl+S) if the download is blocked

Output: binance_hack_addresses.csv  (chain, address, explorer_url)
FBI says to expect: 608 Ethereum, 19 Bitcoin, 1 Solana = 628 total.
"""

import csv
import hashlib
import re
import sys
from html import unescape

FBI_URL = "https://www.fbi.gov/investigate/cyber/alerts/2026/north-korea-responsible-for-6-billion-binance-attack"
EXPECTED = {"ethereum": 608, "bitcoin": 19, "solana": 1}
OUT_FILE = "binance_hack_addresses.csv"

EXPLORERS = {
    "ethereum": "https://etherscan.io/address/{}",
    "bitcoin": "https://mempool.space/address/{}",
    "solana": "https://solscan.io/account/{}",
}

B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# ---------- validators (so random text never gets mistaken for an address) ----------

def b58decode(s):
    n = 0
    for ch in s:
        n = n * 58 + B58_ALPHABET.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    pad = len(s) - len(s.lstrip("1"))
    return b"\x00" * pad + raw


def valid_btc_base58(addr):
    """Legacy (1...) or P2SH (3...) Bitcoin address with a correct checksum."""
    try:
        data = b58decode(addr)
    except ValueError:
        return False
    if len(data) != 25:
        return False
    payload, checksum = data[:-4], data[-4:]
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4] == checksum


def bech32_polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def valid_btc_bech32(addr):
    """SegWit / Taproot Bitcoin address (bc1...) with a correct checksum."""
    addr = addr.lower()
    if not addr.startswith("bc1"):
        return False
    hrp, data = "bc", addr[3:]
    if any(c not in BECH32_CHARSET for c in data) or len(data) < 6:
        return False
    values = [BECH32_CHARSET.index(c) for c in data]
    hrp_exp = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    const = bech32_polymod(hrp_exp + values)
    return const in (1, 0x2BC830A3)  # bech32 (v0) or bech32m (taproot)


def valid_solana(addr):
    try:
        return len(b58decode(addr)) == 32
    except ValueError:
        return False


# ---------- extraction ----------

def get_page_text(source):
    if source:
        with open(source, encoding="utf-8", errors="ignore") as f:
            return f.read()
    import requests
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                             "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"}
    r = requests.get(FBI_URL, headers=headers, timeout=30)
    r.raise_for_status()
    return r.text


def extract(text):
    text = unescape(re.sub(r"<[^>]+>", " ", text))  # strip HTML tags
    found = {"ethereum": [], "bitcoin": [], "solana": []}
    seen = set()

    def add(chain, addr):
        key = addr.lower() if chain == "ethereum" else addr
        if key not in seen:
            seen.add(key)
            found[chain].append(addr)

    # Ethereum: 0x + 40 hex chars
    for m in re.finditer(r"\b0x[a-fA-F0-9]{40}\b", text):
        add("ethereum", m.group())

    # Bitcoin bech32 / taproot
    for m in re.finditer(r"\bbc1[a-zA-HJ-NP-Z0-9]{25,87}\b", text, re.IGNORECASE):
        if valid_btc_bech32(m.group()):
            add("bitcoin", m.group().lower())

    # Base58 tokens: legacy Bitcoin or Solana
    for m in re.finditer(r"\b[1-9A-HJ-NP-Za-km-z]{25,44}\b", text):
        tok = m.group()
        if tok[0] in "13" and len(tok) <= 35 and valid_btc_base58(tok):
            add("bitcoin", tok)
        elif len(tok) >= 32 and valid_solana(tok):
            add("solana", tok)

    return found


def main():
    source = sys.argv[1] if len(sys.argv) > 1 else None
    try:
        text = get_page_text(source)
    except Exception as e:
        print(f"Could not download the FBI page ({e}).")
        print("Open this link in your browser, press Ctrl+S to save it, then run:")
        print(f"   python extract_fbi_addresses.py saved_page.html\n   {FBI_URL}")
        sys.exit(1)

    found = extract(text)

    with open(OUT_FILE, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["chain", "address", "explorer_url"])
        for chain, addrs in found.items():
            for a in addrs:
                w.writerow([chain, a, EXPLORERS[chain].format(a)])

    print(f"Saved {OUT_FILE}\n")
    all_ok = True
    for chain, exp in EXPECTED.items():
        got = len(found[chain])
        status = "OK" if got == exp else "CHECK"
        all_ok &= got == exp
        print(f"  {chain:<9} found {got:>4} / expected {exp:<4} [{status}]")
    total = sum(len(v) for v in found.values())
    print(f"  {'total':<9} found {total:>4} / expected 628")
    if not all_ok:
        print("\nCounts don't match the FBI's numbers. The page may have changed, or the saved copy is "
              "incomplete (some pages load the list in a separate attachment). Check the alert page "
              "for a linked list and run this script on that file too.")


if __name__ == "__main__":
    main()
