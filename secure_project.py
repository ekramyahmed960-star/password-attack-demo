
import time
import itertools

# ============================================================
# 1) SHA-256 ãäÝÐ íÏæíðÇ (ÈÏæä hashlib)
# ============================================================

# ÇáËæÇÈÊ K (Ãæá 32 ÈÊ ãä ßÓæÑ ÇáÌÐæÑ ÇáÊßÚíÈíÉ áÃæá 64 ÚÏÏ Ãæáí)
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# ÇáÞíã ÇáÇÈÊÏÇÆíÉ H0..H7 (Ãæá 32 ÈÊ ãä ßÓæÑ ÇáÌÐæÑ ÇáÊÑÈíÚíÉ áÃæá 8 ÃÚÏÇÏ ÃæáíÉ)
_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

_MASK32 = 0xFFFFFFFF


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_bytes(data: bytes) -> bytes:
    """ÊäÝíÐ íÏæí ßÇãá áÎæÇÑÒãíÉ SHA-256 Úáì ãÓÊæì ÇáÈÇíÊÇÊ."""
    # --- 1) ÇáÍÔæ (padding) ---
    msg = bytearray(data)
    orig_len_bits = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF

    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0x00)
    msg += orig_len_bits.to_bytes(8, byteorder="big")

    # --- 2) ÇáÞíã ÇáÇÈÊÏÇÆíÉ ---
    h = list(_H0)

    # --- 3) ãÚÇáÌÉ ßá ßÊáÉ ãä 64 ÈÇíÊ (512 ÈÊ) ---
    for chunk_start in range(0, len(msg), 64):
        chunk = msg[chunk_start:chunk_start + 64]

        w = [0] * 64
        for i in range(16):
            w[i] = int.from_bytes(chunk[i * 4:i * 4 + 4], byteorder="big")

        for i in range(16, 64):
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & _MASK32

        a, b, c, d, e, f, g, hh = h

        for i in range(64):
            S1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)
            ch = (e & f) ^ ((~e & _MASK32) & g)
            temp1 = (hh + S1 + ch + _K[i] + w[i]) & _MASK32
            S0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & _MASK32

            hh = g
            g = f
            f = e
            e = (d + temp1) & _MASK32
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & _MASK32

        h[0] = (h[0] + a) & _MASK32
        h[1] = (h[1] + b) & _MASK32
        h[2] = (h[2] + c) & _MASK32
        h[3] = (h[3] + d) & _MASK32
        h[4] = (h[4] + e) & _MASK32
        h[5] = (h[5] + f) & _MASK32
        h[6] = (h[6] + g) & _MASK32
        h[7] = (h[7] + hh) & _MASK32

    return b"".join(val.to_bytes(4, byteorder="big") for val in h)


def sha256(text: str) -> str:
    """æÇÌåÉ ãÊæÇÝÞÉ ãÚ ÇáßæÏ ÇáÃÕáí: äÕ -> åßÓÇÏíÓíãÇá SHA-256."""
    return _sha256_bytes(text.encode()).hex()


# ============================================================
# 2) Dictionary Attack
# ============================================================
def dictionary_attack(target_hash, wordlist):
    attempts = 0
    start = time.time()

    for word in wordlist:
        if not word:
            continue
        attempts += 1
        if sha256(word) == target_hash:
            elapsed = time.time() - start
            print(f'\n[+] PASSWORD FOUND: "{word}"')
            print(f"[+] Attempts: {attempts}")
            print(f"[+] Time: {elapsed:.4f} s")
            return word

    print(f"\n[-] Not found in dictionary ({attempts} attempts).")
    return None

# ============================================================
# 3) Brute-force
# ============================================================
def brute_force(target_hash, charset, max_length):
    attempts = 0
    start = time.time()

    for length in range(1, max_length + 1):
        for combo in itertools.product(charset, repeat=length):
            guess = "".join(combo)
            attempts += 1
            if sha256(guess) == target_hash:
                elapsed = time.time() - start
                print(f'\n[+] PASSWORD FOUND (brute): "{guess}"')
                print(f"[+] Attempts: {attempts}")
                print(f"[+] Time: {elapsed:.4f} s")
                return guess

    print(f"\n[-] Brute-force: not found ({attempts} attempts).")
    return None

# ============================================================
# 4) main — ÊÝÇÚáí
# ============================================================
if __name__ == "__main__":
    print("=" * 55)
    print(" Brute-Force / Dictionary Attack Demo (manual SHA-256)")
    print("=" * 55)

    secret = input("\n[*] Enter a password to attack: ").strip()
    if not secret:
        print("[-] Empty password. Exiting.")
        exit()

    target = sha256(secret)
    print(f"[*] Target hash (SHA-256): {target}")

    print("\nChoose attack method:")
    print("  1) Dictionary attack")
    print("  2) Brute-force (digits only, up to length you choose)")
    print("  3) Both")
    choice = input("Your choice [1/2/3]: ").strip()

    wordlist = [
        "123456", "password", "qwerty", "admin", "letmein",
        "password123", "welcome", "iloveyou", "dragon", "monkey",
        "abc123", "111111", "12345678", "sunshine", "princess",
        "football", "baseball", "shadow", "master", "superman"
    ]

    if choice in ("1", "3"):
        print("\n--- Dictionary Attack ---")
        dictionary_attack(target, wordlist)

    if choice in ("2", "3"):
        print("\n--- Brute-force Attack ---")
        charset = input("Charset (default = digits 0123456789): ").strip()
        if not charset:
            charset = "0123456789"
        try:
            max_len = int(input("Max length (default = 4): ").strip() or "4")
        except ValueError:
            max_len = 4

        space = sum(len(charset) ** L for L in range(1, max_len + 1))
        print(f"[*] Search space: {space:,} combinations")
        if space > 5_000_000:
            confirm = input("[!] This may take a while. Continue? [y/N]: ").strip().lower()
            if confirm != "y":
                print("[-] Skipped.")
                exit()

        brute_force(target, charset, max_len)

    print("\n[!] Only test against your own accounts.")