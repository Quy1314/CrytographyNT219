# Student Handbook — OpenSSL for SHA-2 / SHA-3 (text & files)

**Goal.** Copy-pasteable commands to compute and verify SHA-2 / SHA-3 digests for **text** and **files** on Linux/macOS (Bash) and Windows (PowerShell). Includes **HMAC**, **CMAC**, **SHAKE (XOF)**, and a short **length-extension attack** primer.

> Check your OpenSSL first:
>
> ```bash
> openssl version
> openssl list -digest-commands | tr ' ' '\n' | grep -E 'sha3|shake'   # see if SHA-3/SHAKE exist
> ```

---

## 0) Cheat sheet (safe defaults)

| Purpose | Bash (Linux/macOS/WSL/Git Bash) | Windows PowerShell |
|---|---|---|
| SHA-256 of **UTF-8 text (no newline)** | `echo -n 'abc' \| openssl dgst -sha256` | `$b=[Text.Encoding]::UTF8.GetBytes('abc'); [IO.File]::WriteAllBytes('msg.bin',$b); openssl dgst -sha256 msg.bin` |
| SHA-256 of **hex bytes** `48656c6c6f` | `printf '%s' 48656c6c6f \| xxd -r -p \| openssl dgst -sha256` | `$hex='48656c6c6f'; $bytes=for($i=0;$i -lt $hex.Length;$i+=2){[Convert]::ToByte($hex.Substring($i,2),16)}; [IO.File]::WriteAllBytes('msg.bin',$bytes); openssl dgst -sha256 msg.bin` |
| SHA-3-256 of file | `openssl dgst -sha3-256 file.bin` | `openssl dgst -sha3-256 file.bin` |
| SHAKE256 (64-byte XOF) of file | `openssl dgst -shake256 -xoflen 64 file.bin` | `openssl dgst -shake256 -xoflen 64 file.bin` |
| HMAC-SHA-256 of file (ASCII key) | `openssl dgst -sha256 -hmac 'secret' file.bin` | same |
| HMAC with SHA3-256 (portable) | `openssl dgst -mac HMAC -macopt digest:sha3-256 -macopt key:secret file.bin` | same |
| HMAC-SHA-256 (hex key) | `openssl dgst -mac HMAC -macopt digest:sha256 -macopt hexkey:001122... file.bin` | same |
| CMAC-AES-128 (hex key) | `openssl cmac -cipher aes-128-cbc -macopt hexkey:001122... file.bin` | same |
| Raw (binary) digest → file | `openssl dgst -sha256 -binary file.bin > file.sha256.bin` | same |
| Base64 digest (one-line) | `openssl dgst -sha256 -binary file.bin \| openssl base64 -A` | same |

> Tip: `-r` prints coreutils style (`<hex>  <file>`). `-hex` is default; `-binary` outputs raw bytes.

---

## 1) Algorithms at a glance

### SHA-2 family

- **SHA-224**, **SHA-256**, **SHA-384**, **SHA-512**, **SHA-512/224**, **SHA-512/256**  
- OpenSSL names: `-sha224`, `-sha256`, `-sha384`, `-sha512`, `-sha512-224`, `-sha512-256`.

### SHA-3 (Keccak sponge)

- Fixed length: **SHA3-224/256/384/512** → `-sha3-224`, `-sha3-256`, …
- XOFs: **SHAKE128**, **SHAKE256** → `-shake128`, `-shake256` with `-xoflen <bytes>`.
- Relatives: cSHAKE, KMAC (CLI coverage varies; see §4 for HMAC/CMAC).

---

## 2) Hash a **text input** (bytes correctness first)

### 2.1 Bash (UTF-8 text / hex bytes)

```ps
[Text.Encoding]::UTF8.GetBytes('I hate Putin and CCCP') | openssl dgst -sha256
```

```cmd
echo|set /p="I hate Putin and CCCP" | openssl dgst -sha256
```

```bash
# Exact UTF-8 bytes, no trailing newline
echo -n 'The quick brown fox' | openssl dgst -sha256
echo -n 'The quick brown fox' | openssl dgst -sha512
echo -n 'The quick brown fox' | openssl dgst -sha3-256
echo -n 'The quick brown fox' | openssl dgst -shake256 -xoflen 64

# If the message is given as HEX (bytes, not ASCII of hex):
HEX='48656c6c6f20776f726c64'  # "Hello world"
printf '%s' "$HEX" | xxd -r -p | openssl dgst -sha256

# Fallback if xxd is missing:
printf '%s' "$HEX" \
| python3 -c 'import sys,binascii,sys; sys.stdout.buffer.write(binascii.unhexlify(sys.stdin.read().strip()))' \
| openssl dgst -sha256
```

> **Pitfall:** `echo` without `-n` adds `0x0a`. That changes the hash.

### 2.2 PowerShell (BOM-safe, no UTF-16 surprises)

```powershell
# UTF-8 bytes without BOM/newline → file → hash
$msg = 'The quick brown fox'
[byte[]]$b = [Text.Encoding]::UTF8.GetBytes($msg)
[IO.File]::WriteAllBytes('msg.bin', $b)
openssl dgst -sha256 msg.bin
openssl dgst -sha3-256 msg.bin
openssl dgst -shake256 -xoflen 64 msg.bin

# HEX → bytes → file → hash
$hex = '48656c6c6f20776f726c64'
[byte[]]$bytes = for($i=0; $i -lt $hex.Length; $i+=2){ [Convert]::ToByte($hex.Substring($i,2),16) }
[IO.File]::WriteAllBytes('msg.bin', $bytes)
openssl dgst -sha256 msg.bin
```

> **Pitfall:** `Set-Content` in Windows PowerShell 5 may write BOM or UTF-16LE. Prefer `WriteAllBytes`.

---

## 3) Hash **files** (binary-exact, multi-file friendly)

### 3.1 Bash

```bash
# Hex output (default)
openssl dgst -sha256 path/to/file.bin

# Raw digest bytes → save / base64
openssl dgst -sha256 -binary file.bin > file.sha256.bin
openssl dgst -sha256 -binary file.bin | openssl base64 -A > file.sha256.b64

# Coreutils-style (<hex>  <file>)
openssl dgst -sha256 -r file.bin
```

**Verify against an expected hex**

```bash
EXPECTED=ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
ACTUAL=$(echo -n abc | openssl dgst -sha256 | awk '{print $2}')
test "$ACTUAL" = "$EXPECTED" && echo OK || echo FAIL
```

**Batch: write and verify a `SHA256SUMS` file with OpenSSL (no sha256sum)**

```bash
# Write sums
for f in *.bin; do openssl dgst -sha256 -r "$f"; done > SHA256SUMS

# Verify
awk '{print $2" "$1}' SHA256SUMS | while read -r file sum; do
  calc=$(openssl dgst -sha256 -r "$file" | awk '{print $1}')
  if [ "$calc" != "$sum" ]; then echo "FAIL  $file"; exit 1; fi
done; echo "All OK"
```

### 3.2 PowerShell

```powershell
openssl dgst -sha256 'C:\data\file.bin'
openssl dgst -sha256 -binary file.bin | openssl base64 -A
```

---

## 4) MACs: HMAC (SHA-2/3) and CMAC (AES)

### 4.1 HMAC (use for authenticity; defeats length-extension)

**Simple (ASCII key, SHA-256)**

```bash
openssl dgst -sha256 -hmac 'secret' file.bin
```

**Portable for SHA-3 (works even when `-hmac`+`-sha3-256` isn’t wired)**

```bash
openssl dgst -mac HMAC -macopt digest:sha3-256 -macopt key:secret file.bin
```

**Hex key (no ambiguity about encoding)**

```bash
# 32-byte key (256-bit) hex
KEYHEX='00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
openssl dgst -mac HMAC -macopt digest:sha256 -macopt hexkey:$KEYHEX file.bin
```

> **Key tips:** generate with `openssl rand -hex 32` (256-bit). Store keys as hex to avoid BOM/encoding issues.

### 4.2 CMAC (AES-CMAC)

```bash
# AES-128 key (16 bytes hex)
openssl cmac -cipher aes-128-cbc -macopt hexkey:00112233445566778899AABBCCDDEEFF file.bin

# AES-256 key (32 bytes hex)
KEY256='00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'
openssl cmac -cipher aes-256-cbc -macopt hexkey:$KEY256 file.bin
```

> The `-cipher aes-*-cbc` token selects **key size**; CBC “mode” name is historical here (CMAC ignores IV).

**OpenSSL 3 alternative (same result)**

```bash
# Either form is fine; keep one style in your scripts
openssl mac -mac cmac -cipher aes-128-cbc -macopt hexkey:... file.bin
```

---

## 5) SHAKE / XOF quick notes & self-check

```bash
# Arbitrary-length output
openssl dgst -shake128 -xoflen 32 file.bin    # 32-byte XOF
openssl dgst -shake256 -xoflen 64 file.bin    # 64-byte XOF (common)
```

> **Sanity check:** XOF length must match your protocol spec; changing `-xoflen` changes the result.

---

## 6) Length-extension (SHA-2) — what, demo, fix

**Why it happens.** SHA-2 is Merkle–Damgård. If you publish `SHA256(secret || msg)`, an attacker who knows the hash and can **guess the secret length** can continue hashing `pad || extra` from the exposed internal state.

**Sketch**

```bash
# Insecure MAC by defender:
cat secret.bin msg.bin | openssl dgst -sha256 -binary > tag.bin

# Attacker needs a tool that sets IV = tag and initial bitlength ⇒ forge(secret || msg || pad || extra)
# `openssl dgst` cannot set an arbitrary IV; use dedicated tools (e.g., hash_extender/hashpump) for the demo.
```

**Mitigations**
- Use **HMAC**: `HMAC_SHA256(key, msg)` (recommended).
- For sponge hashes, **don’t** hand-roll `SHA3(key || msg)`; prefer **KMAC** (SP 800-185) or HMAC.

---

## 7) Known-good quick vectors

```bash
# SHA-256("abc")
# ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
echo -n abc | openssl dgst -sha256 -r

# SHA3-256("abc")
# 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
echo -n abc | openssl dgst -sha3-256 -r
```

---

## 8) Troubleshooting & pitfalls (read before grading)

- **Newlines:** `echo -n` vs `echo` changes bytes.
- **Encodings:** Windows text cmdlets may add **BOM** or UTF-16LE. Use byte APIs (`WriteAllBytes`).
- **CRLF vs LF:** Hashing must be over the intended bytes; moving text across OSes can change endings.
- **OpenSSL version:** SHA-3/XOF flags need ≥ 1.1.1 (XOF better in 3.x). `-mac HMAC -macopt digest:sha3-256` is safest for HMAC-SHA3.
- **Binary vs hex:** `-binary` gives raw bytes; pipe to `openssl base64 -A` if your protocol wants base64.
- **Performance note:** On 64-bit CPUs, **SHA-512** is often faster than SHA-256; some systems standardize on it.

---

## 9) Handy one-liners you’ll reuse

```bash
# Compute common digests for one file
f=file.bin; for a in sha224 sha256 sha384 sha512 sha512-224 sha512-256 sha3-224 sha3-256 sha3-384 sha3-512; do
  printf '%-11s ' "$a"; openssl dgst -$a "$f" | awk '{print $2}';
done

# PowerShell: file bytes → hex string (debugging)
[BitConverter]::ToString([IO.File]::ReadAllBytes('file.bin')).Replace('-', '')

# Generate strong HMAC key (256-bit) as hex
openssl rand -hex 32
```

