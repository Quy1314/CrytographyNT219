# OpenSSL Cryptography Lab Guide

This guide is designed as a CLI-oriented lab manual for your cryptography sessions on Windows (with `openssl.exe` in `C:\Apache24\bin`).

---

## 0. Environment Setup (Windows)

```bat
:: Make sure Apache OpenSSL is first in PATH
set "PATH=D:\cryptobcu\openssl360\msvc\bin;%PATH%"

:: Check OpenSSL version
openssl version -a
```

If a command fails, you can see available subcommands with:

```bat
openssl help
```

---

## 1. Discovering Algorithms & Providers

### 1.1. List public-key algorithms

```bat
openssl list -public-key-algorithms
```

Use this to see RSA, EC, X25519, ED25519, ML-DSA, ML-KEM, SLH-DSA, etc., and their internal names (IDs).

### 1.2. List ciphers & digests

```bat
openssl list -cipher-algorithms
openssl list -digest-algorithms
```

### 1.3. TLS groups (classical + PQC hybrids)

```bat
openssl list -tls-groups -tls1_3
```

You should see groups like `X25519`, `secp256r1`, and hybrids like `X25519MLKEM768`, `SecP256r1MLKEM768`, etc.

### 1.4. Providers

```bat
openssl list -providers -verbose
```

This tells you which providers are active (e.g., `default`, `legacy`) and which algorithms they offer.

### 1.5. Algorithm-specific help

```bat
openssl genpkey -algorithm RSA -help
openssl genpkey -algorithm EC -help
openssl genpkey -algorithm ML-DSA-65 -help
openssl genpkey -algorithm ML-KEM-768 -help
```

---

## 2. RSA-PSS (Digital Signatures)

### 2.1. Key generation

```bat
:: Generate a 3072-bit RSA key
openssl genpkey -algorithm RSA -out rsa_3072.pem ^
    -pkeyopt rsa_keygen_bits:3072

:: Extract public key
openssl pkey -in rsa_3072.pem -pubout -out rsa_3072_pub.pem

:: Inspect the RSA private key and its public point
openssl pkey -in rsa_3072.pem -text -noout

:: Inspect the RSA public key details (n, e)
openssl pkey -in rsa_3072_pub.pem -pubin -text -noout

```

### 2.2. Sign & verify a file using RSA-PSS

```bat
:: Sign
openssl dgst -sha256 -sigopt rsa_padding_mode:pss ^
    -sign rsa_3072.pem -out msg_rsapss.sig <input file>

:: Inspect the signature file
hexdump -C msg_rsapss.sig
xxd -p msg_rsapss.sig

:: Verify 01
openssl dgst -sha256 -sigopt rsa_padding_mode:pss ^
    -verify rsa_3072_pub.pem -signature msg_rsapss.sig <input file>

:: Verify 02
edit the msg_rsapss.sig and input file then check again
```

---

## 3. ECDSA on P-256

### 3.1. Key generation

```bat
:: Generate EC private key on P-256
openssl genpkey -algorithm EC -out ec_p256.pem ^
    -pkeyopt ec_paramgen_curve:P-256 ^
    -pkeyopt ec_param_enc:named_curve

:: Extract public key
openssl pkey -in ec_p256.pem -pubout -out ec_p256_pub.pem

:: Inspect the EC private key
openssl pkey -in ec_p256.pem -text -noout

:: Inspect the EC public key
openssl pkey -in ec_p256_pub.pem -pubin -text -noout

:: Verify 02
edit the msg_rsapss.sig and input file then check again
```

### 3.2. Sign & verify

```bat
:: Sign (ECDSA)
openssl dgst -sha256 -sign ec_p256.pem -out msg_ecdsa.sig message.txt

:: Inspect the signature file
hexdump -C msg_ecdsa.sig
xxd -p msg_ecdsa.sig
openssl asn1parse -in msg_ecdsa.sig -inform DER

:: Verify
openssl dgst -sha256 -verify ec_p256_pub.pem ^
    -signature msg_ecdsa.sig message.txt

:: Verify 02
edit the msg_ecdsa.sig and input file then check again

```

---

## 4. X25519: Elliptic Curve Key Agreement

### 4.1. Key pair

```bat
:: Generate X25519 private key
openssl genpkey -algorithm X25519 -out x25519_A.pem

:: Extract public key
openssl pkey -in x25519_A.pem -pubout -out x25519_A_pub.pem
```

Repeat similarly for another party (B).

### 4.2. Shared secret derivation

```bat
:: On side A, given B's public key x25519_B_pub.pem:
openssl pkeyutl -derive -inkey x25519_A.pem ^
    -peerkey x25519_B_pub.pem -out shared_secret_A.bin

:: On side B, given A's public key x25519_A_pub.pem:
openssl pkeyutl -derive -inkey x25519_B.pem ^
    -peerkey x25519_A_pub.pem -out shared_secret_B.bin
```

Check secrets are equal:

```bat
fc /b shared_secret_A.bin shared_secret_B.bin
```

---

## 5. Ed25519: Modern Signatures

### 5.1. Key pair

```bat
openssl genpkey -algorithm ED25519 -out ed25519.pem
openssl pkey -in ed25519.pem -pubout -out ed25519_pub.pem
```

### 5.2. Sign & verify

```bat
openssl dgst -sha512 -sign ed25519.pem ^
    -out msg_ed25519.sig message.txt

openssl dgst -sha512 -verify ed25519_pub.pem ^
    -signature msg_ed25519.sig message.txt
```

---

## 6. PQC Signatures: ML-DSA

### 6.1. Key generation (ML-DSA-65)

```bat
:: Key generation
openssl genpkey -algorithm ML-DSA-65 -out mldsa65_priv.pem
openssl pkey -in mldsa65_priv.pem -pubout -out mldsa65_pub.pem

:: Inspect the ML-DSA public key
openssl pkey -in mldsa65_pub.pem -pubin -text -noout

:: Inspect the ML-DSA Private key
openssl pkey -in mldsa65_priv.pem -text -noout
```

### 6.2. Sign & verify

```bat
:: Sign with ML-DSA
openssl pkeyutl -sign -inkey mldsa65_priv.pem ^
    -in "Week11_Cryptography Applications P1.pptx" ^
    -out mldsa65.sig

:: Verify
openssl pkeyutl -verify ^
    -pubin -inkey mldsa65_pub.pem ^
    -in "Week11_Cryptography Applications P1.pptx" ^
    -sigfile mldsa65.sig

```

### 6.3. With context string (pkeyutl)

```bat
:: Sign
openssl pkeyutl -sign -inkey mldsa65_priv.pem ^
    -in message.txt -out mldsa65_ctx.sig ^
    -pkeyopt context-string:"example-context"

:: Verify
openssl pkeyutl -verify -inkey mldsa65_pub.pem -pubin ^
    -in message.txt -sigfile mldsa65_ctx.sig ^
    -pkeyopt context-string:"example-context"
```

---

## 7. PQC KEM: ML-KEM-768

### 7.1. Key pair

```bat
openssl genpkey -algorithm ML-KEM-768 -out mlkem768_priv.pem
openssl pkey -in mlkem768_priv.pem -pubout -out mlkem768_pub.pem
```

### 7.2. Encapsulation (Alice → Bob)

```bat
:: Alice, using Bob's public key
openssl pkeyutl -encap -inkey mlkem768_pub.pem -pubin ^
    -out mlkem768_ct.bin -secret mlkem768_shared_alice.bin
```

### 7.3. Decapsulation (Bob)

```bat
openssl pkeyutl -decap -inkey mlkem768_priv.pem ^
    -in mlkem768_ct.bin -secret mlkem768_shared_bob.bin
```

Verify equality:

```bat
fc /b mlkem768_shared_alice.bin mlkem768_shared_bob.bin
```

This is a post-quantum KEM-based key exchange suitable for deriving session keys.

---

## 8. Self-Signed PQC Certificate (ML-DSA)

### 8.1. Self-signed ML-DSA-65 certificate

```bat
openssl req -x509 -newkey MLDSA65 ^
    -keyout Vo_mldsa.key ^
    -out Vo_mldsa.crt ^
    -subj "/CN=Doan Thi Diem, 038078032299 /C=VN" ^
    -days 365 -nodes
```

### 8.2. Inspect certificate

```bat
openssl x509 -in Vo_mldsa.crt -text -noout
```

### 8.3. Local TLS server (if supported by your build)

```bat
openssl s_server -cert server_mldsa.crt -key server_mldsa.key -accept 8443
```

Client:

```bat
openssl s_client -connect 127.0.0.1:8443
```

---

## 9. HMAC (Message Authentication Code)

This section demonstrates **HMAC** as a symmetric integrity + authenticity mechanism.

### 9.1. List MAC algorithms

```bat
openssl list -mac-algorithms
```

Look for `HMAC`, `CMAC`, etc.

### 9.2. Generate a random HMAC key

```bat
:: 32 bytes (256 bits) in hex
openssl rand -hex 32 > hmac_key.hex
```

`hmac_key.hex` contains a hex-encoded key. For demos, you can also use a short ASCII secret (not secure, but easy for students).

### 9.3. HMAC with a simple ASCII key

```bat
:: WARNING: insecure key, for lab/demo ONLY
set HMAC_KEY=supersecretkey

:: Compute HMAC-SHA256
echo Message to protect> msg.txt

openssl dgst -sha256 -hmac "%HMAC_KEY%" msg.txt
```

This prints something like:

```text
HMAC-SHA256(msg.txt)= 1a2b3c...
```

### 9.4. HMAC using a binary key from file

1. Convert the hex key to binary:

```bat
:: From hex to binary
openssl rand -hex 32 > hmac_key.hex

:: Binary version
type hmac_key.hex | openssl enc -aes-128-ecb -nosalt -nopad > hmac_key.bin
```

(For pure teaching labs, you may skip binary conversion and keep hex/ASCII.)

2. Use `-mac` / `-macopt`:

```bat
:: Using the 'HMAC' MAC with a key
openssl mac -mac HMAC -digest SHA256 ^
    -macopt hexkey:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff ^
    msg.txt
```

On older versions where `openssl mac` is not available, `(dgst -hmac)` is simpler for students:

```bat
openssl dgst -sha256 -hmac "0011223344556677" msg.txt
```

### 9.5. Verify HMAC (simple pattern)

1. Sender computes and sends:

```bat
openssl dgst -sha256 -hmac "%HMAC_KEY%" msg.txt > msg.hmac
```

2. Receiver recomputes:

```bat
openssl dgst -sha256 -hmac "%HMAC_KEY%" msg.txt > msg.hmac.verify
```

3. Compare:

```bat
fc /b msg.hmac msg.hmac.verify
```

If equal, the message is authentic and unmodified (under the shared key assumption).

---

## 10. Session Tokens with HMAC

This section builds a simple **HMAC-based session token** (JWT-like, but handcrafted) to align with your application security lectures.

### 10.1. Token format

We use a simple `key=value` pipe-separated format:

```text
uid=1234|role=user|exp=2025-12-31T23:59:59Z
```

Call this the **payload**. The token will be:

```text
payload || "." || base64url(HMAC(payload))
```

### 10.2. Create a payload file

```bat
echo uid=1234^|role=user^|exp=2025-12-31T23:59:59Z> payload.txt
type payload.txt
```

Note: `^|` escapes the `|` in `cmd.exe`.

### 10.3. Choose an HMAC secret for session tokens

```bat
:: 32-byte random key for tokens (lab/demo)
openssl rand -hex 32 > token_hmac_key.hex
type token_hmac_key.hex
```

For demo, you can also fix an environment variable:

```bat
set TOKEN_KEY=this_is_demo_token_key
```

### 10.4. Compute the HMAC of the payload

```bat
openssl dgst -sha256 -hmac "%TOKEN_KEY%" payload.txt > payload.hmac
type payload.hmac
```

The output looks like:

```text
HMAC-SHA256(payload.txt)= abcd1234...
```

Extract just the hex (for scripting, you can parse it or manually copy it in lab).

### 10.5. Build a “token” string (manual, for teaching)

For a minimal classroom demo, you can simply define the token as:

```text
<payload>.<hex_hmac>
```

Example (pseudo):

```text
uid=1234|role=user|exp=2025-12-31T23:59:59Z.abcd1234...
```

In real systems you would:

1. Use **Base64URL** encoding for both payload and HMAC.
2. Use a strict canonical format (like JSON).
3. Protect against timing attacks when verifying.

### 10.6. Verify a token

Given:

- The received payload in `payload.txt`
- The received `hex_hmac` in a separate file `recv.hmac` (or a header)

1. Recompute:

```bat
openssl dgst -sha256 -hmac "%TOKEN_KEY%" payload.txt > recomputed.hmac
```

2. Compare `recv.hmac` vs `recomputed.hmac` (or the hex parts) with:

```bat
fc /b recv.hmac recomputed.hmac
```

If they match, the token is valid (integrity + authenticity). If not, someone changed either payload or MAC.

### 10.7. Sketch for HTTP-style header

For classroom discussion, you can show something like:

```text
Authorization: HMAC token="uid=1234|role=user|exp=2025-12-31T23:59:59Z.abcd1234..."
```

Then explain:

- Server extracts `payload` and `MAC` from the header.
- Server recomputes HMAC over `payload` with the shared secret.
- If matches, accept; if not, reject.

---

## 11. Suggested Lab Flow

1. **Algorithm Discovery**
   - `openssl list -public-key-algorithms`
   - `openssl list -tls-groups -tls1_3`
2. **Classical Signatures**
   - RSA-PSS, ECDSA, Ed25519.
3. **PQC Signatures + KEM**
   - ML-DSA, ML-KEM.
4. **X25519 Key Agreement**
   - Compare with ML-KEM shared secrets.
5. **HMAC**
   - HMAC-SHA256 over a message.
6. **Session Tokens**
   - Construct / verify a handcrafted HMAC-based token.
7. **(Optional) PQC Certificates and TLS**
   - Self-signed ML-DSA cert + `s_server` / `s_client` demo.

This Markdown file can be directly distributed to students for note-taking and copy-paste of commands.
