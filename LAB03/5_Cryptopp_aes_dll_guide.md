# 🔐 Crypto++ AES DLL/SO Guide (Cross-Platform)

This guide walks through creating a **shared library (DLL or SO)** that exports AES key generation, encryption, and decryption functions using **Crypto++**, along with `tasks.json` build instructions for **G++**, **Clang++**, and **MSVC**.

---

## 📁 1. AES Exportable Functions in `aes_dll.cpp`

```cpp
#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cstring>

using namespace CryptoPP;

extern "C" {

// Exported: Generate AES key and IV (16 bytes each)
__declspec(dllexport) void GenerateAESKeyIV(byte* key, byte* iv) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(iv, AES::BLOCKSIZE);
}

// Exported: Encrypt plaintext to hex string
__declspec(dllexport) void AESEncrypt(const byte* key, const byte* iv, const char* plaintext, char* outHex, int outSize) {
    std::string ciphertext;
    CBC_Mode<AES>::Encryption encryptor(key, AES::DEFAULT_KEYLENGTH, iv);

    StringSource ss(plaintext, true,
        new StreamTransformationFilter(encryptor,
            new StringSink(ciphertext)
        )
    );

    std::string encoded;
    StringSource(ciphertext, true, new HexEncoder(new StringSink(encoded)));

    strncpy(outHex, encoded.c_str(), outSize - 1);
    outHex[outSize - 1] = '\0';
}

// Exported: Decrypt hex string to plaintext
__declspec(dllexport) void AESDecrypt(const byte* key, const byte* iv, const char* hexCipher, char* outPlain, int outSize) {
    std::string decoded, recovered;
    StringSource(hexCipher, true, new HexDecoder(new StringSink(decoded)));

    CBC_Mode<AES>::Decryption decryptor(key, AES::DEFAULT_KEYLENGTH, iv);
    StringSource ss(decoded, true,
        new StreamTransformationFilter(decryptor,
            new StringSink(recovered)
        )
    );

    strncpy(outPlain, recovered.c_str(), outSize - 1);
    outPlain[outSize - 1] = '\0';
}

} // extern "C"
```

---

## ⚙️ 2. tasks.json: Build to DLL/SO

### 🛠 G++ (MinGW / Linux)
```json
{
  "label": "Build AES DLL with g++",
  "type": "shell",
  "command": "g++",
  "args": [
    "-shared", // .so or .dll
    "-fPIC",
    "-o", "${fileDirname}/${fileBasenameNoExtension}.dll",
    "${file}",
    "-lcryptopp", "-static-libgcc", "-static-libstdc++"
  ]
}
```

---

### 🛠 Clang++ (Windows MSYS2)
```json
{
  "label": "Build AES DLL with Clang++",
  "type": "shell",
  "command": "clang++",
  "args": [
    "-shared", //for .so
    "-fPIC",
    "-o", "${fileDirname}/${fileBasenameNoExtension}.dll",
    "${file}",
    "-l:libcryptopp.a",
    "-LD:/cryptolibrary/libs/cryptopp/clang",
    "-ID:/cryptolibrary/include",
    "-lpthread"
  ]
}
```

---

### 🛠 MSVC (Developer Command Prompt)
```json
{
  "label": "Build AES DLL with MSVC",
  "type": "shell",
  "command": "cl.exe",
  "args": [
    "/LD", //for .lib
    "${file}",
    "/I", "D:\\cryptolibrary\\include",
    "D:\\cryptolibrary\\libs\\cryptopp\\msvc\\cryptlib.lib"
  ],
  "options": {
    "cwd": "${fileDirname}"
  }
}
```

---

## 🧪 3. Testing (Optional Console App)

You can write a simple test app in C++ or Python (via `ctypes`) to call:

```cpp
void GenerateAESKeyIV(byte* key, byte* iv);
void AESEncrypt(const byte* key, const byte* iv, const char* plaintext, char* outHex, int outSize);
void AESDecrypt(const byte* key, const byte* iv, const char* hexCipher, char* outPlain, int outSize);
```

---

## ✅ Summary

- 📦 Cross-platform DLL/SO AES library using Crypto++
- 📂 Compatible `tasks.json` for g++, clang++, MSVC
- 🛠 Exports AES: keygen, encrypt, decrypt
