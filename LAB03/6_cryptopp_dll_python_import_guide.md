# 🐍 Importing Crypto++ AES DLL into Python with `ctypes`

This guide explains how to compile a **Crypto++ AES keygen/export DLL** and use it in **Python** via `ctypes`.

---

## 🧱 Step 1: C++ DLL Code

Save this as `aes_key_dll.cpp` and compile with:

```bash
# G++ (MinGW)
g++ -shared -o aes_key.dll aes_key_dll.cpp -lcryptopp -static-libgcc -static-libstdc++

# Or Clang++
clang++ -shared -o aes_key.dll aes_key_dll.cpp -l:libcryptopp.a -lpthread
```

> Make sure to define functions using `extern "C"` and `__declspec(dllexport)`.

---

## 🧪 Example Exported Functions (from C++)

```cpp
extern "C" __declspec(dllexport) void GenerateAESKey(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv);
extern "C" __declspec(dllexport) void SaveKeyToFile(const std::string& filename, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv);
extern "C" __declspec(dllexport) void LoadKeyFromFile(const std::string& filename, CryptoPP::byte key[], CryptoPP::byte iv[]);
```

🛑 `SecByteBlock` and `std::string` are **not recommended** for DLL interfaces. Instead, expose plain `byte*` and `char*` buffers for easy interop.

---

## ✅ Recommended C-Compatible Export

Update your DLL interface like:

```cpp
extern "C" __declspec(dllexport) void GenerateAESKeyRaw(byte* key, byte* iv);
extern "C" __declspec(dllexport) void SaveKeyRaw(const char* filename, const byte* key, const byte* iv);
extern "C" __declspec(dllexport) void LoadKeyRaw(const char* filename, byte* key, byte* iv);
```

---

## 🐍 Step 2: Python Code Using `ctypes`

```python
import ctypes
from ctypes import c_char_p, c_ubyte, POINTER, byref, create_string_buffer

AES_KEY_LEN = 16
AES_BLOCK_SIZE = 16

# Load DLL
dll = ctypes.CDLL("./aes_key.dll", mode=3)

# Define functions
dll.GenerateAESKeyRaw.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
dll.SaveKeyRaw.argtypes = [c_char_p, POINTER(c_ubyte), POINTER(c_ubyte)]
dll.LoadKeyRaw.argtypes = [c_char_p, POINTER(c_ubyte), POINTER(c_ubyte)]

Examples
# GenerateAESKey: void GenerateAESKey(byte *key, byte *iv)
lib.GenerateAESKey.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
lib.GenerateAESKey.restype = None

# SaveKeyToFile: void SaveKeyToFile(const char *filename, const byte *key, const byte *iv)
lib.SaveKeyToFile.argtypes = [ctypes.c_char_p,
                              ctypes.POINTER(ctypes.c_ubyte),
                              ctypes.POINTER(ctypes.c_ubyte)]
lib.SaveKeyToFile.restype = None

# LoadKeyFromFile: void LoadKeyFromFile(const char *filename, const byte *key, const byte *iv)
lib.LoadKeyFromFile.argtypes = [ctypes.c_char_p,
                                ctypes.POINTER(ctypes.c_ubyte),
                                ctypes.POINTER(ctypes.c_ubyte)]
lib.LoadKeyFromFile.restype = None

# Allocate key and IV
key = (c_ubyte * AES_KEY_LEN)()
iv = (c_ubyte * AES_BLOCK_SIZE)()

# Generate and save key
dll.GenerateAESKeyRaw(key, iv)
dll.SaveKeyRaw(b"key.bin", key, iv)

# Load into new buffer
key2 = (c_ubyte * AES_KEY_LEN)()
iv2 = (c_ubyte * AES_BLOCK_SIZE)()
dll.LoadKeyRaw(b"key.bin", key2, iv2)

print("Key:", bytes(key2).hex().upper())
print("IV :", bytes(iv2).hex().upper())
```

---

## 📝 Notes

- You must rebuild your DLL using only **C-compatible types** for use with Python.
- Avoid exporting functions using `SecByteBlock`, `std::string`, or Crypto++ classes directly.
- Pass pointers, arrays, and C-style strings to ensure stability across language boundaries.
