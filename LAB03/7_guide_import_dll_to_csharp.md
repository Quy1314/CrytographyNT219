# 📦 How to Import DLL/SO in C# using P/Invoke

This guide shows how to import and use a native DLL (or `.so` on Linux) in **C#** using `DllImport`.

---

## ✅ 1. C++ DLL (Native Library)

### Sample Exported C++ Code (for AES key handling)

```cpp
// AESLibrary.cpp

#include <cryptopp/aes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>

using namespace CryptoPP;

extern "C" __declspec(dllexport) void __cdecl GenerateAESKey(unsigned char* key, unsigned char* iv) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(iv, AES::BLOCKSIZE);
}

extern "C" __declspec(dllexport) void __cdecl SaveKeyToFile(const char* filename, const unsigned char* key, const unsigned char* iv) {
    FileSink fs(filename, true);
    fs.Put(key, AES::DEFAULT_KEYLENGTH);
    fs.Put(iv, AES::BLOCKSIZE);
    fs.MessageEnd();
}

extern "C" __declspec(dllexport) void __cdecl LoadKeyFromFile(const char* filename, unsigned char* key, unsigned char* iv) {
    FileSource file(filename, false);
    file.Attach(new ArraySink(key, AES::DEFAULT_KEYLENGTH));
    file.Pump(AES::DEFAULT_KEYLENGTH);
    file.Attach(new ArraySink(iv, AES::BLOCKSIZE));
    file.Pump(AES::BLOCKSIZE);
}
```

Compile this to `GenKeyAES.dll` (Windows) or `libGenKeyAES.so` (Linux).

---

## ✅ 2. C# Interop Code

### Sample C# Program

```csharp
using System;
using System.Runtime.InteropServices;

class AESInterop
{
    const int AES_KEY_SIZE = 16;
    const int AES_IV_SIZE = 16;

    [DllImport("GenKeyAES.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode, EntryPoint = "GenerateAESKey")]
    public static extern void GenerateAESKey(byte[] key, byte[] iv);

    [DllImport("GenKeyAES.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void SaveKeyToFile(string filename, byte[] key, byte[] iv);

    [DllImport("GenKeyAES.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void LoadKeyFromFile(string filename, byte[] key, byte[] iv);

    static void Main()
    {
        byte[] key = new byte[AES_KEY_SIZE];
        byte[] iv = new byte[AES_IV_SIZE];

        GenerateAESKey(key, iv);
        Console.WriteLine("Generated Key: " + BitConverter.ToString(key).Replace("-", ""));
        Console.WriteLine("Generated IV : " + BitConverter.ToString(iv).Replace("-", ""));

        SaveKeyToFile("keyfile.bin", key, iv);

        byte[] loadedKey = new byte[AES_KEY_SIZE];
        byte[] loadedIV = new byte[AES_IV_SIZE];

        LoadKeyFromFile("keyfile.bin", loadedKey, loadedIV);
        Console.WriteLine("Loaded Key   : " + BitConverter.ToString(loadedKey).Replace("-", ""));
        Console.WriteLine("Loaded IV    : " + BitConverter.ToString(loadedIV).Replace("-", ""));
    }
}
```

---

## ✅ 3. Important Notes

- On **Windows**: Make sure `GenKeyAES.dll` and its dependencies (e.g., `cryptlib.dll`) are in the same folder or in your `PATH`.
- On **Linux**: Use `.so` file, and you may need to use `LD_LIBRARY_PATH` or copy to `/usr/lib`.
- If functions are not found: check exports with `dumpbin /exports GenKeyAES.dll` or `nm -D libGenKeyAES.so`

---

## 🛠️ Tools and Commands

### For Windows MSVC Build:
```sh
cl /LD AESLibrary.cpp /link /OUT:GenKeyAES.dll
```

### For GCC/MinGW:
```sh
g++ -shared -o GenKeyAES.dll AESLibrary.cpp -lcryptopp
```

### For Linux:
```sh
g++ -fPIC -shared -o libGenKeyAES.so AESLibrary.cpp -lcryptopp
```

---

