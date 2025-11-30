# Guide 7: Cross-Language Integration with Python, C#, and Java
Task 7.1 importing RSA DLL into python
Task 7.2 importing RSA DLL into c#
Task 7.3 importing RSA DLL into java

## Introduction

This guide demonstrates how to use the RSA shared library created in Guide 6 from Python, C#, and Java. Cross-language integration allows you to leverage the performance and security of the C++ implementation while working in your preferred programming language.

## Prerequisites

- RSA shared library (DLL/SO) built according to Guide 6
- Python 3.6+ with ctypes module
- .NET Framework or .NET Core for C#
- Java Development Kit (JDK) 8+ with JNI knowledge

## Python Integration

Python provides the `ctypes` module, which makes it easy to call functions from shared libraries. Let's see how to use our RSA library from Python:

### Basic Setup

First, create a Python wrapper for the RSA library:

```python
# rsa_wrapper.py
import ctypes
import os
from enum import IntEnum
from typing import Tuple, Optional

# Load the shared library
if os.name == 'nt':  # Windows
    _lib = ctypes.CDLL('./rsa.dll')
else:  # Linux/macOS
    _lib = ctypes.CDLL('./librsa.so')

# Define enums
class RSAStatusCode(IntEnum):
    RSA_SUCCESS = 0
    RSA_ERROR_INVALID_PARAMETER = -1
    RSA_ERROR_MEMORY_ALLOCATION = -2
    RSA_ERROR_KEY_GENERATION = -3
    RSA_ERROR_KEY_VALIDATION = -4
    RSA_ERROR_ENCRYPTION = -5
    RSA_ERROR_DECRYPTION = -6
    RSA_ERROR_FILE_IO = -7
    RSA_ERROR_BUFFER_TOO_SMALL = -8
    RSA_ERROR_INVALID_FORMAT = -9
    RSA_ERROR_UNKNOWN = -99

class RSAPaddingScheme(IntEnum):
    RSA_PADDING_PKCS1 = 1
    RSA_PADDING_OAEP = 2

class RSAOutputFormat(IntEnum):
    RSA_FORMAT_BINARY = 1
    RSA_FORMAT_BASE64 = 2
    RSA_FORMAT_HEX = 3

# Define handle types
RSAPublicKeyHandle = ctypes.c_void_p
RSAPrivateKeyHandle = ctypes.c_void_p

# Set function prototypes
_lib.RSA_GenerateKeyPair.argtypes = [
    ctypes.c_uint,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int
]
_lib.RSA_GenerateKeyPair.restype = ctypes.c_int

_lib.RSA_LoadPublicKey.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(RSAPublicKeyHandle)
]
_lib.RSA_LoadPublicKey.restype = ctypes.c_int

_lib.RSA_LoadPrivateKey.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(RSAPrivateKeyHandle)
]
_lib.RSA_LoadPrivateKey.restype = ctypes.c_int

_lib.RSA_FreePublicKey.argtypes = [RSAPublicKeyHandle]
_lib.RSA_FreePublicKey.restype = None

_lib.RSA_FreePrivateKey.argtypes = [RSAPrivateKeyHandle]
_lib.RSA_FreePrivateKey.restype = None

_lib.RSA_Encrypt.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_Encrypt.restype = ctypes.c_int

_lib.RSA_Decrypt.argtypes = [
    RSAPrivateKeyHandle,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_Decrypt.restype = ctypes.c_int

_lib.RSA_EncryptFile.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_EncryptFile.restype = ctypes.c_int

_lib.RSA_DecryptFile.argtypes = [
    RSAPrivateKeyHandle,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_DecryptFile.restype = ctypes.c_int

_lib.RSA_GetErrorMessage.argtypes = [ctypes.c_int]
_lib.RSA_GetErrorMessage.restype = ctypes.c_char_p

_lib.RSA_GetMaxPlaintextLength.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_int
]
_lib.RSA_GetMaxPlaintextLength.restype = ctypes.c_size_t

# Define Python wrapper functions
def generate_key_pair(key_size: int, private_key_file: str, public_key_file: str, use_pem: bool = True) -> RSAStatusCode:
    """Generate an RSA key pair and save to files."""
    status = _lib.RSA_GenerateKeyPair(
        key_size,
        ctypes.c_char_p(private_key_file.encode('utf-8')),
        ctypes.c_char_p(public_key_file.encode('utf-8')),
        1 if use_pem else 0
    )
    return RSAStatusCode(status)

def load_public_key(filename: str) -> Tuple[RSAStatusCode, Optional[RSAPublicKeyHandle]]:
    """Load a public key from a file."""
    key_handle = RSAPublicKeyHandle()
    status = _lib.RSA_LoadPublicKey(
        ctypes.c_char_p(filename.encode('utf-8')),
        ctypes.byref(key_handle)
    )
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    return RSAStatusCode(status), key_handle

def load_private_key(filename: str) -> Tuple[RSAStatusCode, Optional[RSAPrivateKeyHandle]]:
    """Load a private key from a file."""
    key_handle = RSAPrivateKeyHandle()
    status = _lib.RSA_LoadPrivateKey(
        ctypes.c_char_p(filename.encode('utf-8')),
        ctypes.byref(key_handle)
    )
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    return RSAStatusCode(status), key_handle

def free_public_key(key_handle: RSAPublicKeyHandle) -> None:
    """Free a public key handle."""
    _lib.RSA_FreePublicKey(key_handle)

def free_private_key(key_handle: RSAPrivateKeyHandle) -> None:
    """Free a private key handle."""
    _lib.RSA_FreePrivateKey(key_handle)

def encrypt(public_key: RSAPublicKeyHandle, data: bytes, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, use_hybrid: bool = False) -> Tuple[RSAStatusCode, Optional[bytes]]:
    """Encrypt data using an RSA public key."""
    # First call to get required buffer size
    encrypted_length = ctypes.c_size_t(0)
    status = _lib.RSA_Encrypt(
        public_key,
        data,
        len(data),
        None,
        ctypes.byref(encrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL:
        return RSAStatusCode(status), None
    
    # Allocate buffer and call again
    encrypted_data = ctypes.create_string_buffer(encrypted_length.value)
    status = _lib.RSA_Encrypt(
        public_key,
        data,
        len(data),
        encrypted_data,
        ctypes.byref(encrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    
    return RSAStatusCode(status), bytes(encrypted_data[:encrypted_length.value])

def decrypt(private_key: RSAPrivateKeyHandle, encrypted_data: bytes, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, use_hybrid: bool = False) -> Tuple[RSAStatusCode, Optional[bytes]]:
    """Decrypt data using an RSA private key."""
    # First call to get required buffer size
    decrypted_length = ctypes.c_size_t(0)
    status = _lib.RSA_Decrypt(
        private_key,
        encrypted_data,
        len(encrypted_data),
        None,
        ctypes.byref(decrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL:
        return RSAStatusCode(status), None
    
    # Allocate buffer and call again
    decrypted_data = ctypes.create_string_buffer(decrypted_length.value)
    status = _lib.RSA_Decrypt(
        private_key,
        encrypted_data,
        len(encrypted_data),
        decrypted_data,
        ctypes.byref(decrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    
    return RSAStatusCode(status), bytes(decrypted_data[:decrypted_length.value])

def encrypt_file(public_key: RSAPublicKeyHandle, input_file: str, output_file: str, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, output_format: RSAOutputFormat = RSAOutputFormat.RSA_FORMAT_BINARY, use_hybrid: bool = False) -> RSAStatusCode:
    """Encrypt a file using an RSA public key."""
    status = _lib.RSA_EncryptFile(
        public_key,
        ctypes.c_char_p(input_file.encode('utf-8')),
        ctypes.c_char_p(output_file.encode('utf-8')),
        padding_scheme,
        output_format,
        1 if use_hybrid else 0
    )
    return RSAStatusCode(status)

def decrypt_file(private_key: RSAPrivateKeyHandle, input_file: str, output_file: str, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, input_format: RSAOutputFormat = RSAOutputFormat.RSA_FORMAT_BINARY, use_hybrid: bool = False) -> RSAStatusCode:
    """Decrypt a file using an RSA private key."""
    status = _lib.RSA_DecryptFile(
        private_key,
        ctypes.c_char_p(input_file.encode('utf-8')),
        ctypes.c_char_p(output_file.encode('utf-8')),
        padding_scheme,
        input_format,
        1 if use_hybrid else 0
    )
    return RSAStatusCode(status)

def get_error_message(status_code: RSAStatusCode) -> str:
    """Get the error message for a status code."""
    message = _lib.RSA_GetErrorMessage(status_code)
    return message.decode('utf-8')

def get_max_plaintext_length(public_key: RSAPublicKeyHandle, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP) -> int:
    """Get the maximum plaintext length that can be encrypted with the given key and padding scheme."""
    return _lib.RSA_GetMaxPlaintextLength(public_key, padding_scheme)
```

### Using the Python Wrapper

Now let's create a Python script that uses our wrapper:

```python
# rsa_example.py
import rsa_wrapper as rsa

def main():
    # Generate RSA keys
    print("Generating RSA keys...")
    status = rsa.generate_key_pair(3072, "private_key.pem", "public_key.pem", True)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Key generation failed: {rsa.get_error_message(status)}")
        return
    
    # Load the public key
    print("Loading public key...")
    status, public_key = rsa.load_public_key("public_key.pem")
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Failed to load public key: {rsa.get_error_message(status)}")
        return
    
    # Encrypt a message
    message = b"Hello from Python!"
    print(f"Encrypting message: {message.decode('utf-8')}")
    status, encrypted_data = rsa.encrypt(public_key, message)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Encryption failed: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        return
    
    # Load the private key
    print("Loading private key...")
    status, private_key = rsa.load_private_key("private_key.pem")
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Failed to load private key: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        return
    
    # Decrypt the message
    print("Decrypting message...")
    status, decrypted_data = rsa.decrypt(private_key, encrypted_data)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Decryption failed: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        rsa.free_private_key(private_key)
        return
    
    # Print the decrypted message
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")
    
    # File encryption example
    print("\nFile encryption example:")
    
    # Create a test file
    with open("plaintext.txt", "w") as f:
        f.write("This is a test file for RSA encryption.")
    
    # Encrypt the file
    print("Encrypting file...")
    status = rsa.encrypt_file(
        public_key, 
        "plaintext.txt", 
        "encrypted.bin", 
        rsa.RSAPaddingScheme.RSA_PADDING_OAEP, 
        rsa.RSAOutputFormat.RSA_FORMAT_BINARY, 
        True  # Use hybrid encryption for files
    )
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"File encryption failed: {rsa.get_error_message(status)}")
    else:
        print("File encrypted successfully.")
    
    # Decrypt the file
    print("Decrypting file...")
    status = rsa.decrypt_file(
        private_key, 
        "encrypted.bin", 
        "decrypted.txt", 
        rsa.RSAPaddingScheme.RSA_PADDING_OAEP, 
        rsa.RSAOutputFormat.RSA_FORMAT_BINARY, 
        True  # Use hybrid decryption for files
    )
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"File decryption failed: {rsa.get_error_message(status)}")
    else:
        print("File decrypted successfully.")
        with open("decrypted.txt", "r") as f:
            print(f"Decrypted file content: {f.read()}")
    
    # Clean up
    rsa.free_public_key(public_key)
    rsa.free_private_key(private_key)
    print("Done.")

if __name__ == "__main__":
    main()
```

### Running the Python Example

To run the Python example:

```bash
# Make sure the shared library is in the same directory or in the system's library path
python rsa_example.py
```

## C# Integration

C# provides P/Invoke (Platform Invoke) to call functions from native libraries. Let's see how to use our RSA library from C#:

### Basic Setup
- rsa_lib.dll 
- dll dependencies if needed

```csharp
// Program.cs
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;


class Program
{
    // ENUMs
    public enum RSAStatusCode
    {
        RSA_SUCCESS = 0,
        RSA_ERROR_INVALID_PARAMETER = -1,
        RSA_ERROR_MEMORY_ALLOCATION = -2,
        RSA_ERROR_KEY_GENERATION = -3,
        RSA_ERROR_KEY_VALIDATION = -4,
        RSA_ERROR_ENCRYPTION = -5,
        RSA_ERROR_DECRYPTION = -6,
        RSA_ERROR_FILE_IO = -7,
        RSA_ERROR_BUFFER_TOO_SMALL = -8,
        RSA_ERROR_INVALID_FORMAT = -9,
        RSA_ERROR_UNKNOWN = -99
    }

    public enum RSAPaddingScheme
    {
        RSA_PADDING_PKCS1 = 1,
        RSA_PADDING_OAEP = 2
    }

    // HANDLE TYPES
    public struct RSAPublicKeyHandle
    {
        public IntPtr Handle;
    }

    public struct RSAPrivateKeyHandle
    {
        public IntPtr Handle;
    }

    // IMPORT DLL FUNCTIONS
    const string DllName = "rsa_lib.dll";

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern RSAStatusCode RSA_GenerateKeyPair(
        uint keySize,
        [MarshalAs(UnmanagedType.LPStr)] string privateKeyFile,
        [MarshalAs(UnmanagedType.LPStr)] string publicKeyFile,
        int usePEM
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern RSAStatusCode RSA_LoadPublicKey(
        [MarshalAs(UnmanagedType.LPStr)] string filename,
        out IntPtr keyHandle
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern RSAStatusCode RSA_LoadPrivateKey(
        [MarshalAs(UnmanagedType.LPStr)] string filename,
        out IntPtr keyHandle
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void RSA_FreePublicKey(IntPtr keyHandle);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern void RSA_FreePrivateKey(IntPtr keyHandle);

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern RSAStatusCode RSA_Encrypt(
        IntPtr publicKey,
        byte[] data,
        UIntPtr dataLength,
        byte[] encryptedData,
        ref UIntPtr encryptedDataLength,
        RSAPaddingScheme paddingScheme,
        int useHybrid
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern RSAStatusCode RSA_Decrypt(
        IntPtr privateKey,
        byte[] encryptedData,
        UIntPtr encryptedDataLength,
        byte[] decryptedData,
        ref UIntPtr decryptedDataLength,
        RSAPaddingScheme paddingScheme,
        int useHybrid
    );

    [DllImport(DllName, CallingConvention = CallingConvention.Cdecl)]
    private static extern IntPtr RSA_GetErrorMessage(RSAStatusCode code);

    // UTIL
    static string GetErrorMessage(RSAStatusCode code)
    {
        IntPtr ptr = RSA_GetErrorMessage(code);
        return Marshal.PtrToStringAnsi(ptr);
    }

    // MAIN TEST
    static void Main()
    {
        Console.WriteLine("Generating RSA keys...");
        RSAStatusCode status = RSA_GenerateKeyPair(3072, "private_key.pem", "public_key.pem", 1);
        if (status != RSAStatusCode.RSA_SUCCESS)
        {
            Console.WriteLine($"Key generation failed: {GetErrorMessage(status)}");
            return;
        }

        Console.WriteLine("Loading public key...");
        status = RSA_LoadPublicKey("public_key.pem", out IntPtr pubHandle);
        if (status != RSAStatusCode.RSA_SUCCESS)
        {
            Console.WriteLine($"Load public key failed: {GetErrorMessage(status)}");
            return;
        }

        string message = "Hello from C#";
        byte[] data = Encoding.UTF8.GetBytes(message);
        Console.WriteLine($"Encrypting message: {message}");

        // --- Encrypt (2-pass logic) ---
        UIntPtr encLen = UIntPtr.Zero;
        status = RSA_Encrypt(pubHandle, data, (UIntPtr)data.Length, null, ref encLen, RSAPaddingScheme.RSA_PADDING_OAEP, 0);
        if (status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL)
        {
            Console.WriteLine($"Unexpected status on first call: {status}");
            RSA_FreePublicKey(pubHandle);
            return;
        }

        byte[] encBuf = new byte[(ulong)encLen];
        status = RSA_Encrypt(pubHandle, data, (UIntPtr)data.Length, encBuf, ref encLen, RSAPaddingScheme.RSA_PADDING_OAEP, 0);
        if (status != RSAStatusCode.RSA_SUCCESS)
        {
            Console.WriteLine($"Encryption failed: {GetErrorMessage(status)}");
            RSA_FreePublicKey(pubHandle);
            return;
        }

        Console.WriteLine($"Ciphertext length: {(ulong)encLen} bytes");

        // --- Load private key ---
        Console.WriteLine("Loading private key...");
        status = RSA_LoadPrivateKey("private_key.pem", out IntPtr privHandle);
        if (status != RSAStatusCode.RSA_SUCCESS)
        {
            Console.WriteLine($"Load private key failed: {GetErrorMessage(status)}");
            RSA_FreePublicKey(pubHandle);
            return;
        }

        // --- Decrypt (2-pass logic) ---
        UIntPtr decLen = UIntPtr.Zero;
        status = RSA_Decrypt(privHandle, encBuf, encLen, null, ref decLen, RSAPaddingScheme.RSA_PADDING_OAEP, 0);
        if (status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL)
        {
            Console.WriteLine($"Unexpected status on decrypt first call: {status}");
            RSA_FreePublicKey(pubHandle);
            RSA_FreePrivateKey(privHandle);
            return;
        }

        byte[] decBuf = new byte[(ulong)decLen];
        status = RSA_Decrypt(privHandle, encBuf, encLen, decBuf, ref decLen, RSAPaddingScheme.RSA_PADDING_OAEP, 0);
        if (status != RSAStatusCode.RSA_SUCCESS)
        {
            Console.WriteLine($"Decryption failed: {GetErrorMessage(status)}");
        }
        else
        {
            string recovered = Encoding.UTF8.GetString(decBuf, 0, (int)decLen);
            Console.WriteLine($"Decrypted message: {recovered}");
        }

        // --- Cleanup ---
        RSA_FreePublicKey(pubHandle);
        RSA_FreePrivateKey(privHandle);
        Console.WriteLine("Done.");
    }
}
```

### Running the CSharp Example
Make sure the shared library is in the same directory with your execution file .exe

## Java Integration
Integrate the C++ RSA library (`rsa_lib.cpp`) with Java using JNI, build a shared DLL, and test encryption/decryption directly from Java.

### Prerequisites
**Required files:**
- `rsa_lib.cpp`, `rsa_lib.h`
- `RSAInteropJNI.cpp` 
- `RSAInterop.java`

### Generate JNI Header
Write `RSAInterop.java` to declare native methods for all exported RSA API functions
```java
public class RSAInterop {

    static {
        System.loadLibrary("RSAInteropJNI"); // nạp DLL
    }

    // ==== 1. Key management ====
    public native int RSA_GenerateKeyPair(int keySize, String privateKeyFile, String publicKeyFile, int usePEM);
    public native int RSA_LoadPublicKey(String filename, long[] keyHandle);
    public native int RSA_LoadPrivateKey(String filename, long[] keyHandle);
    public native void RSA_FreePublicKey(long keyHandle);
    public native void RSA_FreePrivateKey(long keyHandle);

    // ==== 2. Encryption / Decryption ====
    public native int RSA_Encrypt(long publicKeyHandle,
                                  byte[] data,
                                  long dataLen,
                                  byte[] encryptedData,
                                  long[] encryptedDataLength,
                                  int paddingScheme,
                                  int useHybrid);

    public native int RSA_Decrypt(long privateKeyHandle,
                                  byte[] encryptedData,
                                  long encryptedDataLength,
                                  byte[] decryptedData,
                                  long[] decryptedDataLength,
                                  int paddingScheme,
                                  int useHybrid);

    // ==== 3. File-based ====
    public native int RSA_EncryptFile(long publicKeyHandle,
                                      String inputFile,
                                      String outputFile,
                                      int paddingScheme,
                                      int outputFormat,
                                      int useHybrid);

    public native int RSA_DecryptFile(long privateKeyHandle,
                                      String inputFile,
                                      String outputFile,
                                      int paddingScheme,
                                      int outputFormat,
                                      int useHybrid);

    // ==== 4. Error handling & utility ====
    public native String RSA_GetErrorMessage(int code);
    public native long RSA_GetMaxPlaintextLength(long publicKeyHandle, int paddingScheme);


    // ==== 5. Test harness ====
    public static void main(String[] args) {
        RSAInterop rsa = new RSAInterop();

        System.out.println("Generating RSA keys...");
        int status = rsa.RSA_GenerateKeyPair(2048, "private_key.pem", "public_key.pem", 1);
        if (status != 0) {
            System.out.println("Key generation failed: " + rsa.RSA_GetErrorMessage(status));
            return;
        }

        long[] pubHandle = new long[1];
        long[] privHandle = new long[1];
        rsa.RSA_LoadPublicKey("public_key.pem", pubHandle);
        rsa.RSA_LoadPrivateKey("private_key.pem", privHandle);

        String msg = "Hello from Java JNI RSA!";
        byte[] data = msg.getBytes();

        long[] encLen = new long[1];
        rsa.RSA_Encrypt(pubHandle[0], data, data.length, null, encLen, 2, 0);
        byte[] enc = new byte[(int) encLen[0]];
        rsa.RSA_Encrypt(pubHandle[0], data, data.length, enc, encLen, 2, 0);
        System.out.println("Encrypted length: " + encLen[0]);

        long[] decLen = new long[1];
        rsa.RSA_Decrypt(privHandle[0], enc, encLen[0], null, decLen, 2, 0);
        byte[] dec = new byte[(int) decLen[0]];
        rsa.RSA_Decrypt(privHandle[0], enc, encLen[0], dec, decLen, 2, 0);

        String recovered = new String(dec, 0, (int) decLen[0]);
        System.out.println("Decrypted message: " + recovered);

        rsa.RSA_FreePublicKey(pubHandle[0]);
        rsa.RSA_FreePrivateKey(privHandle[0]);
    }
}
```

From the folder containing `RSAInterop.java`:
```sh
javac RSAInterop.java
javac -h . RSAInterop.java
```

### Implement the JNI Wrapper in C++
Create `RSAInteropJNI.cpp`:

```cpp
#include "RSAInterop.h"
#include "rsa_lib.h"
#include <jni.h>
#include <cstring>

extern "C" {

// ===== 1. GenerateKeyPair =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1GenerateKeyPair
  (JNIEnv* env, jobject, jint keySize, jstring privFile, jstring pubFile, jint usePEM)
{
    const char* priv = env->GetStringUTFChars(privFile, nullptr);
    const char* pub  = env->GetStringUTFChars(pubFile, nullptr);
    RSAStatusCode result = RSA_GenerateKeyPair((unsigned)keySize, priv, pub, usePEM);
    env->ReleaseStringUTFChars(privFile, priv);
    env->ReleaseStringUTFChars(pubFile, pub);
    return result;
}

// ===== 2. LoadPublicKey =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1LoadPublicKey
  (JNIEnv* env, jobject, jstring filename, jlongArray handleArr)
{
    const char* fname = env->GetStringUTFChars(filename, nullptr);
    RSAPublicKeyHandle key = nullptr;
    RSAStatusCode st = RSA_LoadPublicKey(fname, &key);
    env->ReleaseStringUTFChars(filename, fname);
    if (st == RSA_SUCCESS) {
        jlong ptr = reinterpret_cast<jlong>(key);
        env->SetLongArrayRegion(handleArr, 0, 1, &ptr);
    }
    return st;
}

// ===== 3. LoadPrivateKey =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1LoadPrivateKey
  (JNIEnv* env, jobject, jstring filename, jlongArray handleArr)
{
    const char* fname = env->GetStringUTFChars(filename, nullptr);
    RSAPrivateKeyHandle key = nullptr;
    RSAStatusCode st = RSA_LoadPrivateKey(fname, &key);
    env->ReleaseStringUTFChars(filename, fname);
    if (st == RSA_SUCCESS) {
        jlong ptr = reinterpret_cast<jlong>(key);
        env->SetLongArrayRegion(handleArr, 0, 1, &ptr);
    }
    return st;
}

// ===== 4. FreePublicKey =====
JNIEXPORT void JNICALL Java_RSAInterop_RSA_1FreePublicKey
  (JNIEnv*, jobject, jlong handle)
{
    RSA_FreePublicKey((RSAPublicKeyHandle)handle);
}

// ===== 5. FreePrivateKey =====
JNIEXPORT void JNICALL Java_RSAInterop_RSA_1FreePrivateKey
  (JNIEnv*, jobject, jlong handle)
{
    RSA_FreePrivateKey((RSAPrivateKeyHandle)handle);
}

// ===== 6. Encrypt =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1Encrypt
  (JNIEnv* env, jobject, jlong handle, jbyteArray data, jlong dataLen,
   jbyteArray outBuf, jlongArray outLenArr, jint pad, jint useHybrid)
{
    jbyte* in = env->GetByteArrayElements(data, nullptr);
    size_t inLen = (size_t)dataLen;
    size_t outLen = 0;
    unsigned char* out = nullptr;

    if (outBuf) {
        outLen = env->GetArrayLength(outBuf);
        out = (unsigned char*)env->GetByteArrayElements(outBuf, nullptr);
    }

    RSAStatusCode st = RSA_Encrypt((RSAPublicKeyHandle)handle,
                                   (unsigned char*)in, inLen,
                                   out, &outLen, (RSAPaddingScheme)pad, useHybrid);

    if (st == RSA_ERROR_BUFFER_TOO_SMALL || st == RSA_SUCCESS) {
        jlong len64 = (jlong)outLen;
        env->SetLongArrayRegion(outLenArr, 0, 1, &len64);
    }

    if (outBuf && out)
        env->ReleaseByteArrayElements(outBuf, (jbyte*)out, 0);
    env->ReleaseByteArrayElements(data, in, 0);
    return st;
}

// ===== 7. Decrypt =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1Decrypt
  (JNIEnv* env, jobject, jlong handle, jbyteArray inBuf, jlong inLen,
   jbyteArray outBuf, jlongArray outLenArr, jint pad, jint useHybrid)
{
    jbyte* enc = env->GetByteArrayElements(inBuf, nullptr);
    size_t encLen = (size_t)inLen;
    size_t outLen = 0;
    unsigned char* out = nullptr;

    if (outBuf) {
        outLen = env->GetArrayLength(outBuf);
        out = (unsigned char*)env->GetByteArrayElements(outBuf, nullptr);
    }

    RSAStatusCode st = RSA_Decrypt((RSAPrivateKeyHandle)handle,
                                   (unsigned char*)enc, encLen,
                                   out, &outLen, (RSAPaddingScheme)pad, useHybrid);

    if (st == RSA_ERROR_BUFFER_TOO_SMALL || st == RSA_SUCCESS) {
        jlong len64 = (jlong)outLen;
        env->SetLongArrayRegion(outLenArr, 0, 1, &len64);
    }

    if (outBuf && out)
        env->ReleaseByteArrayElements(outBuf, (jbyte*)out, 0);
    env->ReleaseByteArrayElements(inBuf, enc, 0);
    return st;
}

// ===== 8. EncryptFile =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1EncryptFile
  (JNIEnv* env, jobject, jlong pubHandle, jstring inFile, jstring outFile,
   jint pad, jint fmt, jint useHybrid)
{
    const char* in = env->GetStringUTFChars(inFile, nullptr);
    const char* out = env->GetStringUTFChars(outFile, nullptr);
    RSAStatusCode st = RSA_EncryptFile((RSAPublicKeyHandle)pubHandle, in, out,
                                       (RSAPaddingScheme)pad, (RSAOutputFormat)fmt, useHybrid);
    env->ReleaseStringUTFChars(inFile, in);
    env->ReleaseStringUTFChars(outFile, out);
    return st;
}

// ===== 9. DecryptFile =====
JNIEXPORT jint JNICALL Java_RSAInterop_RSA_1DecryptFile
  (JNIEnv* env, jobject, jlong privHandle, jstring inFile, jstring outFile,
   jint pad, jint fmt, jint useHybrid)
{
    const char* in = env->GetStringUTFChars(inFile, nullptr);
    const char* out = env->GetStringUTFChars(outFile, nullptr);
    RSAStatusCode st = RSA_DecryptFile((RSAPrivateKeyHandle)privHandle, in, out,
                                       (RSAPaddingScheme)pad, (RSAOutputFormat)fmt, useHybrid);
    env->ReleaseStringUTFChars(inFile, in);
    env->ReleaseStringUTFChars(outFile, out);
    return st;
}

// ===== 10. GetErrorMessage =====
JNIEXPORT jstring JNICALL Java_RSAInterop_RSA_1GetErrorMessage
  (JNIEnv* env, jobject, jint code)
{
    const char* msg = RSA_GetErrorMessage((RSAStatusCode)code);
    return env->NewStringUTF(msg);
}

// ===== 11. GetMaxPlaintextLength =====
JNIEXPORT jlong JNICALL Java_RSAInterop_RSA_1GetMaxPlaintextLength
  (JNIEnv*, jobject, jlong pubHandle, jint pad)
{
    size_t len = RSA_GetMaxPlaintextLength((RSAPublicKeyHandle)pubHandle, (RSAPaddingScheme)pad);
    return (jlong)len;
}

} // extern "C"
```

### Compile the JNI DLL
Open msys2 and compile RSAInteropJNI.cpp together with the RSA library source and link with Crypto++.
```sh
g++ -DRSA_LIB_EXPORTS -I"C:\Program Files\Java\jdk-21\include" -I"C:\Program Files\Java\jdk-21\include\win32" -I"C:\Documentss\Cryptography\LAB04_BTTL\tasks\include" -shared -o RSAInteropJNI.dll RSAInteropJNI.cpp rsa_lib.cpp -L"C:\Documentss\Cryptography\LAB04_BTTL\tasks\lib\cryptopp\gcc" -lcryptopp

"C:\Documentss\Cryptography\LAB04_BTTL\tasks\include"
```

Both the JNI layer and RSA code are built into one DLL (RSAInteropJNI.dll)

### Run Your Java Application
```sh
java -Djava.library.path=. RSAInterop
```


