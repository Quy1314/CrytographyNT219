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