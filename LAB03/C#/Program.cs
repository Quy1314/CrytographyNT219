using System;
using System.IO;
using System.Runtime.InteropServices;

class AESLibrary
{
    public const int AES_KEY_SIZE = 16;
    public const int AES_IV_SIZE = 16;

    // ===== DLL IMPORTS =====
    [DllImport("AESLibrary.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void GenerateAESKey(byte[] key, byte[] iv);

    [DllImport("AESLibrary.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int SaveKeyToFile(string filename, byte[] key, byte[] iv);

    [DllImport("AESLibrary.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int LoadKeyFromFile(string filename, byte[] key, byte[] iv);

    [DllImport("AESLibrary.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int AESEncryptFile(byte[] key, byte[] iv, string inFile, string outFile);

    [DllImport("AESLibrary.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int AESDecryptFile(byte[] key, byte[] iv, string inFile, string outFile);
}

class Program
{
    static void Main()
    {
        byte[] key = new byte[AESLibrary.AES_KEY_SIZE];
        byte[] iv = new byte[AESLibrary.AES_IV_SIZE];

        // Sinh và lưu key
        AESLibrary.GenerateAESKey(key, iv);
        Console.WriteLine("Generated Key: " + BitConverter.ToString(key).Replace("-", ""));
        Console.WriteLine("Generated IV : " + BitConverter.ToString(iv).Replace("-", ""));

        string keyfile = "key.bin";
        AESLibrary.SaveKeyToFile(keyfile, key, iv);

        // Đọc lại key
        byte[] key2 = new byte[AESLibrary.AES_KEY_SIZE];
        byte[] iv2 = new byte[AESLibrary.AES_IV_SIZE];
        AESLibrary.LoadKeyFromFile(keyfile, key2, iv2);

        // File đầu vào và đầu ra
        string inputFile = "plaintext.txt";
        string encFile = "encrypted.bin";
        string decFile = "decrypted.txt";

        // Mã hóa
        AESLibrary.AESEncryptFile(key2, iv2, inputFile, encFile);

        // Hiển thị ciphertext dạng HEX
        if (File.Exists(encFile))
        {
            byte[] cipher = File.ReadAllBytes(encFile);
            Console.WriteLine("Ciphertext (HEX): " + BitConverter.ToString(cipher).Replace("-", ""));
        }

        // Giải mã
        AESLibrary.AESDecryptFile(key2, iv2, encFile, decFile);

        // In nội dung plaintext
        if (File.Exists(decFile))
        {
            string plain = File.ReadAllText(decFile);
            Console.WriteLine("Decrypted Text: " + plain);
        }
    }
}
