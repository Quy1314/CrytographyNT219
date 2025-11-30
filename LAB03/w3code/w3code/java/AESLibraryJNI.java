public class AESLibraryJNI {
    static {
        System.loadLibrary("AESLibraryJNI"); 

    }

    // native methods
    public native void GenerateAESKey(byte[] key, byte[] iv);
    public native int SaveKeyToFile(String filename, byte[] key, byte[] iv);
    public native int LoadKeyFromFile(String filename, byte[] key, byte[] iv);
    public native int AESEncryptFile(byte[] key, byte[] iv, String inFile, String outFile);
    public native int AESDecryptFile(byte[] key, byte[] iv, String inFile, String outFile);

    // test main
    public static void main(String[] args) {
        AESLibraryJNI aes = new AESLibraryJNI();
        byte[] key = new byte[16];
        byte[] iv  = new byte[16];

        aes.GenerateAESKey(key, iv);
        System.out.println("Key: " + bytesToHex(key));
        System.out.println("IV : " + bytesToHex(iv));

        aes.SaveKeyToFile("key.bin", key, iv);
        aes.LoadKeyFromFile("key.bin", key, iv);

        aes.AESEncryptFile(key, iv, "plaintext.txt", "cipher.bin");
        aes.AESDecryptFile(key, iv, "cipher.bin", "decrypted.txt");
        System.out.println("Done");
    }

    private static String bytesToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) sb.append(String.format("%02X", b));
        return sb.toString();
    }
}
