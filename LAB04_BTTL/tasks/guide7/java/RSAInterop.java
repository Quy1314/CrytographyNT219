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