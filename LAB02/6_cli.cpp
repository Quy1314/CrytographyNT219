#include <iostream>
#include <fstream>
#include <string>
#include <cryptlib.h>
#include <hex.h>
#include <base64.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <files.h>

using namespace CryptoPP;

std::string HexToBytes(const std::string& hex) {
    std::string bytes;
    StringSource(hex, true,
        new HexDecoder(new StringSink(bytes))
    );
    return bytes;
}

std::string BytesToHex(const std::string& bytes) {
    std::string hex;
    StringSource(bytes, true,
        new HexEncoder(new StringSink(hex), false)
    );
    return hex;
}

std::string BytesToBase64(const std::string& bytes) {
    std::string b64;
    StringSource(bytes, true,
        new Base64Encoder(new StringSink(b64), false)
    );
    return b64;
}

std::string Base64ToBytes(const std::string& b64) {
    std::string bytes;
    StringSource(b64, true,
        new Base64Decoder(new StringSink(bytes))
    );
    return bytes;
}

void WriteToFile(const std::string& filename, const std::string& data) {
    try {
        StringSource(data, true,
            new FileSink(filename.c_str())  // ghi dữ liệu ra file
        );
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "File write error: " << e.what() << std::endl;
        throw;
    }
}

std::string AESEncrypt(const std::string& plaintext,
                       const CryptoPP::byte key[], const CryptoPP::byte iv[]) {
    std::string ciphertext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
    CryptoPP::StringSource(plaintext, true,
        new CryptoPP::StreamTransformationFilter(enc,
            new CryptoPP::StringSink(ciphertext),
            CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING)
    );
    return ciphertext;
}

std::string AESDecrypt(const std::string& ciphertext,
                       const CryptoPP::byte key[], const CryptoPP::byte iv[]) {
    std::string plaintext;
    CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv);
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::StreamTransformationFilter(dec,
            new CryptoPP::StringSink(plaintext),
            CryptoPP::BlockPaddingSchemeDef::PKCS_PADDING)
    );
    return plaintext;
}

void PrintHelp() {
    std::cout <<
        "Usage: aes_cli [options]\n"
        "Options:\n"
        "  --help                     Show this help message\n"
        "  --in <text>                Input text (plaintext for encrypt, encoded text for decrypt)\n"
        "  --out <file>               Output file (optional)\n"
        "  --key <hex>                AES key in hex (16 bytes = 32 hex chars)\n"
        "  --iv <hex>                 AES IV in hex (16 bytes = 32 hex chars)\n"
        "  --encrypt                  Encrypt the input\n"
        "  --decrypt                  Decrypt the input\n"
        "  --encode <type>            Output/input encoding: hex | base64 | raw (default: hex)\n"
        "  --verbose                  Show detailed info during process\n\n"
        "Examples:\n"
        "  Encrypt (Base64 output):\n"
        "    6_cli.exe --encrypt --in \"HELLO\" \\\n"
        "      --key 00112233445566778899AABBCCDDEEFF \n"
        "      --iv 0102030405060708090A0B0C0D0E0F10 \n"
        "      --encode base64 --verbose\n\n"
        "  Decrypt (from hex input):\n"
        "    6_cli.exe --decrypt --in \"AABBCCDDEE...\" \n"
        "      --key 00112233445566778899AABBCCDDEEFF \n"
        "      --iv 0102030405060708090A0B0C0D0E0F10 \n"
        "      --encode hex\n";
}

int main(int argc, char* argv[]) {
    std::string inputText, keyHex, ivHex, outputFile, encode = "hex";
    bool encrypt = false, decrypt = false, verbose = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") { PrintHelp(); return 0; }
        else if (arg == "--in" && i + 1 < argc) inputText = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--key" && i + 1 < argc) keyHex = argv[++i];
        else if (arg == "--iv" && i + 1 < argc) ivHex = argv[++i];
        else if (arg == "--encode" && i + 1 < argc) encode = argv[++i];
        else if (arg == "--encrypt") encrypt = true;
        else if (arg == "--decrypt") decrypt = true;
        else if (arg == "--verbose") verbose = true;
    }

    if (!encrypt && !decrypt) {
        std::cerr << "Error: must specify --encrypt or --decrypt\n";
        PrintHelp();
        return 1;
    }
    if (keyHex.empty() || ivHex.empty()) {
        std::cerr << "Error: missing key or iv\n";
        return 1;
    }

    std::string keyBytes = HexToBytes(keyHex);
    std::string ivBytes  = HexToBytes(ivHex);

    if (keyBytes.size() != CryptoPP::AES::DEFAULT_KEYLENGTH ||
        ivBytes.size() != CryptoPP::AES::BLOCKSIZE) {
        std::cerr << "Error: invalid key/IV length (16 bytes expected)\n";
        return 1;
    }

    std::string result;

    try {
        if (encrypt) {
            if (verbose) {
                std::cout << "[+] Encrypt mode\n"
                          << "[+] Input text: " << inputText << "\n"
                          << "[+] Key: " << keyHex << "\n"
                          << "[+] IV:  " << ivHex << "\n";
            }

            result = AESEncrypt(inputText,
                reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()),
                reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()));

            if (encode == "base64") result = BytesToBase64(result);
            else if (encode == "hex") result = BytesToHex(result);
            else if (encode != "raw") throw std::runtime_error("Invalid encode type");

            if (verbose) std::cout << "[+] Ciphertext (" << encode << "): " << result << "\n";
        }
        else {
            if (verbose) {
                std::cout << "[+] Decrypt mode\n"
                          << "[+] Input (" << encode << "): " << inputText << "\n"
                          << "[+] Key: " << keyHex << "\n"
                          << "[+] IV:  " << ivHex << "\n";
            }

            std::string cipherBytes;
            if (encode == "base64") cipherBytes = Base64ToBytes(inputText);
            else if (encode == "hex") cipherBytes = HexToBytes(inputText);
            else cipherBytes = inputText;

            result = AESDecrypt(cipherBytes,
                reinterpret_cast<const CryptoPP::byte*>(keyBytes.data()),
                reinterpret_cast<const CryptoPP::byte*>(ivBytes.data()));

            if (verbose) std::cout << "[+] Plaintext: " << result << "\n";
        }
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ error: " << e.what() << std::endl;
        return 1;
    }

    std::string outFileName = outputFile.empty() ? "output.bin" : outputFile;
    WriteToFile(outFileName, result);

    if (verbose) {
        std::cout << "[+] Result written to file: " << outFileName << "\n";
    }
    return 0;
}
