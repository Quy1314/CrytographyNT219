#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Load private key from PEM
RSA::PrivateKey LoadPrivateKeyFromPEM(const std::string& filename) {
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    while (std::getline(file, line)) {
        if (line.find("BEGIN") != std::string::npos) inKey = true;
        else if (line.find("END") != std::string::npos) inKey = false;
        else if (inKey) base64Data += line;
    }

    std::string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(new StringSink(derData))
    );

    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);
    return privateKey;
}

// RSA decrypt OAEP
std::string RSADecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
    std::string recovered;
    StringSource ss(ciphertext, true,
        new PK_DecryptorFilter(rng, decryptor,
            new StringSink(recovered)
        )
    );
    return recovered;
}

// Hybrid decrypt (RSA-OAEP + AES-CBC)
std::string HybridDecrypt(const std::string& base64Input, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;

    // Decode Base64
    std::string ciphertext;
    StringSource ss(base64Input, true,
        new Base64Decoder(new StringSink(ciphertext))
    );

    if (ciphertext.size() < 4) throw std::runtime_error("Ciphertext too short");

    word32 keyLength = *reinterpret_cast<const word32*>(ciphertext.data());
    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE)
        throw std::runtime_error("Ciphertext format invalid");

    std::string encryptedKey = ciphertext.substr(4, keyLength);

    byte iv[AES::BLOCKSIZE];
    memcpy(iv, ciphertext.data() + 4 + keyLength, AES::BLOCKSIZE);

    std::string aesEncrypted = ciphertext.substr(4 + keyLength + AES::BLOCKSIZE);

    // RSA decrypt AES key
    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
    std::string recoveredKey;
    StringSource ss1(encryptedKey, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(recoveredKey)
        )
    );

    // AES decrypt
    std::string recoveredData;
    CBC_Mode<AES>::Decryption aesDec(
        reinterpret_cast<const byte*>(recoveredKey.data()),
        recoveredKey.size(),
        iv
    );

    StringSource ss2(aesEncrypted, true,
        new StreamTransformationFilter(aesDec,
            new StringSink(recoveredData)
        )
    );

    return recoveredData;
}

int main() {
    try {
        RSA::PrivateKey privateKey = LoadPrivateKeyFromPEM("private_key.pem");
        AutoSeededRandomPool rng;
        if (!privateKey.Validate(rng, 3)) {
            std::cerr << "Private key invalid\n"; return 1;
        }

        std::cout << "Insert RSA Base64 ciphertext (short, <= key size): ";
        std::string rsaBase64;
        std::getline(std::cin, rsaBase64);
        try {
            std::string rsaCiphertext;
            StringSource ss(rsaBase64, true,
                new Base64Decoder(new StringSink(rsaCiphertext))
            );
            std::string rsaRecovered = RSADecrypt(rsaCiphertext, privateKey);
            std::cout << "RSA decrypted: " << rsaRecovered << "\n";
        } catch (const Exception& e) {
            std::cerr << "RSA decryption failed: " << e.what() << "\n";
        }

        std::cout << "\nInsert Hybrid Base64 ciphertext: ";
        std::string hybridBase64;
        std::getline(std::cin, hybridBase64);
        try {
            std::string hybridRecovered = HybridDecrypt(hybridBase64, privateKey);
            std::cout << "Hybrid decrypted: " << hybridRecovered << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Hybrid decryption failed: " << e.what() << "\n";
        }

    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Std exception: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
