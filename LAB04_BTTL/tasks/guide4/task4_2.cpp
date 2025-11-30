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

// Load private key (DER)
RSA::PrivateKey LoadPrivateKeyFromDER(const std::string& filename) {
    RSA::PrivateKey privateKey;
    FileSource fs(filename.c_str(), true);
    privateKey.Load(fs);
    return privateKey;
}

// Load private key (PEM)
RSA::PrivateKey LoadPrivateKeyFromPEM(const std::string& filename) {
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PRIVATE KEY-----" || line == "-----BEGIN RSA PRIVATE KEY-----") {
            inKey = true;
        } else if (line == "-----END PRIVATE KEY-----" || line == "-----END RSA PRIVATE KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }

    std::string derData;
    StringSource ss(base64Data, true, new Base64Decoder(new StringSink(derData)));

    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);

    return privateKey;
}

// RSA OAEP decryption
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

// Hybrid (RSA + AES) decryption
std::string HybridDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;
    if (ciphertext.size() < 4) throw std::runtime_error("Invalid ciphertext format");

    word32 keyLength = *reinterpret_cast<const word32*>(ciphertext.data());
    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE) throw std::runtime_error("Invalid ciphertext format");

    std::string encryptedKey = ciphertext.substr(4, keyLength);
    byte iv[AES::BLOCKSIZE];
    memcpy(iv, ciphertext.data() + 4 + keyLength, AES::BLOCKSIZE);
    std::string aesEncrypted = ciphertext.substr(4 + keyLength + AES::BLOCKSIZE);

    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
    std::string recoveredKey;
    StringSource ss1(encryptedKey, true, new PK_DecryptorFilter(rng, rsaDecryptor, new StringSink(recoveredKey)));

    std::string recoveredData;
    CBC_Mode<AES>::Decryption aesDecryption(reinterpret_cast<const byte*>(recoveredKey.data()), AES::DEFAULT_KEYLENGTH, iv);
    StringSource ss2(aesEncrypted, true, new StreamTransformationFilter(aesDecryption, new StringSink(recoveredData)));

    return recoveredData;
}

int main() {
    try {
        RSA::PrivateKey privateKey;
        std::string rsaRecovered, hybridRecovered;

        try {
            privateKey = LoadPrivateKeyFromPEM("private_key.pem");
            std::cout << "Loaded private key from PEM file.\n";
        } catch (...) {
            privateKey = LoadPrivateKeyFromDER("private_key.der");
            std::cout << "Loaded private key from DER file.\n";
        }

        AutoSeededRandomPool rng;
        if (!privateKey.Validate(rng, 3)) {
            std::cerr << "Private key validation failed\n";
            return 1;
        }

        // RSA decryption
        std::string rsaCiphertext;
        FileSource fs1("rsa_encrypted.bin", true, new StringSink(rsaCiphertext));
        try {
            rsaRecovered = RSADecrypt(rsaCiphertext, privateKey);
            std::cout << "\nRSA decryption result: " << rsaRecovered << "\n";
        } catch (const Exception& e) {
            std::cerr << "RSA decryption failed: " << e.what() << "\n";
        }

        // Hybrid decryption
        std::string hybridCiphertext;
        FileSource fs2("hybrid_encrypted.bin", true, new StringSink(hybridCiphertext));
        try {
            hybridRecovered = HybridDecrypt(hybridCiphertext, privateKey);
            std::cout << "\nHybrid decryption result: " << hybridRecovered << "\n";
        } catch (const std::exception& e) {
            std::cerr << "Hybrid decryption failed: " << e.what() << "\n";
        }

        // Save hybrid result
        if (!hybridRecovered.empty()) {
            FileSink fs3("hybrid_decrypted_output.bin");
            fs3.Put(reinterpret_cast<const byte*>(hybridRecovered.data()), hybridRecovered.size());
            fs3.MessageEnd();
            std::cout << "Hybrid decrypted data saved to hybrid_decrypted_output.bin\n";
        }

        // Save RSA result
        if (!rsaRecovered.empty()) {
            FileSink fs4("rsa_decrypted_output.bin");
            fs4.Put(reinterpret_cast<const byte*>(rsaRecovered.data()), rsaRecovered.size());
            fs4.MessageEnd();
            std::cout << "RSA decrypted data saved to rsa_decrypted_output.bin\n";
        }

    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << "\n";
    }
}
