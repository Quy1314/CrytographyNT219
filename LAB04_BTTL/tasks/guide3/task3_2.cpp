#include <iostream>
#include <string>
#include <fstream>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>

using namespace CryptoPP;

// Function to load a public key from a DER file
RSA::PublicKey LoadPublicKeyFromDER(const std::string& filename) {
    RSA::PublicKey publicKey;
    FileSource fs(filename.c_str(), true);
    publicKey.Load(fs);
    return publicKey;
}

// Function to load a public key from a PEM file
RSA::PublicKey LoadPublicKeyFromPEM(const std::string& filename) {
    // Read the PEM file
    std::ifstream file(filename);
    std::string line, base64Data;
    bool inKey = false;
    
    while (std::getline(file, line)) {
        if (line == "-----BEGIN PUBLIC KEY-----") {
            inKey = true;
        } else if (line == "-----END PUBLIC KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    // Decode the Base64 data
    std::string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    // Load the key
    RSA::PublicKey publicKey;
    ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
    publicKey.Load(as);
    
    return publicKey;
}

// Function for direct RSA encryption with OAEP padding
std::string RSAEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    
    // Create an encryptor with OAEP padding
    RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
    
    // Check if the message fits within the maximum size
    size_t maxPlaintextLength = encryptor.FixedMaxPlaintextLength();
    if (plaintext.length() > maxPlaintextLength) {
        throw std::runtime_error("Message too long for RSA encryption. Maximum length: " + 
                                 std::to_string(maxPlaintextLength) + " bytes.");
    }
    
    // Perform encryption
    std::string ciphertext;
    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(rng, encryptor,
            new StringSink(ciphertext)
        )
    );
    
    return ciphertext;
}

// Function for hybrid encryption (RSA + AES)
std::string HybridEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey) {
    AutoSeededRandomPool rng;
    
    // Generate a random AES key
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rng.GenerateBlock(iv, sizeof(iv));
    
    // Encrypt the plaintext with AES
    std::string ciphertext;
    CBC_Mode<AES>::Encryption aesEncryption(aesKey, sizeof(aesKey), iv);
    StringSource ss1(plaintext, true, 
        new StreamTransformationFilter(aesEncryption,
            new StringSink(ciphertext)
        )
    );
    
    // Encrypt the AES key with RSA-OAEP
    RSAES_OAEP_SHA256_Encryptor rsaEncryptor(publicKey);
    std::string encryptedKey;
    StringSource ss2(aesKey, sizeof(aesKey), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedKey)
        )
    );
    
    // Combine the encrypted key, IV, and ciphertext
    // Format: [encryptedKeyLength(4 bytes)][encryptedKey][IV][ciphertext]
    std::string result;
    
    // Add the length of the encrypted key as a 4-byte integer
    word32 keyLength = static_cast<word32>(encryptedKey.size());
    result.append(reinterpret_cast<const char*>(&keyLength), 4);
    
    // Add the encrypted key, IV, and ciphertext
    result += encryptedKey;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result += ciphertext;
    
    return result;
}

// Function to encode binary data to Base64
std::string Base64Encode(const std::string& data) {
    std::string encoded;
    StringSource ss(data, true,
        new Base64Encoder(
            new StringSink(encoded)
        )
    );
    return encoded;
}

int main(int argc, char* argv[]) {
    try {
        // Load the public key
        RSA::PublicKey publicKey;
        try {
            publicKey = LoadPublicKeyFromPEM("public_key.pem");
            std::cout << "Loaded public key from PEM file." << std::endl;
        } catch (const CryptoPP::Exception&) {
            publicKey = LoadPublicKeyFromDER("public_key.der");
            std::cout << "Loaded public key from DER file." << std::endl;
        }

        // Validate the key
        AutoSeededRandomPool rng;
        if (!publicKey.Validate(rng, 3)) {
            std::cerr << "Public key validation failed" << std::endl;
            return 1;
        }
        std::string inputFile;

// Duyệt argument
for (int i = 1; i < argc; i++) {
    if (std::string(argv[i]) == "--file") {
        inputFile = argv[++i];
    }
}

if (inputFile.empty()) {
    std::cerr << "No input file specified. Use --file <filename>" << std::endl;
    return 1;
}

// Đọc nội dung file
std::string message;
FileSource fs(inputFile.c_str(), true, new StringSink(message));
std::cout << "Original Message: " << message << std::endl;

// Mã hóa hybrid
std::string hybridCiphertext = HybridEncrypt(message, publicKey);
std::string hybridCiphertextBase64 = Base64Encode(hybridCiphertext);
std::cout << "Hybrid Encrypted (Base64): " << hybridCiphertextBase64 << std::endl;
// Mã hóa RSA
std::string RSACiphertext = RSAEncrypt(message, publicKey);
std::string RSACiphertextBase64 = Base64Encode(RSACiphertext);
std::cout << "Direct RSA Encrypted (Base64): " << RSACiphertextBase64 << std::endl;
// Lưu ra file nhị phân
FileSink outFile("hybrid_encrypted.bin");
outFile.Put(reinterpret_cast<const byte*>(hybridCiphertext.data()), hybridCiphertext.size());
outFile.MessageEnd();
std::cout << "Hybrid encrypted data saved to hybrid_encrypted.bin" << std::endl;

FileSink outFile2("rsa_encrypted.bin");
outFile2.Put(reinterpret_cast<const byte*>(RSACiphertext.data()), RSACiphertext.size());
outFile2.MessageEnd();
std::cout << "RSA encrypted data saved to rsa_encrypted.bin" << std::endl;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
