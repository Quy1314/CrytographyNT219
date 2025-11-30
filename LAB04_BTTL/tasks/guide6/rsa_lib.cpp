// rsa_lib.cpp - Implementation file

#include "rsa_lib.h"
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/base64.h>
#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <fstream>
#include <string>
#include <vector>
#include <map>

using namespace CryptoPP;

// Define the opaque handle structures
struct RSAPublicKey_st {
    RSA::PublicKey key;
};

struct RSAPrivateKey_st {
    RSA::PrivateKey key;
};

// Error message mapping
static std::map<RSAStatusCode, const char*> errorMessages = {
    {RSA_SUCCESS, "Success"},
    {RSA_ERROR_INVALID_PARAMETER, "Invalid parameter"},
    {RSA_ERROR_MEMORY_ALLOCATION, "Memory allocation failed"},
    {RSA_ERROR_KEY_GENERATION, "Key generation failed"},
    {RSA_ERROR_KEY_VALIDATION, "Key validation failed"},
    {RSA_ERROR_ENCRYPTION, "Encryption failed"},
    {RSA_ERROR_DECRYPTION, "Decryption failed"},
    {RSA_ERROR_FILE_IO, "File I/O error"},
    {RSA_ERROR_BUFFER_TOO_SMALL, "Buffer too small"},
    {RSA_ERROR_INVALID_FORMAT, "Invalid format"},
    {RSA_ERROR_UNKNOWN, "Unknown error"}
};

// Utility function to save a key to a DER file
template<class KEY>
static bool SaveKeyToDERFile(const KEY& key, const std::string& filename) {
    try {
        ByteQueue queue;
        key.Save(queue);
        
        FileSink file(filename.c_str());
        queue.CopyTo(file);
        file.MessageEnd();
        return true;
    } catch (...) {
        return false;
    }
}

// Utility function to convert DER to PEM
static bool DERToPEM(const std::string& derFilename, const std::string& pemFilename, 
                    const std::string& header, const std::string& footer) {
    try {
        // Read DER file
        std::ifstream derFile(derFilename, std::ios::binary);
        std::vector<char> derData((std::istreambuf_iterator<char>(derFile)),
                                std::istreambuf_iterator<char>());
        derFile.close();
        
        // Base64 encode
        std::string base64Data;
        StringSource ss(reinterpret_cast<const byte*>(derData.data()), derData.size(), true,
            new Base64Encoder(
                new StringSink(base64Data), true, 64
            )
        );
        
        // Write PEM file
        std::ofstream pemFile(pemFilename);
        pemFile << header << std::endl;
        pemFile << base64Data;
        pemFile << footer << std::endl;
        pemFile.close();
        return true;
    } catch (...) {
        return false;
    }
}

// Implementation of key generation
RSA_API RSAStatusCode RSA_GenerateKeyPair(
    unsigned int keySize,
    const char* privateKeyFile,
    const char* publicKeyFile,
    int usePEM
) {
    if (!privateKeyFile || !publicKeyFile || keySize < 1024) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        // Create a random number generator
        AutoSeededRandomPool rng;
        
        // Generate RSA keys
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, keySize);
        
        // Extract the public key from the private key
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        
        // Validate the keys
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        result = publicKey.Validate(rng, 3);
        if (!result) {
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        // Determine filenames
        std::string privateKeyDer = std::string(privateKeyFile) + (usePEM ? ".der" : "");
        std::string publicKeyDer = std::string(publicKeyFile) + (usePEM ? ".der" : "");
        
        // Save keys in DER format
        if (!SaveKeyToDERFile(privateKey, usePEM ? privateKeyDer : privateKeyFile)) {
            return RSA_ERROR_FILE_IO;
        }
        
        if (!SaveKeyToDERFile(publicKey, usePEM ? publicKeyDer : publicKeyFile)) {
            return RSA_ERROR_FILE_IO;
        }
        
        // Convert to PEM format if requested
        if (usePEM) {
            if (!DERToPEM(privateKeyDer, privateKeyFile, 
                         "-----BEGIN RSA PRIVATE KEY-----", 
                         "-----END RSA PRIVATE KEY-----")) {
                return RSA_ERROR_FILE_IO;
            }
            
            if (!DERToPEM(publicKeyDer, publicKeyFile, 
                         "-----BEGIN PUBLIC KEY-----", 
                         "-----END PUBLIC KEY-----")) {
                return RSA_ERROR_FILE_IO;
            }
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        return RSA_ERROR_KEY_GENERATION;
    } catch (const std::exception&) {
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of public key loading
RSA_API RSAStatusCode RSA_LoadPublicKey(
    const char* filename,
    RSAPublicKeyHandle* keyHandle
) {
    if (!filename || !keyHandle) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        *keyHandle = new RSAPublicKey_st();
        if (!*keyHandle) {
            return RSA_ERROR_MEMORY_ALLOCATION;
        }
        
        // Try loading as PEM
        bool isPEM = false;
        std::ifstream file(filename);
        std::string line, base64Data;
        bool inKey = false;
        
        while (std::getline(file, line)) {
            if (line == "-----BEGIN PUBLIC KEY-----") {
                inKey = true;
                isPEM = true;
            } else if (line == "-----END PUBLIC KEY-----") {
                inKey = false;
            } else if (inKey) {
                base64Data += line;
            }
        }
        
        if (isPEM) {
            // Decode the Base64 data
            std::string derData;
            StringSource ss(base64Data, true,
                new Base64Decoder(
                    new StringSink(derData)
                )
            );
            
            // Load the key
            ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
            (*keyHandle)->key.Load(as);
        } else {
            // Try loading as DER
            FileSource fs(filename, true);
            (*keyHandle)->key.Load(fs);
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        if (!(*keyHandle)->key.Validate(rng, 3)) {
            delete *keyHandle;
            *keyHandle = nullptr;
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_FILE_IO;
    } catch (const std::exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of private key loading
RSA_API RSAStatusCode RSA_LoadPrivateKey(
    const char* filename,
    RSAPrivateKeyHandle* keyHandle
) {
    if (!filename || !keyHandle) {
        return RSA_ERROR_INVALID_PARAMETER;
    }
    
    try {
        *keyHandle = new RSAPrivateKey_st();
        if (!*keyHandle) {
            return RSA_ERROR_MEMORY_ALLOCATION;
        }
        
        // Try loading as PEM
        bool isPEM = false;
        std::ifstream file(filename);
        std::string line, base64Data;
        bool inKey = false;
        
        while (std::getline(file, line)) {
            if (line == "-----BEGIN RSA PRIVATE KEY-----" || line == "-----BEGIN PRIVATE KEY-----") {
                inKey = true;
                isPEM = true;
            } else if (line == "-----END RSA PRIVATE KEY-----" || line == "-----END PRIVATE KEY-----") {
                inKey = false;
            } else if (inKey) {
                base64Data += line;
            }
        }
        
        if (isPEM) {
            // Decode the Base64 data
            std::string derData;
            StringSource ss(base64Data, true,
                new Base64Decoder(
                    new StringSink(derData)
                )
            );
            
            // Load the key
            ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
            (*keyHandle)->key.Load(as);
        } else {
            // Try loading as DER
            FileSource fs(filename, true);
            (*keyHandle)->key.Load(fs);
        }
        
        // Validate the key
        AutoSeededRandomPool rng;
        if (!(*keyHandle)->key.Validate(rng, 3)) {
            delete *keyHandle;
            *keyHandle = nullptr;
            return RSA_ERROR_KEY_VALIDATION;
        }
        
        return RSA_SUCCESS;
    } catch (const CryptoPP::Exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_FILE_IO;
    } catch (const std::exception&) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    } catch (...) {
        if (*keyHandle) {
            delete *keyHandle;
            *keyHandle = nullptr;
        }
        return RSA_ERROR_UNKNOWN;
    }
}

// Implementation of public key freeing
RSA_API void RSA_FreePublicKey(RSAPublicKeyHandle keyHandle) {
    if (keyHandle) {
        delete keyHandle;
    }
}

// Implementation of private key freeing
RSA_API void RSA_FreePrivateKey(RSAPrivateKeyHandle keyHandle) {
    if (keyHandle) {
        delete keyHandle;
    }
}

// Implementation of direct RSA encryption
static std::string RSAEncryptInternal(
    const std::string& plaintext,
    const RSA::PublicKey& publicKey,
    RSAPaddingScheme paddingScheme
) {
    AutoSeededRandomPool rng;
    
    // Create an encryptor with the specified padding
    PK_Encryptor* encryptor = nullptr;
    
    if (paddingScheme == RSA_PADDING_PKCS1) {
        encryptor = new RSAES_PKCS1v15_Encryptor(publicKey);
    } else {  // Default to OAEP
        encryptor = new RSAES_OAEP_SHA256_Encryptor(publicKey);
    }
    
    // Check if the message fits within the maximum size
    size_t maxPlaintextLength = encryptor->FixedMaxPlaintextLength();
    if (plaintext.length() > maxPlaintextLength) {
        delete encryptor;
        throw std::runtime_error("Message too long for RSA encryption");
    }
    
    // Perform encryption
    std::string ciphertext;
    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(rng, *encryptor,
            new StringSink(ciphertext)
        )
    );
    
    delete encryptor;
    return ciphertext;
}

// Implementation of direct RSA decryption
static std::string RSADecryptInternal(
    const std::string& ciphertext,
    const RSA::PrivateKey& privateKey,
    RSAPaddingScheme paddingScheme
) {
    AutoSeededRandomPool rng;
    std::string recovered;

    try {
        if (paddingScheme == RSA_PADDING_PKCS1) {
            RSAES_PKCS1v15_Decryptor decryptor(privateKey);
            StringSource ss(ciphertext, true,
                new PK_DecryptorFilter(rng, decryptor,
                    new StringSink(recovered)
                )
            );
        } else { // OAEP-SHA256
            RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
            StringSource ss(ciphertext, true,
                new PK_DecryptorFilter(rng, decryptor,
                    new StringSink(recovered)
                )
            );
        }
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error(std::string("RSA decryption failed: ") + e.what());
    }

    return recovered;
}

// Implementation of hybrid encryption
static std::string HybridEncryptInternal(
    const std::string& plaintext,
    const RSA::PublicKey& publicKey,
    RSAPaddingScheme paddingScheme
) {
    AutoSeededRandomPool rng;
    
    // Generate a random AES key
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rng.GenerateBlock(iv, sizeof(iv));

    // Encrypt the plaintext with AES-CBC
    std::string ciphertext;
    CBC_Mode<AES>::Encryption aesEnc(aesKey, sizeof(aesKey), iv);
    StringSource ss1(plaintext, true,
        new StreamTransformationFilter(aesEnc,
            new StringSink(ciphertext)
        )
    );

    // Encrypt AES key using RSA (with padding)
    std::string encryptedKey;
    try {
        if (paddingScheme == RSA_PADDING_PKCS1) {
            RSAES_PKCS1v15_Encryptor rsaEnc(publicKey);
            StringSource ss2(aesKey, sizeof(aesKey), true,
                new PK_EncryptorFilter(rng, rsaEnc,
                    new StringSink(encryptedKey)
                )
            );
        } else {
            RSAES_OAEP_SHA256_Encryptor rsaEnc(publicKey);
            StringSource ss2(aesKey, sizeof(aesKey), true,
                new PK_EncryptorFilter(rng, rsaEnc,
                    new StringSink(encryptedKey)
                )
            );
        }
    } catch (const Exception& e) {
        throw std::runtime_error(std::string("Hybrid RSA encryption failed: ") + e.what());
    }

    // Combine: [4 bytes keyLen][encryptedKey][IV][ciphertext]
    std::string result;
    word32 keyLen = static_cast<word32>(encryptedKey.size());
    byte lenBytes[4];
    lenBytes[0] = (keyLen >> 24) & 0xFF;
    lenBytes[1] = (keyLen >> 16) & 0xFF;
    lenBytes[2] = (keyLen >> 8) & 0xFF;
    lenBytes[3] = keyLen & 0xFF;
    result.append(reinterpret_cast<const char*>(lenBytes), 4);
    result += encryptedKey;
    result.append(reinterpret_cast<const char*>(iv), sizeof(iv));
    result += ciphertext;

    return result;
}

// Implementation of hybrid decryption
// ==========================================================
// Hybrid Decrypt (RSA + AES)
// ==========================================================
static std::string HybridDecryptInternal(
    const std::string& ciphertext,
    const RSA::PrivateKey& privateKey,
    RSAPaddingScheme paddingScheme
) {
    if (ciphertext.size() < 4 + AES::BLOCKSIZE)
        throw std::runtime_error("Invalid ciphertext length");

    // Step 1: extract encrypted key length (first 4 bytes, big-endian)
    const byte* data = reinterpret_cast<const byte*>(ciphertext.data());
    word32 keyLength = (static_cast<word32>(data[0]) << 24) |
                       (static_cast<word32>(data[1]) << 16) |
                       (static_cast<word32>(data[2]) << 8)  |
                        static_cast<word32>(data[3]);

    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE)
        throw std::runtime_error("Invalid ciphertext structure (length mismatch)");

    // Step 2: slice sections
    const byte* encKeyPtr = data + 4;
    const byte* ivPtr = encKeyPtr + keyLength;
    const byte* aesDataPtr = ivPtr + AES::BLOCKSIZE;

    std::string encKey(reinterpret_cast<const char*>(encKeyPtr), keyLength);
    std::string iv(reinterpret_cast<const char*>(ivPtr), AES::BLOCKSIZE);
    std::string aesCipher(reinterpret_cast<const char*>(aesDataPtr),
                          ciphertext.size() - (4 + keyLength + AES::BLOCKSIZE));

    // Step 3: decrypt AES key using RSA
    AutoSeededRandomPool rng;
    std::string aesKey;
    try {
        if (paddingScheme == RSA_PADDING_PKCS1) {
            RSAES_PKCS1v15_Decryptor dec(privateKey);
            StringSource ss(encKey, true,
                new PK_DecryptorFilter(rng, dec,
                    new StringSink(aesKey)
                )
            );
        } else {
            RSAES_OAEP_SHA256_Decryptor dec(privateKey);
            StringSource ss(encKey, true,
                new PK_DecryptorFilter(rng, dec,
                    new StringSink(aesKey)
                )
            );
        }
    } catch (const Exception& e) {
        throw std::runtime_error(std::string("RSA key decryption failed: ") + e.what());
    }

    // Step 4: decrypt AES payload
    std::string recovered;
    CBC_Mode<AES>::Decryption aesDec((const byte*)aesKey.data(), aesKey.size(), (const byte*)iv.data());
    try {
        StringSource ss2(aesCipher, true,
            new StreamTransformationFilter(aesDec,
                new StringSink(recovered)
            )
        );
    } catch (const Exception& e) {
        throw std::runtime_error(std::string("AES decryption failed: ") + e.what());
    }

    return recovered;
}

// ==========================================================
// RSA_Encrypt (Public Key)
// ==========================================================
RSA_API RSAStatusCode RSA_Encrypt(
    RSAPublicKeyHandle publicKey,
    const unsigned char* data,
    size_t dataLength,
    unsigned char* encryptedData,
    size_t* encryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
) {
    if (!publicKey || !data || !encryptedDataLength)
        return RSA_ERROR_INVALID_PARAMETER;

    try {
        std::string plaintext(reinterpret_cast<const char*>(data), dataLength);
        std::string ciphertext = useHybrid
            ? HybridEncryptInternal(plaintext, publicKey->key, paddingScheme)
            : RSAEncryptInternal(plaintext, publicKey->key, paddingScheme);

        if (!encryptedData) {
            *encryptedDataLength = ciphertext.size();
            return RSA_ERROR_BUFFER_TOO_SMALL;
        }

        if (*encryptedDataLength < ciphertext.size())
            return RSA_ERROR_BUFFER_TOO_SMALL;

        memcpy(encryptedData, ciphertext.data(), ciphertext.size());
        *encryptedDataLength = ciphertext.size();
        return RSA_SUCCESS;
    } catch (...) {
        return RSA_ERROR_ENCRYPTION;
    }
}

// ==========================================================
// RSA_Decrypt (Private Key)
// ==========================================================
RSA_API RSAStatusCode RSA_Decrypt(
    RSAPrivateKeyHandle privateKey,
    const unsigned char* encryptedData,
    size_t encryptedDataLength,
    unsigned char* decryptedData,
    size_t* decryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
) {
    if (!privateKey || !encryptedData || !decryptedDataLength)
        return RSA_ERROR_INVALID_PARAMETER;

    try {
        std::string cipher(reinterpret_cast<const char*>(encryptedData), encryptedDataLength);
        std::string recovered = useHybrid
            ? HybridDecryptInternal(cipher, privateKey->key, paddingScheme)
            : RSADecryptInternal(cipher, privateKey->key, paddingScheme);

        if (!decryptedData) {
            *decryptedDataLength = recovered.size();
            return RSA_ERROR_BUFFER_TOO_SMALL;
        }

        if (*decryptedDataLength < recovered.size())
            return RSA_ERROR_BUFFER_TOO_SMALL;

        memcpy(decryptedData, recovered.data(), recovered.size());
        *decryptedDataLength = recovered.size();
        return RSA_SUCCESS;
    } catch (...) {
        return RSA_ERROR_DECRYPTION;
    }
}

// ==========================================================
// File-based Encryption
// ==========================================================
RSA_API RSAStatusCode RSA_EncryptFile(
    RSAPublicKeyHandle publicKey,
    const char* inputFilename,
    const char* outputFilename,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat outputFormat,   // <-- thêm dòng này
    int useHybrid
) {
    if (!publicKey || !inputFilename || !outputFilename)
        return RSA_ERROR_INVALID_PARAMETER;

    try {
        std::string plaintext;
        FileSource fs(inputFilename, true, new StringSink(plaintext));

        std::string ciphertext = useHybrid
            ? HybridEncryptInternal(plaintext, publicKey->key, paddingScheme)
            : RSAEncryptInternal(plaintext, publicKey->key, paddingScheme);

        FileSink out(outputFilename);
        out.Put((const byte*)ciphertext.data(), ciphertext.size());
        out.MessageEnd();

        return RSA_SUCCESS;
    } catch (...) {
        return RSA_ERROR_FILE_IO;
    }
}

// ==========================================================
// File-based Decryption
// ==========================================================
RSA_API RSAStatusCode RSA_DecryptFile(
    RSAPrivateKeyHandle privateKey,
    const char* inputFilename,
    const char* outputFilename,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat inputFormat,    // <-- thêm dòng này
    int useHybrid
) {
    if (!privateKey || !inputFilename || !outputFilename)
        return RSA_ERROR_INVALID_PARAMETER;

    try {
        std::string ciphertext;
        FileSource fs(inputFilename, true, new StringSink(ciphertext));

        std::string recovered = useHybrid
            ? HybridDecryptInternal(ciphertext, privateKey->key, paddingScheme)
            : RSADecryptInternal(ciphertext, privateKey->key, paddingScheme);

        FileSink out(outputFilename);
        out.Put((const byte*)recovered.data(), recovered.size());
        out.MessageEnd();

        return RSA_SUCCESS;
    } catch (...) {
        return RSA_ERROR_FILE_IO;
    }
}

// ==========================================================
// Utility: Get Error Message
// ==========================================================
RSA_API const char* RSA_GetErrorMessage(RSAStatusCode code) {
    static std::map<RSAStatusCode, const char*> errorMessages = {
        {RSA_SUCCESS, "Success"},
        {RSA_ERROR_INVALID_PARAMETER, "Invalid parameter"},
        {RSA_ERROR_MEMORY_ALLOCATION, "Memory allocation failed"},
        {RSA_ERROR_KEY_GENERATION, "Key generation failed"},
        {RSA_ERROR_KEY_VALIDATION, "Key validation failed"},
        {RSA_ERROR_ENCRYPTION, "Encryption failed"},
        {RSA_ERROR_DECRYPTION, "Decryption failed"},
        {RSA_ERROR_FILE_IO, "File I/O error"},
        {RSA_ERROR_BUFFER_TOO_SMALL, "Buffer too small"},
        {RSA_ERROR_INVALID_FORMAT, "Invalid format"},
        {RSA_ERROR_UNKNOWN, "Unknown error"}
    };

    auto it = errorMessages.find(code);
    if (it != errorMessages.end())
        return it->second;
    return "Unknown error";
}


// ==========================================================
// Utility: Max Plaintext Length
// ==========================================================
RSA_API size_t RSA_GetMaxPlaintextLength(
    RSAPublicKeyHandle publicKey,
    RSAPaddingScheme paddingScheme
) {
    if (!publicKey) return 0;
    size_t keyBytes = publicKey->key.GetModulus().ByteCount();

    if (paddingScheme == RSA_PADDING_PKCS1)
        return keyBytes - 11; // PKCS#1 v1.5 overhead
    else
        return keyBytes - 2 * 32 - 2; // OAEP-SHA256 overhead
}