# Guide 5: Full RSA Implementation with Command-Line Arguments

## Introduction

This guide demonstrates how to create a complete RSA encryption/decryption application using the Crypto++ library with command-line arguments. This comprehensive implementation combines all the concepts covered in the previous guides into a single, versatile command-line tool that can generate keys, encrypt, and decrypt data.

## Prerequisites

- Crypto++ library installed (version 8.6.0 or later)
- Understanding of RSA cryptography concepts
- C++ development environment
- Familiarity with command-line argument parsing

## Application Features

Our RSA application will support the following operations:

1. **Key Generation**: Generate RSA key pairs and save them in both DER and PEM formats
2. **Encryption**: Encrypt data using an RSA public key
3. **Decryption**: Decrypt data using an RSA private key
4. **File Support**: Read input from files and write output to files
5. **Command-Line Interface**: Control all operations through command-line arguments

## Command-Line Argument Structure

The application will support the following command-line arguments:

```
Usage: rsa_tool [OPERATION] [OPTIONS]

OPERATIONS:
  --generate-keys     Generate RSA key pair
  --encrypt           Encrypt data
  --decrypt           Decrypt data

OPTIONS:
  --key-size SIZE     Key size in bits (default: 3072)
  --public-key FILE   Public key file (PEM or DER)
  --private-key FILE  Private key file (PEM or DER)
  --input FILE        Input file (default: stdin)
  --output FILE       Output file (default: stdout)
  --format FORMAT     Output format: binary, base64, hex (default: binary)
  --padding PADDING   Padding scheme: pkcs1, oaep (default: oaep)
  --hybrid            Use hybrid encryption for large messages
  --help              Display this help message
```

## Parsing Command-Line Arguments

We'll use a simple approach to parse command-line arguments:

```cpp
#include <iostream>
#include <string>
#include <map>
#include <vector>

// Function to parse command-line arguments
std::map<std::string, std::string> ParseCommandLine(int argc, char* argv[]) {
    std::map<std::string, std::string> args;
    std::vector<std::string> operations = {"--generate-keys", "--encrypt", "--decrypt", "--help"};
    
    // Set default values
    args["--key-size"] = "3072";
    args["--format"] = "binary";
    args["--padding"] = "oaep";
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        // Check if it's an operation
        for (const auto& op : operations) {
            if (arg == op) {
                args[op] = "true";
                continue;
            }
        }
        
        // Check if it's a flag option
        if (arg == "--hybrid") {
            args[arg] = "true";
            continue;
        }
        
        // Check if it's a value option
        if (i + 1 < argc && arg.substr(0, 2) == "--") {
            args[arg] = argv[i + 1];
            ++i;  // Skip the next argument (the value)
        }
    }
    
    return args;
}

// Function to display help message
void DisplayHelp() {
    std::cout << "Usage: rsa_tool [OPERATION] [OPTIONS]\n\n"
              << "OPERATIONS:\n"
              << "  --generate-keys     Generate RSA key pair\n"
              << "  --encrypt           Encrypt data\n"
              << "  --decrypt           Decrypt data\n\n"
              << "OPTIONS:\n"
              << "  --key-size SIZE     Key size in bits (default: 3072)\n"
              << "  --public-key FILE   Public key file (PEM or DER)\n"
              << "  --private-key FILE  Private key file (PEM or DER)\n"
              << "  --input FILE        Input file (default: stdin)\n"
              << "  --output FILE       Output file (default: stdout)\n"
              << "  --format FORMAT     Output format: binary, base64, hex (default: binary)\n"
              << "  --padding PADDING   Padding scheme: pkcs1, oaep (default: oaep)\n"
              << "  --hybrid            Use hybrid encryption for large messages\n"
              << "  --help              Display this help message\n";
}
```

## Key Generation Implementation

Let's implement the key generation functionality:

```cpp
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <fstream>

using namespace CryptoPP;

// Function to save a key to a DER file
template<class KEY>
void SaveKeyToDERFile(const KEY& key, const std::string& filename) {
    ByteQueue queue;
    key.Save(queue);
    
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

// Function to convert DER to PEM
void DERToPEM(const std::string& derFilename, const std::string& pemFilename, 
              const std::string& header, const std::string& footer) {
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
}

// Function to generate RSA keys
bool GenerateKeys(const std::map<std::string, std::string>& args) {
    try {
        // Parse key size
        int keySize = std::stoi(args.at("--key-size"));
        std::cout << "Generating " << keySize << "-bit RSA keys..." << std::endl;
        
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
            std::cerr << "Private key validation failed" << std::endl;
            return false;
        }
        
        result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return false;
        }
        
        std::cout << "Keys generated and validated successfully." << std::endl;
        
        // Determine output filenames
        std::string privateKeyDer = "private_key.der";
        std::string publicKeyDer = "public_key.der";
        std::string privateKeyPem = "private_key.pem";
        std::string publicKeyPem = "public_key.pem";
        
        // Override with command-line arguments if provided
        if (args.find("--private-key") != args.end()) {
            privateKeyPem = args.at("--private-key");
            privateKeyDer = privateKeyPem + ".der";
        }
        
        if (args.find("--public-key") != args.end()) {
            publicKeyPem = args.at("--public-key");
            publicKeyDer = publicKeyPem + ".der";
        }
        
        // Save keys in DER format
        std::cout << "Saving keys in DER format..." << std::endl;
        SaveKeyToDERFile(privateKey, privateKeyDer);
        SaveKeyToDERFile(publicKey, publicKeyDer);
        
        // Convert to PEM format
        std::cout << "Converting keys to PEM format..." << std::endl;
        DERToPEM(privateKeyDer, privateKeyPem, 
                 "-----BEGIN RSA PRIVATE KEY-----", 
                 "-----END RSA PRIVATE KEY-----");
        
        DERToPEM(publicKeyDer, publicKeyPem, 
                 "-----BEGIN PUBLIC KEY-----", 
                 "-----END PUBLIC KEY-----");
        
        std::cout << "Keys saved in both DER and PEM formats:" << std::endl;
        std::cout << "  Private key: " << privateKeyPem << " and " << privateKeyDer << std::endl;
        std::cout << "  Public key: " << publicKeyPem << " and " << publicKeyDer << std::endl;
        
        return true;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return false;
    }
}
```

## Key Loading Functions

We need functions to load keys from both PEM and DER formats:

```cpp
// Function to load a public key (tries PEM first, then DER)
RSA::PublicKey LoadPublicKey(const std::string& filename) {
    try {
        // Try loading as PEM
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
        
        if (!base64Data.empty()) {
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
        
        // If PEM loading failed, try DER
        RSA::PublicKey publicKey;
        FileSource fs(filename.c_str(), true);
        publicKey.Load(fs);
        return publicKey;
    } catch (const Exception& e) {
        throw Exception(Exception::OTHER_ERROR, "Failed to load public key: " + std::string(e.what()));
    }
}

// Function to load a private key (tries PEM first, then DER)
RSA::PrivateKey LoadPrivateKey(const std::string& filename) {
    try {
        // Try loading as PEM
        std::ifstream file(filename);
        std::string line, base64Data;
        bool inKey = false;
        
        while (std::getline(file, line)) {
            if (line == "-----BEGIN RSA PRIVATE KEY-----" || line == "-----BEGIN PRIVATE KEY-----") {
                inKey = true;
            } else if (line == "-----END RSA PRIVATE KEY-----" || line == "-----END PRIVATE KEY-----") {
                inKey = false;
            } else if (inKey) {
                base64Data += line;
            }
        }
        
        if (!base64Data.empty()) {
            // Decode the Base64 data
            std::string derData;
            StringSource ss(base64Data, true,
                new Base64Decoder(
                    new StringSink(derData)
                )
            );
            
            // Load the key
            RSA::PrivateKey privateKey;
            ArraySource as(reinterpret_cast<const byte*>(derData.data()), derData.size(), true);
            privateKey.Load(as);
            return privateKey;
        }
        
        // If PEM loading failed, try DER
        RSA::PrivateKey privateKey;
        FileSource fs(filename.c_str(), true);
        privateKey.Load(fs);
        return privateKey;
    } catch (const Exception& e) {
        throw Exception(Exception::OTHER_ERROR, "Failed to load private key: " + std::string(e.what()));
    }
}
```

## Encryption Implementation

Now let's implement the encryption functionality:

```cpp
// Function for direct RSA encryption
std::string RSAEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey, 
                      const std::string& paddingScheme) {
    AutoSeededRandomPool rng;
    
    // Create an encryptor with the specified padding
    PK_Encryptor* encryptor = nullptr;
    
    if (paddingScheme == "pkcs1") {
        encryptor = new RSAES_PKCS1v15_Encryptor(publicKey);
    } else {  // Default to OAEP
        encryptor = new RSAES_OAEP_SHA256_Encryptor(publicKey);
    }
    
    // Check if the message fits within the maximum size
    size_t maxPlaintextLength = encryptor->FixedMaxPlaintextLength();
    if (plaintext.length() > maxPlaintextLength) {
        delete encryptor;
        throw std::runtime_error("Message too long for RSA encryption. Maximum length: " + 
                                 std::to_string(maxPlaintextLength) + " bytes.");
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

// Function for hybrid encryption (RSA + AES)
std::string HybridEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey,
                         const std::string& paddingScheme) {
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
    
    // Encrypt the AES key with RSA
    PK_Encryptor* rsaEncryptor = nullptr;
    
    if (paddingScheme == "pkcs1") {
        rsaEncryptor = new RSAES_PKCS1v15_Encryptor(publicKey);
    } else {  // Default to OAEP
        rsaEncryptor = new RSAES_OAEP_SHA256_Encryptor(publicKey);
    }
    
    std::string encryptedKey;
    StringSource ss2(aesKey, sizeof(aesKey), true,
        new PK_EncryptorFilter(rng, *rsaEncryptor,
            new StringSink(encryptedKey)
        )
    );
    
    delete rsaEncryptor;
    
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

// Main encryption function
bool Encrypt(const std::map<std::string, std::string>& args) {
    try {
        // Check for required arguments
        if (args.find("--public-key") == args.end()) {
            std::cerr << "Error: Public key file (--public-key) is required for encryption" << std::endl;
            return false;
        }
        
        // Load the public key
        std::string publicKeyFile = args.at("--public-key");
        std::cout << "Loading public key from " << publicKeyFile << "..." << std::endl;
        RSA::PublicKey publicKey = LoadPublicKey(publicKeyFile);
        
        // Validate the key
        AutoSeededRandomPool rng;
        bool result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return false;
        }
        
        // Read input data
        std::string inputData;
        if (args.find("--input") != args.end()) {
            std::string inputFile = args.at("--input");
            std::cout << "Reading input from " << inputFile << "..." << std::endl;
            FileSource fs(inputFile.c_str(), true, new StringSink(inputData));
        } else {
            std::cout << "Reading input from stdin (press Enter twice to finish)...\n";
            std::string line;
            int blanks = 0;
            while (std::getline(std::cin, line)) {
                if (line.empty()) {
                    if (++blanks == 2) break;
                } else {
                    blanks = 0;
                    inputData += line + "\n";
                }
            }
        }
        if (inputData.empty()) {
            std::cerr << "Error: no input data provided\n";
            return false;
        }

        // Encrypt
        bool useHybrid = args.find("--hybrid") != args.end();
        std::string padding = (args.find("--padding") != args.end()) ? args.at("--padding") : "oaep";
        std::string ciphertext;

        if (useHybrid) {
            std::cout << "Performing hybrid RSA + AES encryption...\n";
            ciphertext = HybridEncrypt(inputData, publicKey, padding);
        } else {
            std::cout << "Performing RSA encryption (" << padding << ")...\n";
            ciphertext = RSAEncrypt(inputData, publicKey, padding);
        }

        // Write output
        std::string format = (args.find("--format") != args.end()) ? args.at("--format") : "binary";
        if (args.find("--output") != args.end()) {
            std::string outFile = args.at("--output");
            std::ofstream out(outFile, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to open output file: " << outFile << "\n";
                return false;
            }

            if (format == "binary") {
                out.write(ciphertext.data(), ciphertext.size());
            } else if (format == "base64") {
                StringSource ss(ciphertext, true, new Base64Encoder(new FileSink(out), false));
            } else if (format == "hex") {
                StringSource ss(ciphertext, true, new HexEncoder(new FileSink(out), false));
            } else {
                std::cerr << "Unknown format: " << format << "\n";
                return false;
            }

            std::cout << "Ciphertext written to " << outFile << "\n";
        } else {
            std::cout << "\nCiphertext (" << format << "):\n";
            if (format == "binary") {
                std::cout << "[binary data not shown]\n";
            } else if (format == "base64") {
                StringSource ss(ciphertext, true, new Base64Encoder(new FileSink(std::cout), false));
            } else {
                StringSource ss(ciphertext, true, new HexEncoder(new FileSink(std::cout), false));
            }
            std::cout << "\n";
        }

        return true;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
        return false;
    }
}
```

## Decryption Implementation

Now let's implement the decryption functionality:

```cpp
// Function for direct RSA decryption
std::string RSADecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey,
                       const std::string& paddingScheme) {
    AutoSeededRandomPool rng;
    PK_Decryptor* decryptor = nullptr;

    if (paddingScheme == "pkcs1")
        decryptor = new RSAES_PKCS1v15_Decryptor(privateKey);
    else
        decryptor = new RSAES_OAEP_SHA256_Decryptor(privateKey);

    std::string recovered;
    StringSource(ciphertext, true,
        new PK_DecryptorFilter(rng, *decryptor, new StringSink(recovered))
    );
    delete decryptor;
    return recovered;
}

// Function for hybrid decryption (RSA + AES)
std::string HybridDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey) {
    AutoSeededRandomPool rng;

    // Check ciphertext length
    if (ciphertext.size() < 4 + AES::BLOCKSIZE) {
        throw std::runtime_error("Ciphertext too short for hybrid RSA decryption");
    }

    // Step 1: Extract encrypted key length (first 4 bytes)
    const byte* data = reinterpret_cast<const byte*>(ciphertext.data());
    word32 keyLength = (static_cast<word32>(data[3]) << 24) |
                   (static_cast<word32>(data[2]) << 16) |
                   (static_cast<word32>(data[1]) << 8)  |
                    static_cast<word32>(data[0]);

    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE) {
        throw std::runtime_error("Invalid ciphertext structure (length mismatch)");
    }

    // Step 2: Extract encrypted AES key, IV, and AES ciphertext
    const byte* encryptedKey = data + 4;
    const byte* iv = encryptedKey + keyLength;
    const byte* aesCipher = iv + AES::BLOCKSIZE;
    size_t aesCipherLen = ciphertext.size() - (4 + keyLength + AES::BLOCKSIZE);

    // Step 3: Decrypt AES key with RSA (OAEP-SHA256)
    std::string decryptedKey;
    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);

    StringSource ss1(encryptedKey, keyLength, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(decryptedKey)
        )
    );

    if (decryptedKey.size() != AES::DEFAULT_KEYLENGTH) {
        throw std::runtime_error("Decrypted AES key size mismatch");
    }

    // Step 4: Decrypt the AES ciphertext
    CBC_Mode<AES>::Decryption aesDecryption(
        reinterpret_cast<const byte*>(decryptedKey.data()),
        decryptedKey.size(),
        iv
    );

    std::string recovered;
    StringSource ss2(aesCipher, aesCipherLen, true,
        new StreamTransformationFilter(aesDecryption,
            new StringSink(recovered)
        )
    );

    // Step 5: Return recovered plaintext
    return recovered;
}



bool Decrypt(const std::map<std::string, std::string>& args) {
    try {
        if (args.find("--private-key") == args.end()) {
            std::cerr << "Error: --private-key is required for decryption\n";
            return false;
        }

        std::string priFile = args.at("--private-key");
        RSA::PrivateKey privateKey = LoadPrivateKey(priFile);

        AutoSeededRandomPool rng;
        if (!privateKey.Validate(rng, 3)) {
            std::cerr << "Private key validation failed\n";
            return false;
        }

        // Read ciphertext
        std::string ciphertext;
        if (args.find("--input") != args.end()) {
            FileSource fs(args.at("--input").c_str(), true, new StringSink(ciphertext));
        } else {
            std::cout << "Reading ciphertext from stdin (paste Base64 and press Enter twice to finish)...\n";
            std::string line, b64Input;
            int blanks = 0;
            while (std::getline(std::cin, line)) {
                if (line.empty()) {
                    if (++blanks == 2) break;
                } else {
                    blanks = 0;
                    b64Input += line;
                }
            }
            StringSource ss(b64Input, true, new Base64Decoder(new StringSink(ciphertext)));
        }
        if (ciphertext.empty()) {
            std::cerr << "Error: no ciphertext data provided\n";
            return false;
        }

        // Decrypt
        bool useHybrid = args.find("--hybrid") != args.end();
        std::string padding = (args.find("--padding") != args.end()) ? args.at("--padding") : "oaep";
        std::string recovered;

        if (useHybrid) {
            std::cout << "Performing hybrid RSA + AES decryption...\n";
            recovered = HybridDecrypt(ciphertext, privateKey);
        } else {
            std::cout << "Performing RSA decryption (" << padding << ")...\n";
            recovered = RSADecrypt(ciphertext, privateKey, padding);
        }

        // Write output
        std::string format = (args.find("--format") != args.end()) ? args.at("--format") : "binary";
        if (args.find("--output") != args.end()) {
            std::string outFile = args.at("--output");
            std::ofstream out(outFile, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to open output file: " << outFile << "\n";
                return false;
            }

            if (format == "binary") {
                out.write(recovered.data(), recovered.size());
            } else if (format == "base64") {
                StringSource ss(recovered, true, new Base64Encoder(new FileSink(out), false));
            } else if (format == "hex") {
                StringSource ss(recovered, true, new HexEncoder(new FileSink(out), false));
            } else {
                std::cerr << "Unknown format: " << format << "\n";
                return false;
            }

            std::cout << "Plaintext written to " << outFile << "\n";
        } else {
            std::cout << "\nRecovered plaintext:\n" << recovered << "\n";
        }

        return true;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
        return false;
    }
}
```
## Main Implementation
```cpp
int main(int argc, char* argv[]) {
    std::map<std::string, std::string> args = ParseCommandLine(argc, argv);

    if (args["--generate-keys"] == "true") {
        GenerateKeys(args);
    }
    else if (args["--encrypt"] == "true") {
        Encrypt(args);
    }
    else if (args["--decrypt"] == "true") {
        Decrypt(args);
    }
    else {
        DisplayHelp();
    }

    return 0;
}
```
