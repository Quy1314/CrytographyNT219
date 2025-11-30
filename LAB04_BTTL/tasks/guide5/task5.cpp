#include <iostream>
#include <string>
#include <map>
#include <vector>
#include <fstream>
#include <stdexcept>      // Cho std::runtime_error
#include <sstream>        // Cho std::istreambuf_iterator

// Crypto++ Headers
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>      // Cho CBC_Mode
#include <cryptopp/filters.h>    // Cho StringSource, StreamTransformationFilter, etc.
#include <cryptopp/cryptlib.h>   // Cho Exception, word32

using namespace CryptoPP;

// Khai báo sớm các hàm
void DisplayHelp();
bool GenerateKeys(const std::map<std::string, std::string>& args);
bool Encrypt(const std::map<std::string, std::string>& args);
bool Decrypt(const std::map<std::string, std::string>& args);
std::map<std::string, std::string> ParseCommandLine(int argc, char* argv[]);
template<class KEY>
void SaveKeyToDERFile(const KEY& key, const std::string& filename);
void DERToPEM(const std::string& derFilename, const std::string& pemFilename,
              const std::string& header, const std::string& footer);
RSA::PublicKey LoadPublicKey(const std::string& filename);
RSA::PrivateKey LoadPrivateKey(const std::string& filename);
std::string RSAEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey,
                       const std::string& paddingScheme);
std::string HybridEncrypt(const std::string& plaintext, const RSA::PublicKey& publicKey,
                          const std::string& paddingScheme);
std::string RSADecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey,
                       const std::string& paddingScheme);
std::string HybridDecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey);


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
        bool isOperation = false;
        for (const auto& op : operations) {
            if (arg == op) {
                args[op] = "true";
                isOperation = true;
                break; // Thoát vòng lặp bên trong
            }
        }
        if (isOperation) continue; // Chuyển sang đối số tiếp theo

        // Check if it's a flag option
        if (arg == "--hybrid") {
            args[arg] = "true";
            continue;
        }

        // Check if it's a value option
        if (i + 1 < argc && arg.substr(0, 2) == "--") {
            args[arg] = argv[i + 1];
            ++i;  // Skip the next argument (the value)
        } else if (arg.substr(0, 2) == "--") {
             // Xử lý trường hợp đối số có giá trị bị thiếu (như --input mà không có gì theo sau)
             // Hoặc đây có thể là một lỗi, nhưng chúng ta sẽ để trống giá trị
             args[arg] = "";
        }
    }

    return args;
}

// Function to display help message
void DisplayHelp() {
    std::cout << "Usage: rsa_tool [OPERATION] [OPTIONS]\n\n"
              << "OPERATIONS:\n"
              << "  --generate-keys    Generate RSA key pair\n"
              << "  --encrypt          Encrypt data\n"
              << "  --decrypt          Decrypt data\n\n"
              << "OPTIONS:\n"
              << "  --key-size SIZE    Key size in bits (default: 3072)\n"
              << "  --public-key FILE  Public key file (PEM or DER)\n"
              << "  --private-key FILE Private key file (PEM or DER)\n"
              << "  --input FILE       Input file (default: stdin)\n"
              << "  --output FILE      Output file (default: stdout)\n"
              << "  --format FORMAT    Output format: binary, base64, hex (default: binary)\n"
              << "  --padding PADDING  Padding scheme: pkcs1, oaep (default: oaep)\n"
              << "  --hybrid           Use hybrid encryption for large messages\n"
              << "  --help             Display this help message\n";
}

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
    if (!derFile) {
        throw std::runtime_error("Failed to open DER file: " + derFilename);
    }
    std::vector<char> derData((std::istreambuf_iterator<char>(derFile)),
                              std::istreambuf_iterator<char>());
    derFile.close();

    // Base64 encode
    std::string base64Data;
    StringSource ss(reinterpret_cast<const byte*>(derData.data()), derData.size(), true,
        new Base64Encoder(
            new StringSink(base64Data),
            true, 64 // true = insert line breaks, 64 = line length
        )
    );

    // Write PEM file
    std::ofstream pemFile(pemFilename);
    if (!pemFile) {
        throw std::runtime_error("Failed to open PEM file for writing: " + pemFilename);
    }
    pemFile << header << std::endl;
    pemFile << base64Data; // Base64Encoder đã thêm ngắt dòng
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
        publicKey.AssignFrom(privateKey); // Sử dụng AssignFrom thay vì constructor

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
            privateKeyDer = privateKeyPem + ".der_from_cmd"; // Đổi tên để tránh ghi đè nếu tên PEM không có .pem
        }

        if (args.find("--public-key") != args.end()) {
            publicKeyPem = args.at("--public-key");
            publicKeyDer = publicKeyPem + ".der_from_cmd";
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
        file.close(); // Đóng file sau khi đọc xong

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

        // If PEM loading failed or not PEM, try DER
        RSA::PublicKey publicKey;
        FileSource fs(filename.c_str(), true);
        publicKey.Load(fs);
        return publicKey;
    } catch (const Exception& e) {
        throw Exception(Exception::OTHER_ERROR, "Failed to load public key (" + filename + "): " + std::string(e.what()));
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
        file.close(); // Đóng file sau khi đọc xong

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

        // If PEM loading failed or not PEM, try DER
        RSA::PrivateKey privateKey;
        FileSource fs(filename.c_str(), true);
        privateKey.Load(fs);
        return privateKey;
    } catch (const Exception& e) {
        throw Exception(Exception::OTHER_ERROR, "Failed to load private key (" + filename + "): " + std::string(e.what()));
    }
}

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
                                 std::to_string(maxPlaintextLength) + " bytes. Use --hybrid for larger messages.");
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

    // Add the length of the encrypted key as a 4-byte integer (little-endian)
    word32 keyLength = static_cast<word32>(encryptedKey.size());
    // Đảm bảo lưu trữ ở dạng little-endian hoặc big-endian một cách nhất quán
    // Ở đây chúng ta chỉ lưu trữ 4 byte thô của word32
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
            std::cout << "Reading input from stdin (press Enter, then Ctrl+D or Ctrl+Z+Enter to finish)...\n";
            std::cin.unsetf(std::ios::skipws); // Đọc cả khoảng trắng
            std::string line;
            // Đọc tất cả từ cin vào inputData
            inputData.assign(std::istreambuf_iterator<char>(std::cin),
                             std::istreambuf_iterator<char>());

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
            // Mở file ở chế độ nhị phân cho tất cả các định dạng
            std::ofstream out(outFile, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to open output file: " << outFile << "\n";
                return false;
            }

            if (format == "binary") {
                out.write(ciphertext.data(), ciphertext.size());
            } else if (format == "base64") {
                // false ở cuối Base64Encoder nghĩa là không ngắt dòng
                StringSource ss(ciphertext, true, new Base64Encoder(new FileSink(out), false));
            } else if (format == "hex") {
                // false ở cuối HexEncoder nghĩa là không viết hoa
                StringSource ss(ciphertext, true, new HexEncoder(new FileSink(out), false));
            } else {
                std::cerr << "Unknown format: " << format << "\n";
                return false;
            }
            out.close(); // Đóng file
            std::cout << "Ciphertext written to " << outFile << "\n";
        } else {
            std::cout << "\nCiphertext (" << format << "):\n";
            if (format == "binary") {
                 // Không nên in dữ liệu nhị phân trực tiếp ra cout,
                 // thay vào đó, chuyển sang base64 để dễ xem
                std::cout << "[Binary data, redirect output to file or use base64/hex format]\n";
                // Hoặc: StringSource ss(ciphertext, true, new Base64Encoder(new FileSink(std::cout), true));
            } else if (format == "base64") {
                // true ở cuối Base64Encoder nghĩa là có ngắt dòng
                StringSource ss(ciphertext, true, new Base64Encoder(new FileSink(std::cout), true));
            } else {
                 // true ở cuối HexEncoder nghĩa là viết hoa
                StringSource ss(ciphertext, true, new HexEncoder(new FileSink(std::cout), true));
            }
            std::cout << "\n";
        }

        return true;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << "\n";
        return false;
    }
}

// Function for direct RSA decryption
std::string RSADecrypt(const std::string& ciphertext, const RSA::PrivateKey& privateKey,
                       const std::string& paddingScheme) {
    AutoSeededRandomPool rng;
    PK_Decryptor* decryptor = nullptr;

    if (paddingScheme == "pkcs1")
        decryptor = new RSAES_PKCS1v15_Decryptor(privateKey);
    else // Default to OAEP
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

    // Step 1: Extract encrypted key length (first 4 bytes, little-endian)
    const byte* data = reinterpret_cast<const byte*>(ciphertext.data());
    word32 keyLength = 0;
    // Đọc 4 byte dưới dạng word32 (giả sử cùng một endian-ness như khi lưu)
    std::memcpy(&keyLength, data, 4);


    if (ciphertext.size() < 4 + keyLength + AES::BLOCKSIZE) {
        throw std::runtime_error("Invalid ciphertext structure (length mismatch)");
    }

    // Step 2: Extract encrypted AES key, IV, and AES ciphertext
    const byte* encryptedKey = data + 4;
    const byte* iv = encryptedKey + keyLength;
    const byte* aesCipher = iv + AES::BLOCKSIZE;
    size_t aesCipherLen = ciphertext.size() - (4 + keyLength + AES::BLOCKSIZE);

    // Step 3: Decrypt AES key with RSA (OAEP-SHA256)
    // LƯU Ý: Giả định OAEP_SHA256 được sử dụng trong HybridEncrypt.
    // Nếu HybridEncrypt sử dụng PKCS1, thì ở đây cũng phải dùng PKCS1.
    // Để đơn giản, chúng ta giả định OAEP cho phần hybrid.
    std::string decryptedKey;
    RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);

    StringSource ss1(encryptedKey, keyLength, true,
        new PK_DecryptorFilter(rng, rsaDecryptor,
            new StringSink(decryptedKey)
        )
    );

    if (decryptedKey.size() != AES::DEFAULT_KEYLENGTH) {
         // Thử giải mã bằng PKCS1 phòng trường hợp
        try {
            RSAES_PKCS1v15_Decryptor rsaPkcsDecryptor(privateKey);
            StringSource ss_pkcs(encryptedKey, keyLength, true,
                new PK_DecryptorFilter(rng, rsaPkcsDecryptor,
                    new StringSink(decryptedKey)
                )
            );
        } catch (const Exception&) {
             // Nếu cả hai đều thất bại, ném lỗi ban đầu
             throw std::runtime_error("Decrypted AES key size mismatch (OAEP failed)");
        }

         if (decryptedKey.size() != AES::DEFAULT_KEYLENGTH) {
            throw std::runtime_error("Decrypted AES key size mismatch (OAEP and PKCS1 failed)");
         }
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

// Main decryption function
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
        std::string format = (args.find("--format") != args.end()) ? args.at("--format") : "binary";

        if (args.find("--input") != args.end()) {
            std::string inputFile = args.at("--input");
            std::cout << "Reading input from " << inputFile << "...\n";
            // Đọc file nhị phân
            FileSource fs(inputFile.c_str(), true, new StringSink(ciphertext), false); // false = không nhị phân? Thử true
            // Thử lại với true
            ciphertext.clear();
            FileSource fs_bin(inputFile.c_str(), true, new StringSink(ciphertext));


        } else {
            std::cout << "Reading input from stdin (press Enter, then Ctrl+D or Ctrl+Z+Enter to finish)...\n";
             std::cin.unsetf(std::ios::skipws);
             std::string inputData;
             inputData.assign(std::istreambuf_iterator<char>(std::cin),
                              std::istreambuf_iterator<char>());
             ciphertext = inputData;
        }

        // Decode if not binary
        if (format == "base64") {
            std::string decoded;
            StringSource ss(ciphertext, true, new Base64Decoder(new StringSink(decoded)));
            ciphertext = decoded;
        } else if (format == "hex") {
            std::string decoded;
            StringSource ss(ciphertext, true, new HexDecoder(new StringSink(decoded)));
            ciphertext = decoded;
        }
        // Nếu format là "binary", không cần làm gì

        if (ciphertext.empty()) {
            std::cerr << "Error: no ciphertext data provided or decoding failed\n";
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
        // Định dạng output không liên quan đến định dạng input
        std::string outFormat = (args.find("--format") != args.end()) ? args.at("--format") : "binary";

        if (args.find("--output") != args.end()) {
            std::string outFile = args.at("--output");
            std::ofstream out(outFile, std::ios::binary);
            if (!out) {
                std::cerr << "Failed to open output file: " << outFile << "\n";
                return false;
            }

            // Ghi dữ liệu đã giải mã (thường là văn bản)
            // Nếu người dùng muốn định dạng output là base64 hoặc hex?
            // Hướng dẫn không rõ ràng về việc định dạng output khi giải mã.
            // Giả sử --format áp dụng cho *input* khi giải mã và *output* khi mã hóa.
            // Khi giải mã, chúng ta sẽ xuất ra dạng thô (binary/text).
            out.write(recovered.data(), recovered.size());

            std::cout << "Plaintext written to " << outFile << "\n";
        } else {
            std::cout << "\nRecovered plaintext:\n" << recovered << "\n";
        }

        return true;
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << "\n";
        return false;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << "\n";
        return false;
    }
}

// Main Implementation
int main(int argc, char* argv[]) {
    if (argc == 1) { // Không có đối số nào được cung cấp
        DisplayHelp();
        return 0;
    }

    std::map<std::string, std::string> args = ParseCommandLine(argc, argv);

    if (args.count("--help")) {
         DisplayHelp();
    } else if (args.count("--generate-keys")) {
        GenerateKeys(args);
    } else if (args.count("--encrypt")) {
        Encrypt(args);
    } else if (args.count("--decrypt")) {
        Decrypt(args);
    } else {
        std::cout << "No valid operation specified.\n\n";
        DisplayHelp();
    }

    return 0;
}