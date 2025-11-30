#include <cryptlib.h>
#include <hex.h>
#include <base64.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <gcm.h>
#include <ccm.h>
#include <xts.h>
#include <files.h>
#include <osrng.h>
#include <iostream>
#include <string>
#include <fstream>
#include <algorithm>
#include <sha.h>
#include <vector>
#include <utility>
#include <cstdio>
#include <stdexcept>
#include <sstream>
#include <cctype>
#include <iomanip>

#undef byte

using namespace CryptoPP;
const std::streamsize limit = 16 * 1024;

// --- Khai báo hàm ---
void PrintHelp();
std::string HexToBytes(const std::string& hex);
std::string BytesToHex(const std::string& bytes);
std::string BytesToBase64(const std::string& bytes);
std::string Base64ToBytes(const std::string& b64);
std::string HextoBase64(const std::string& hex);
void WriteToFile(const std::string& filename, const std::string& data);
bool CheckEcbPolicy(const std::string& mode, const std::string& inputFile, bool allowecb);
std::string ReadFromFile(const std::string& filename);
void CheckEmptyKeyIVNonce(const std::string& mode, std::string& ivHex, std::string& inputKeyHex, std::string& nonceHex, const std::string& rkeyChosenStr, const std::string& rivStr, const std::string& rnonceStr, size_t& keyLenBits);
void DoEncryption(const std::string& mode, const std::string& inputData, const std::string& inputKeyHex, const std::string& ivHex, const std::string& nonceHex, const std::string& aadData, const std::string& encode, const std::string& outputFile, bool aead, bool verbose, bool usePadding = true);
void DoDecryption(const std::string& mode, const std::string& inputDataRaw, const std::string& inputKeyHex, const std::string& ivHex, const std::string& nonceHex, const std::string& aadData, const std::string& outputFile, bool aead, bool verbose, bool usePadding = true);
std::string Sha256Hash(const std::string& data);
std::string EscapeJsonString(const std::string& input);
void PersistIVKeyNonce(const std::string& filename, const std::string& ivHex, const std::string& nonceHex, const std::string& mode, bool aead, bool verbose, const std::string& encode, const std::string& aadData, const std::string& keyHex, const std::string& outputFile);
void modifyOutputFileExtension(std::string& filePath, const std::string& newExtension);
std::string trim(const std::string& str);
bool CheckNonceUsed(const std::string& filename, const std::string& ivOrNonceHexToCheck, const std::string& modeToCheck, bool verbose);
void StoreIVUsed(const std::string& filename, const std::string& ivOrNonceHex, const std::string& mode, bool verbose);

struct KatVector {
    std::string count;
    std::string KEY, IV, PLAINTEXT, AAD, CIPHERTEXT, TAG;
    bool FAIL;
    std::string OPERATION; 

    KatVector() : FAIL(false) {}
};
static void trim_kat(std::string &s);

static std::vector<KatVector> ParseKatRsp(const std::string& path);
void run_kat(const std::string& katFilePath, std::ofstream& csv, bool allowecb);


// --- Hàm Main ---
int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false);
    std::cin.tie(NULL);

    AutoSeededRandomPool prng;

    byte rkey128[16];
    byte rkey192[24];
    byte rkey256[32];
    byte riv[AES::BLOCKSIZE];
    byte rnonce[16];

    prng.GenerateBlock(rkey128, sizeof(rkey128));
    prng.GenerateBlock(rkey192, sizeof(rkey192));
    prng.GenerateBlock(rkey256, sizeof(rkey256));
    prng.GenerateBlock(riv, sizeof(riv));
    prng.GenerateBlock(rnonce, sizeof(rnonce));

    bool encrypt = false, decrypt = false, verbose = false, aead = false, allowecb = false;
    std::string inputText, inputFile, outputFile = "output.bin", keytextHex, keyfilehex, ivHex, nonceHex, aadFile, aadText, encode, mode, threadsNum, katPath;
    std::string keyLenStr = "256";
    size_t keyLenBits = 256;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") { PrintHelp(); return 0; }
        else if (arg == "--in" && i + 1 < argc) inputFile = argv[++i];
        else if (arg == "--text" && i + 1 < argc) inputText = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--key-hex" && i + 1 < argc) keytextHex = argv[++i];
        else if (arg == "--key" && i + 1 < argc) keyfilehex = argv[++i];
        else if (arg == "--keylen" && i + 1 < argc) keyLenStr = argv[++i];
        else if (arg == "--iv-hex" && i + 1 < argc) ivHex = argv[++i];
        else if (arg == "--nonce-hex" && i + 1 < argc) nonceHex = argv[++i];
        else if (arg == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (arg == "--aead") aead = true;
        else if (arg == "--aad" && i + 1 < argc) aadFile = argv[++i];
        else if (arg == "--aad-" && i + 1 < argc) aadText = argv[++i];
        else if (arg == "--encode" && i + 1 < argc) encode = argv[++i];
        else if (arg == "--encrypt") encrypt = true;
        else if (arg == "--decrypt") decrypt = true;
        else if (arg == "--verbose") verbose = true;
        else if (arg == "--allow-ecb") allowecb = true;
        else if (arg == "--threads" && i + 1 < argc) threadsNum = argv[++i];
        else if (arg == "--kat" && i + 1 < argc) katPath = argv[++i];
    }

    if (!encrypt && !decrypt && !katPath.empty()) {
        modifyOutputFileExtension(outputFile, ".bin");
    } else if (decrypt) {

    }
     else if (encrypt) {
         modifyOutputFileExtension(outputFile, ".bin");
     }


    if (!katPath.empty()) {
        std::string csvFilename = "mytool_kat_results.csv"; 
        try {
            std::ofstream katCsv(csvFilename); 
            if (!katCsv.is_open()) {
                std::cerr << "Error: Could not open KAT results file: " << csvFilename << std::endl;
                return 1;
            }
            katCsv << "filename,COUNT,operation,pass\n"; 
            run_kat(katPath, katCsv, allowecb); 
            katCsv.close(); 
            std::cout << "KAT results written to " << csvFilename << std::endl; 

        } catch (const std::exception& e) {
            std::cerr << "KAT execution failed: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    }

    std::transform(mode.begin(), mode.end(), mode.begin(), ::toupper);
    std::transform(encode.begin(), encode.end(), encode.begin(), ::tolower);
    std::transform(keytextHex.begin(), keytextHex.end(), keytextHex.begin(), ::toupper);
    std::transform(ivHex.begin(), ivHex.end(), ivHex.begin(), ::toupper);
    std::transform(nonceHex.begin(), nonceHex.end(), nonceHex.begin(), ::toupper);

     try {
        if (keyLenStr == "128") keyLenBits = 128;
        else if (keyLenStr == "192") keyLenBits = 192;
        else if (keyLenStr == "256") keyLenBits = 256;
        else {
             std::cerr << "Warning: Invalid --keylen (" << keyLenStr << "). Expected 128, 192, or 256. Defaulting to 256." << std::endl;
             keyLenBits = 256;
        }
    } catch (const std::invalid_argument& e) {
        std::cerr << "Warning: Invalid --keylen value '" << keyLenStr << "'. Using default 256 bits." << std::endl;
        keyLenBits = 256;
    } catch (const std::out_of_range& e) {
         std::cerr << "Warning: --keylen value '" << keyLenStr << "' out of range. Using default 256 bits." << std::endl;
         keyLenBits = 256;
    }


    if (inputFile.empty() && inputText.empty()) {
        std::cerr << "Error: must provide input via --in or --text\n";
        PrintHelp();
        return 1;
    }

    std::string inputData;
    if (!inputFile.empty()) {
        try {
            inputData = ReadFromFile(inputFile);
        } catch (const std::exception& e) {
             std::cerr << "Error reading input file: " << e.what() << std::endl;
            return 1;
        }
    } else {
        inputData = inputText;
    }

    std::string inputKey;
    if (keyfilehex.empty()) {
        inputKey = keytextHex;
    } else {
        try {
            inputKey = ReadFromFile(keyfilehex);
            inputKey.erase(std::remove_if(inputKey.begin(), inputKey.end(),
                [](char c) { return !std::isxdigit(c); }), inputKey.end());
            std::transform(inputKey.begin(), inputKey.end(), inputKey.begin(), ::toupper);
        } catch (const std::exception& e) {
             std::cerr << "Error reading key file: " << e.what() << std::endl;
            return 1;
        }
    }

    if (!encrypt && !decrypt && katPath.empty()) {
        std::cerr << "Error: must specify --encrypt, --decrypt, or --kat\n";
        PrintHelp();
        return 1;
    }

    if ((mode == "ECB") && encrypt) {
        std::cout << "WARNING: The ECB mode is insecure and should not be used for real-world applications." << std::endl;
        if (!CheckEcbPolicy(mode, inputFile, allowecb)) {
            return 1;
        }
    } else if ((mode == "ECB") && decrypt) {
        std::cout << "WARNING: The ECB mode is insecure and should not be used for real-world applications." << std::endl;
    }

    std::string aadData;
    if (aead) {
        if (!aadFile.empty()) {
            try {
                aadData = ReadFromFile(aadFile);
            } catch (const std::exception& e) {
                std::cerr << "Error: failed to read AAD file '" << aadFile << "': " << e.what() << std::endl;
                return 1;
            }
        } else if (!aadText.empty()) {
            aadData = aadText;
        }
    }

    std::string rkey128Str(reinterpret_cast<const char*>(rkey128), sizeof(rkey128));
    std::string rkey192Str(reinterpret_cast<const char*>(rkey192), sizeof(rkey192));
    std::string rkey256Str(reinterpret_cast<const char*>(rkey256), sizeof(rkey256));
    std::string rivStr(reinterpret_cast<const char*>(riv), sizeof(riv));
    std::string rnonceStr(reinterpret_cast<const char*>(rnonce), sizeof(rnonce));

    std::string rkeyChosenStr;
    if (keyLenBits == 128) rkeyChosenStr = rkey128Str;
    else if (keyLenBits == 192) rkeyChosenStr = rkey192Str;
    else rkeyChosenStr = rkey256Str;
     

    try {
        CheckEmptyKeyIVNonce(mode, ivHex, inputKey, nonceHex, rkeyChosenStr, rivStr, rnonceStr, keyLenBits);
    } catch (const std::exception& e) {
        std::cerr << "Error during parameter validation: " << e.what() << std::endl;
        return 1;
    }

    try {
        if (encrypt) {
             std::string persistFile = outputFile + ".meta.json";
             std::string IVstorageFile = "IVstored.bin";

            std::string valueToCheckAndStore;
            if (mode == "CTR") {
                valueToCheckAndStore = ivHex;
            } else if (mode == "GCM" || mode == "CCM") {
                valueToCheckAndStore = nonceHex;
            }

            if (!valueToCheckAndStore.empty() && (mode == "CTR" || mode == "GCM" || mode == "CCM")) {
                 if (!CheckNonceUsed(IVstorageFile, valueToCheckAndStore, mode, verbose)) {
                     return 1;
                 }
            }

            if (verbose) {
                std::cout << "[+] Encrypt mode: " << mode << "\n";
                if (!inputFile.empty()) std::cout << "[+] Input file:   " << inputFile << "\n";
                else std::cout << "[+] Input text size: " << inputData.length() << " bytes\n";
                std::cout << "[+] Output file:  " << outputFile << "\n";
                 std::cout << "[+] Key Length:   " << keyLenBits << " bits\n";
                std::cout << "[+] Key:          " << inputKey << "\n";
                if ((mode == "GCM" || mode == "CCM") && aead) {
                    std::cout << "[+] Nonce:        " << nonceHex << "\n";
                    if (!aadData.empty())
                        std::cout << "[+] AAD size:     " << aadData.length() << " bytes\n";
                } else if (mode != "ECB") {
                    std::cout << "[+] IV:           " << ivHex << "\n";
                }
                 std::cout << "[+] Encoding:     " << (encode.empty() ? "raw" : encode) << "\n";
            }
            DoEncryption(mode, inputData, inputKey, ivHex, nonceHex, aadData, encode, outputFile, aead, verbose);

             if (!valueToCheckAndStore.empty() && (mode == "CTR" || mode == "GCM" || mode == "CCM")) {
                 StoreIVUsed(IVstorageFile, valueToCheckAndStore, mode, verbose);
             }

            PersistIVKeyNonce(persistFile, ivHex, nonceHex, mode, aead, verbose, encode, aadData, inputKey, outputFile);

             if(verbose) {
                std::cout << "Encryption completed successfully." << std::endl;
                std::cout << "Output written to " << outputFile << std::endl;
                std::cout << "Metadata sidecar written to " << persistFile << std::endl;
                if (mode == "CTR" || mode == "GCM" || mode == "CCM")
                     std::cout << "IV/Nonce usage recorded in " << IVstorageFile << std::endl;
            } else {
                 std::cout << "Encryption completed." << std::endl;
            }
        } else if (decrypt) {
             std::string rawInputData;
             try {
                if (encode == "hex") {
                    rawInputData = HexToBytes(inputData);
                } else if (encode == "base64") {
                    rawInputData = Base64ToBytes(inputData);
                } else {
                     if (!encode.empty() && encode != "raw") {
                         std::cerr << "Warning: Unrecognized encoding '" << encode << "', assuming raw input." << std::endl;
                     }
                    rawInputData = inputData;
                }
             } catch (const std::exception& e) {
                 std::cerr << "Error decoding input data: " << e.what() << std::endl;
                 return 1;
             }

             std::string outputPlaintextfile = outputFile;
             modifyOutputFileExtension(outputPlaintextfile, ".txt");

            if (verbose) {
                 std::cout << "[+] Decrypt mode: " << mode << "\n";
                 if (!inputFile.empty()) std::cout << "[+] Input file:   " << inputFile << "\n";
                 else std::cout << "[+] Input size (" << (encode.empty() ? "raw" : encode) << "): " << inputData.length() << " chars/bytes\n";
                 std::cout << "[+] Output file:  " << outputPlaintextfile << "\n";
                 std::cout << "[+] Key Length:   " << keyLenBits << " bits\n";
                 std::cout << "[+] Key:          " << inputKey << "\n";
                 if ((mode == "GCM" || mode == "CCM") && aead) {
                     std::cout << "[+] Nonce:        " << nonceHex << "\n";
                     if (!aadData.empty())
                         std::cout << "[+] AAD size:     " << aadData.length() << " bytes\n";
                 } else if (mode != "ECB") {
                     std::cout << "[+] IV:           " << ivHex << "\n";
                 }
            }

            DoDecryption(mode, rawInputData, inputKey, ivHex, nonceHex, aadData, outputPlaintextfile, aead, verbose);

            if (verbose) {
                 std::cout << "Decryption completed successfully." << std::endl;
                 std::cout << "Plaintext written to " << outputPlaintextfile << std::endl;
            } else {
                 std::cout << "Decryption completed." << std::endl;
            }
        }

    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}


// --- Các hàm phụ ---

void PrintHelp() { 
    std::cout <<
R"(mytool - AES CLI (Crypto++ backend)
===================================

Usage:
  mytool <command> [--in INFILE | --text "..."] [--out OUTFILE]
         [--key KEYFILE | --key-hex HEX] [--keylen BITS]
         [--iv-hex IV-hex] [--nonce-hex NONCE-hex]
         [--mode MODE] [--aead] [--aad FILE | --aad- "..."]
         [--encode hex|base64|raw] [--threads N] [--allow-ecb]
         [--kat path/to/vectors.rsp] [--verbose] [--help]

Commands:
  --encrypt            Encrypt input (use --in or --text)
  --decrypt            Decrypt input (use --in or --text)
  --kat PATH           Run Known Answer Tests from the specified .rsp file and exit.

Options:
  --in INFILE          Input file path.
  --text "..."         Input text provided inline.
  --out OUTFILE        Output file (default: output.bin, always forced to .bin for encrypt).

  --key KEYFILE        Read key from a file (hex content).
  --key-hex HEX        Key given as hex string.
                       (Use --key OR --key-hex)
  --keylen BITS        Key length in bits: 128, 192, or 256. (Default: 256).
                       For XTS mode: 128 (for XTS-AES-128) or 256 (for XTS-AES-256).

  --iv-hex IV-hex      IV (hex). Required for non-ECB modes (incl. XTS). Default: Random.
  --nonce-hex NONCE-hex Nonce (hex). Required for GCM/CCM modes. Default: Random.

  --mode MODE          AES mode: ECB | CBC | CFB | OFB | CTR | GCM | CCM | XTS
  --aead               Treat mode as AEAD (for GCM/CCM).
  --aad FILE           Additional Authenticated Data (AAD) from file (for GCM/CCM).
  --aad- "..."         Additional Authenticated Data (AAD) from inline text (for GCM/CCM).

  --encode VALUE       Encoding for output (--encrypt) / input (--decrypt):
                       hex | base64 | raw (default: raw for output, expects same for input)

  --threads N          Number of threads (optional, not currently implemented).

  --allow-ecb          Allow ECB mode on files larger than 16 KiB (Insecure!).
  --verbose            Verbose output (show parameters and steps).
  --help               Show this help message and exit.

Notes:
  - Must specify --encrypt, --decrypt, or --kat.
  - Use either --in (file) OR --text (inline) for encrypt/decrypt.
  - Key lengths (--keylen) determine AES variant.
  - Corresponding hex key (--key-hex) lengths: 128b=32, 192b=48, 256b=64.
  - XTS key lengths (--keylen): 128 uses 64 hex, 256 uses 128 hex.
  - IV/Nonce length: IV=16B(32 hex). Nonce varies (GCM best 12B/24 hex, CCM 7-13B/14-26 hex).
  - Encryption creates/appends to a sidecar file '.meta.json'.
  - IV/Nonce usage for CTR/GCM/CCM is logged to 'IVstored.bin'.
)";
}
std::string HexToBytes(const std::string& hex) { 
    std::string bytes;
    try {
        StringSource(hex, true,
            new HexDecoder(
                new StringSink(bytes)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Hex decoding failed for '" + hex + "': " + e.what());
    }
    return bytes;
}
std::string BytesToHex(const std::string& bytes) { 
    std::string hex;
    StringSource(bytes, true,
        new HexEncoder(
            new StringSink(hex),
            false
        )
    );
    return hex;
}
std::string BytesToBase64(const std::string& bytes) { 
    std::string b64;
    StringSource(bytes, true,
        new Base64Encoder(
            new StringSink(b64),
            false
        )
    );
    return b64;
}
std::string Base64ToBytes(const std::string& b64) { 
    std::string bytes;
     try {
        StringSource(b64, true,
            new Base64Decoder(
                new StringSink(bytes)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Base64 decoding failed for '" + b64 + "': " + e.what());
    }
    return bytes;
}
std::string HextoBase64(const std::string& hex) { 
    std::string bytes = HexToBytes(hex);
    return BytesToBase64(bytes);
}
void WriteToFile(const std::string& filename, const std::string& data) { 
    try {
        FileSink file(filename.c_str());
        file.Put(reinterpret_cast<const byte*>(data.data()), data.size());
        file.MessageEnd();
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("File write error (" + filename + "): " + e.what());
    }
}
bool CheckEcbPolicy(const std::string& mode, const std::string& inputFile, bool allowecb) { 
    if (mode != "ECB" || inputFile.empty()) {
        return true;
    }
    std::ifstream file(inputFile, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open input file '" << inputFile << "' to check its size.\n";
        return false;
    }
    std::streamsize fileSize = file.tellg();
    file.close();

    if (fileSize > limit && !allowecb) {
        std::cerr << "ERROR: Input file is larger than " << (limit / 1024) << " KiB.\n";
        std::cerr << "Using ECB mode on large files is insecure as it does not hide data patterns.\n";
        std::cerr << "To proceed anyway, please add the '--allow-ecb' flag.\n";
        return false;
    }
    return true;
}
std::string ReadFromFile(const std::string& filename) { 
    std::string data;
    try {
        FileSource file(filename.c_str(), true, new StringSink(data));
    } catch (const CryptoPP::FileStore::OpenErr& e) {
         throw std::runtime_error("File read error: Could not open file '" + filename + "'. " + e.what());
    }
    catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("File read error (" + filename + "): " + e.what());
    }
    return data;
}
void CheckEmptyKeyIVNonce(const std::string& mode, std::string& ivHex, std::string& inputKeyHex, std::string& nonceHex, const std::string& rkeyChosenStr, const std::string& rivStr, const std::string& rnonceStr, size_t& keyLenBits) { 
    bool isXTS = (mode == "XTS");
    size_t expectedKeyLenBytes = keyLenBits / 8;
    size_t expectedKeyLenHex = expectedKeyLenBytes * 2;

    if (inputKeyHex.empty()) {
        inputKeyHex = BytesToHex(rkeyChosenStr);
        if (inputKeyHex.length() > expectedKeyLenHex) {
            inputKeyHex.resize(expectedKeyLenHex);
        } else if (inputKeyHex.length() < expectedKeyLenHex) {
             throw std::runtime_error("Internal error: Generated random key is too short.");
        }

        if (!inputKeyHex.empty()) {
             std::cout << "Missing key, generated random key (" << keyLenBits << " bits";
             std::cout << ", hex): " << inputKeyHex << std::endl;
        } else {
             throw std::runtime_error("Failed to generate random key hex.");
        }
    }
    else {
        if (inputKeyHex.length() % 2 != 0) {
            throw std::runtime_error("Invalid key hex length (" + std::to_string(inputKeyHex.length()) + "). Must be an even number.");
        }
        size_t keyLenBytesProvided = inputKeyHex.length() / 2;

        if (keyLenBytesProvided != expectedKeyLenBytes) {
             throw std::runtime_error("Provided key hex length (" + std::to_string(inputKeyHex.length()) +
                                      ") does not match the expected length for " + std::to_string(keyLenBits) + "-bit key in " +
                                      mode + " mode (" + std::to_string(expectedKeyLenHex) + " hex chars / " +
                                      std::to_string(expectedKeyLenBytes) + " bytes).");
        }
    }

    if (mode != "ECB" && !(mode == "GCM" || mode == "CCM")) {
        if (ivHex.empty()) {
            ivHex = BytesToHex(rivStr);
            if (!ivHex.empty()) {
                std::cout << "Missing IV for mode " << mode << ", generated random IV (hex): " << ivHex << std::endl;
            } else {
                throw std::runtime_error("Failed to generate random IV hex.");
            }
        }
        else {
            if (ivHex.length() % 2 != 0) {
                 throw std::runtime_error("Invalid IV hex length (" + std::to_string(ivHex.length()) + "). Must be an even number.");
            }
            size_t ivLenBytes = ivHex.length() / 2;
            if (ivLenBytes != AES::BLOCKSIZE) {
                throw std::runtime_error("Invalid IV hex length (" + std::to_string(ivHex.length()) + ") for mode " + mode + ". Expected " + std::to_string(2 * AES::BLOCKSIZE) + " (" + std::to_string(AES::BLOCKSIZE) + " bytes).");
            }
        }
    }

    if (mode == "GCM" || mode == "CCM") {
        if (nonceHex.empty()) {
            nonceHex = BytesToHex(rnonceStr);
            if (nonceHex.length() > 24) nonceHex.resize(24);
            if (!nonceHex.empty()) {
                std::cout << "Missing Nonce for mode " << mode << ", generated random 12-byte Nonce (hex): " << nonceHex << std::endl;
            } else {
                 throw std::runtime_error("Failed to generate random Nonce hex.");
            }
        }
        else {
             if ((mode == "GCM") && nonceHex.length() != 24) {
                 std::cerr << "Warning: Nonce length (" << nonceHex.length() << " hex chars) is not the recommended 12 bytes (24 hex chars) for GCM performance and security." << std::endl;
             }
             else if ((mode == "CCM") && (nonceHex.length() < 14 || nonceHex.length() > 26) ) {
                 std::cerr << "Warning: Nonce length (" << nonceHex.length() << " hex chars) is outside the typical 7-13 byte range (14-26 hex chars) for CCM." << std::endl;
             }
        }
    }
}
std::string Sha256Hash(const std::string& data) { 
    SHA256 hash;
    std::string digest;
    StringSource(data, true,
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest),
                false
            )
        )
    );
    return digest;
}
std::string EscapeJsonString(const std::string& input) { 
    std::string output;
    output.reserve(input.length());
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b";  break;
            case '\f': output += "\\f";  break;
            case '\n': output += "\\n";  break;
            case '\r': output += "\\r";  break;
            case '\t': output += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) <= 0x1F) {
                    char buffer[7];
                    snprintf(buffer, sizeof(buffer), "\\u%04X", static_cast<unsigned char>(c));
                    output += buffer;
                } else {
                    output += c;
                }
                break;
        }
    }
    return output;
}
void PersistIVKeyNonce(const std::string& filename, const std::string& ivHex, const std::string& nonceHex, const std::string& mode, bool aead, bool verbose, const std::string& encode, const std::string& aadData, const std::string& keyHex, const std::string& outputFile) { 
    std::string existingContent;
    std::ifstream readFile(filename);
    if (readFile) {
        existingContent.assign((std::istreambuf_iterator<char>(readFile)), std::istreambuf_iterator<char>());
        readFile.close();
    }

    std::ofstream jsonFile(filename);
    if (!jsonFile.is_open()) {
        std::cerr << "Warning: Could not open sidecar file '" << filename << "' for writing." << std::endl;
        return;
    }

    std::string keyBytes = HexToBytes(keyHex);
    std::string keyHash = Sha256Hash(keyBytes);
    std::string aadHash;
    if (aead && !aadData.empty()) {
        aadHash = Sha256Hash(aadData);
    }
    std::string effectiveEncode = encode.empty() ? "raw" : encode;

    size_t keyLenBytes = keyBytes.length();
    std::string keyLenStr;
    if (keyLenBytes == 16) keyLenStr = "128";
    else if (keyLenBytes == 24) keyLenStr = "192";
    else if (keyLenBytes == 32) keyLenStr = "256";
    else keyLenStr = "Unknown";
    
    std::string algorithmStr = "AES-" + keyLenStr + "-" + mode;


    std::string newObject = "  {\n";
    newObject += "    \"algorithm\": \"" + EscapeJsonString(algorithmStr) + "\",\n";
    newObject += "    \"operation_mode\": \"" + EscapeJsonString(mode) + "\",\n";
    newObject += "    \"aead_enabled\": " + std::string(aead ? "true" : "false") + ",\n";
    newObject += "    \"output_file\": \"" + EscapeJsonString(outputFile) + "\",\n";
    newObject += "    \"output_encoding\": \"" + EscapeJsonString(effectiveEncode) + "\",\n";

    if (mode == "GCM" || mode == "CCM") {
        if (!nonceHex.empty()) newObject += "    \"nonce_hex\": \"" + EscapeJsonString(nonceHex) + "\",\n";
    } else if (mode != "ECB") {
       if (!ivHex.empty()) newObject += "    \"iv_hex\": \"" + EscapeJsonString(ivHex) + "\",\n";
    }

    newObject += "    \"key_hash_sha256\": \"" + EscapeJsonString(keyHash) + "\"";

    if (!aadHash.empty()) {
        newObject += ",\n    \"aad_data_hash_sha256\": \"" + EscapeJsonString(aadHash) + "\"";
    }
    newObject += "\n  }";

    std::string finalJson;
    if (existingContent.empty()) {
        finalJson = "[\n" + newObject + "\n]";
    } else {
        size_t lastBracketPos = existingContent.find_last_of(']');
        if (lastBracketPos == std::string::npos) {
            std::cerr << "Warning: Existing sidecar file '" << filename << "' has invalid format. Overwriting with new entry." << std::endl;
            finalJson = "[\n" + newObject + "\n]";
        } else {
             std::string contentBeforeLastBracket = existingContent.substr(0, lastBracketPos);
             while (!contentBeforeLastBracket.empty() && std::isspace(contentBeforeLastBracket.back())) {
                contentBeforeLastBracket.pop_back();
             }
              if (contentBeforeLastBracket.find_last_of('}') != std::string::npos) {
                  finalJson = contentBeforeLastBracket + ",\n" + newObject + "\n]";
              } else {
                   finalJson = contentBeforeLastBracket + "\n" + newObject + "\n]";
              }
        }
    }

    jsonFile << finalJson;
    jsonFile.close();
}
void DoEncryption(const std::string& mode, const std::string& inputData, const std::string& inputKeyHex, const std::string& ivHex, const std::string& nonceHex, const std::string& aadData, const std::string& encode, const std::string& outputFile, bool aead, bool verbose, bool usePadding /*= true*/) { 
    std::string ciphertext_raw;
    std::string key = HexToBytes(inputKeyHex);
    std::string iv;
    std::string nonce;

    try {
        if (mode == "ECB") {
            ECB_Mode<AES>::Encryption encryptor;
            encryptor.SetKey((const byte*)key.data(), key.size());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw),
                    usePadding ? StreamTransformationFilter::PKCS_PADDING : StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else if (mode == "CBC") {
            iv = HexToBytes(ivHex);
            CBC_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw),
                     usePadding ? StreamTransformationFilter::PKCS_PADDING : StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else if (mode == "CFB") {
            iv = HexToBytes(ivHex);
            CFB_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw)
                )
            );
        }
        else if (mode == "OFB") {
             iv = HexToBytes(ivHex);
            OFB_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw)
                )
            );
        }
        else if (mode == "CTR") {
             iv = HexToBytes(ivHex);
            CTR_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw)
                )
            );
        }
        else if (mode == "GCM") {
            nonce = HexToBytes(nonceHex);
            const int TAG_SIZE = 16;
            GCM<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)nonce.data(), nonce.size());
            AuthenticatedEncryptionFilter ef(encryptor,
                new StringSink(ciphertext_raw), false, TAG_SIZE, "",
                AuthenticatedEncryptionFilter::NO_PADDING
            );
            ef.ChannelPut("AAD", (const byte*)aadData.data(), aadData.size());
            ef.ChannelMessageEnd("AAD");
            ef.ChannelPut("", (const byte*)inputData.data(), inputData.size());
            ef.ChannelMessageEnd("");
        }
        else if (mode == "CCM") {
            nonce = HexToBytes(nonceHex);
            const int TAG_SIZE = 8;
            CCM<AES, TAG_SIZE>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)nonce.data(), nonce.size());
            encryptor.SpecifyDataLengths(aadData.size(), inputData.size(), 0);
            AuthenticatedEncryptionFilter ef(encryptor,
                new StringSink(ciphertext_raw), false, TAG_SIZE, "",
                 AuthenticatedEncryptionFilter::NO_PADDING
            );
            ef.ChannelPut("AAD", (const byte*)aadData.data(), aadData.size());
             ef.ChannelMessageEnd("AAD");
            ef.ChannelPut("", (const byte*)inputData.data(), inputData.size());
            ef.ChannelMessageEnd("");
        }
        else if (mode == "XTS") {
            iv = HexToBytes(ivHex);
            XTS_Mode<AES>::Encryption encryptor;
            encryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(inputData, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext_raw),
                    StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else {
            throw std::runtime_error("Unsupported encryption mode: " + mode);
        }

        std::string data_to_write;
        if (encode == "hex") {
            data_to_write = BytesToHex(ciphertext_raw);
             std::ofstream outFile(outputFile);
             if (!outFile) throw std::runtime_error("Cannot open output file for writing: " + outputFile);
             outFile << data_to_write;
             outFile.close();

        } else if (encode == "base64") {
            data_to_write = BytesToBase64(ciphertext_raw);
             std::ofstream outFile(outputFile);
             if (!outFile) throw std::runtime_error("Cannot open output file for writing: " + outputFile);
             outFile << data_to_write;
             outFile.close();
        } else {
            data_to_write = ciphertext_raw;

            std::ofstream outFile(outputFile, std::ios::binary);
            if (!outFile) {
                throw std::runtime_error("Cannot open output file for binary writing: " + outputFile);
            }

            if (mode != "ECB") {
                if (mode == "GCM" || mode == "CCM") {
                     if (!nonceHex.empty()) {
                        std::string nonceBytes = HexToBytes(nonceHex);
                        outFile.write(nonceBytes.data(), nonceBytes.size());
                     }
                } else {
                     if (!ivHex.empty()) {
                        std::string ivBytes = HexToBytes(ivHex);
                        outFile.write(ivBytes.data(), ivBytes.size());
                     }
                }
            }

            outFile.write(data_to_write.data(), data_to_write.size());
            outFile.close();
        }

    } catch (const CryptoPP::InvalidArgument& e) {
        std::string errorMsg = "Crypto++ Invalid Argument Error during encryption: ";
        errorMsg += e.what();
        if (mode == "GCM" || mode == "CCM") errorMsg += " (Check nonce length? GCM usually 12 bytes, CCM 7-13 bytes)";
        else if (mode == "XTS") errorMsg += " (Check key length? Expected 32 or 64 bytes total. Check IV length? Expected 16 bytes)";
        else if (mode != "ECB") errorMsg += " (Check IV length? Should be " + std::to_string(AES::BLOCKSIZE) + " bytes)";
        throw std::runtime_error(errorMsg);
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Crypto++ Error during encryption: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw;
    }
}
void DoDecryption(const std::string& mode, const std::string& inputDataRaw, const std::string& inputKeyHex, const std::string& ivHex, const std::string& nonceHex, const std::string& aadData, const std::string& outputFile, bool aead, bool verbose, bool usePadding /*= true*/) { 
    std::string plaintext;
    std::string key = HexToBytes(inputKeyHex);
    std::string iv;
    std::string nonce;
    std::string ciphertext = inputDataRaw;

    try {
        size_t header_size = 0; 
        if ((mode != "ECB") && (ivHex.empty() && nonceHex.empty())) {
            if (mode == "GCM" || mode == "CCM") {
                size_t expected_nonce_bytes = 12;
                if (mode == "CCM") {
                     expected_nonce_bytes = 12;
                }
                 if (ciphertext.length() >= expected_nonce_bytes) {
                    nonce = ciphertext.substr(0, expected_nonce_bytes);
                    ciphertext = ciphertext.substr(expected_nonce_bytes);
                    header_size = expected_nonce_bytes;
                 } else {
                     throw std::runtime_error("Input data too short to contain expected Nonce header for raw mode.");
                 }

            } else {
                if (ciphertext.length() >= AES::BLOCKSIZE) {
                    iv = ciphertext.substr(0, AES::BLOCKSIZE);
                    ciphertext = ciphertext.substr(AES::BLOCKSIZE);
                    header_size = AES::BLOCKSIZE;
                 } else {
                      throw std::runtime_error("Input data too short to contain expected IV header for raw mode.");
                 }
            }
        } else {
            if (mode == "GCM" || mode == "CCM") {
                 nonce = HexToBytes(nonceHex);
            } else if (mode != "ECB") {
                 iv = HexToBytes(ivHex);
            }
        }


        if (mode == "ECB") {
            ECB_Mode<AES>::Decryption decryptor;
            decryptor.SetKey((const byte*)key.data(), key.size());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext),
                    usePadding ? StreamTransformationFilter::PKCS_PADDING : StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else if (mode == "CBC") {
            CBC_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext),
                    usePadding ? StreamTransformationFilter::PKCS_PADDING : StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else if (mode == "CFB") {
            CFB_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext)
                )
            );
        }
        else if (mode == "OFB") {
            OFB_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext)
                )
            );
        }
        else if (mode == "CTR") {
            CTR_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext)
                )
            );
        }
        else if (mode == "GCM") {
            const int TAG_SIZE = 16;
            GCM<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)nonce.data(), nonce.size());

            AuthenticatedDecryptionFilter df(decryptor,
                new StringSink(plaintext),
                AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END,
                TAG_SIZE
            );

            df.ChannelPut("AAD", (const byte*)aadData.data(), aadData.size());
            df.ChannelMessageEnd("AAD");


            df.ChannelPut("", (const byte*)ciphertext.data(), ciphertext.size());
            df.ChannelMessageEnd("");

        }
        else if (mode == "CCM") {
            const int TAG_SIZE = 8;
            CCM<AES, TAG_SIZE>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)nonce.data(), nonce.size());

             size_t ciphertextLen = ciphertext.size() - TAG_SIZE;
             if (ciphertext.size() < TAG_SIZE) {
                 throw std::runtime_error("CCM Error: Input data is shorter than the expected tag size.");
             }
            decryptor.SpecifyDataLengths(aadData.size(), ciphertextLen, 0);

            AuthenticatedDecryptionFilter df(decryptor,
                new StringSink(plaintext),
                 AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END,
                 TAG_SIZE
            );

            df.ChannelPut("AAD", (const byte*)aadData.data(), aadData.size());
            df.ChannelMessageEnd("AAD");

            df.ChannelPut("", (const byte*)ciphertext.data(), ciphertext.size());
            df.ChannelMessageEnd("");

        }
        else if (mode == "XTS") {
            XTS_Mode<AES>::Decryption decryptor;
            decryptor.SetKeyWithIV((const byte*)key.data(), key.size(), (const byte*)iv.data());
            StringSource ss(ciphertext, true,
                new StreamTransformationFilter(decryptor,
                    new StringSink(plaintext),
                    StreamTransformationFilter::NO_PADDING
                )
            );
        }
        else {
             throw std::runtime_error("Unsupported decryption mode: " + mode);
        }

        WriteToFile(outputFile, plaintext);

    } catch (const CryptoPP::InvalidArgument& e) {
        std::string errorMsg = "Crypto++ Invalid Argument Error during decryption: ";
        errorMsg += e.what();
         if (mode == "GCM" || mode == "CCM") errorMsg += " (Check nonce length/format?)";
         else if (mode == "XTS") errorMsg += " (Check key length? Expected 32 or 64 bytes total. Check IV length? Expected 16 bytes)";
         else if (mode != "ECB") errorMsg += " (Check IV length? Should be " + std::to_string(AES::BLOCKSIZE) + " bytes)";
        throw std::runtime_error(errorMsg);
    } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
        throw std::runtime_error("Decryption failed: Data integrity check (authentication tag) mismatch. " + std::string(e.what()));
    } catch (const CryptoPP::Exception& e) {
        throw std::runtime_error("Crypto++ Error during decryption: " + std::string(e.what()));
    } catch (const std::exception& e) {
        throw;
    }
}
void modifyOutputFileExtension(std::string& filePath, const std::string& newExtension) { 
    size_t pos = filePath.find_last_of('.');
    if (pos != std::string::npos) {
        filePath.replace(pos, std::string::npos, newExtension);
    } else {
        filePath += newExtension;
    }
}
std::string trim(const std::string& str) { 
    size_t first = str.find_first_not_of(" \t\n\r\f\v");
    if (std::string::npos == first) {
        return str;
    }
    size_t last = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(first, (last - first + 1));
}
bool CheckNonceUsed(const std::string& filename, const std::string& ivOrNonceHexToCheck, const std::string& modeToCheck, bool verbose) { 
    if (modeToCheck != "CTR" && modeToCheck != "CCM" && modeToCheck != "GCM") {
        return true;
    }

    std::ifstream ivFile(filename);
    if (!ivFile.is_open()) {
        return true;
    }

    std::string line;
    int lineNumber = 0;
    std::string upperModeToCheck = modeToCheck;
    std::transform(upperModeToCheck.begin(), upperModeToCheck.end(), upperModeToCheck.begin(), ::toupper);
    std::string upperIvOrNonceToCheck = ivOrNonceHexToCheck;
    std::transform(upperIvOrNonceToCheck.begin(), upperIvOrNonceToCheck.end(), upperIvOrNonceToCheck.begin(), ::toupper);

    std::string expectedLabel = (upperModeToCheck == "CTR") ? "IV: " : "Nonce: ";
    size_t expectedLabelLen = expectedLabel.length();

    while (std::getline(ivFile, line)) {
        lineNumber++;

        size_t modePos = line.find("Mode: ");
        if (modePos == std::string::npos) {
            continue;
        }

        size_t commaPos = line.find(',', modePos + 6);
        if (commaPos == std::string::npos) {
             continue;
        }

        std::string storedModeStr = line.substr(modePos + 6, commaPos - (modePos + 6));
        storedModeStr = trim(storedModeStr);
        std::transform(storedModeStr.begin(), storedModeStr.end(), storedModeStr.begin(), ::toupper);

        if (storedModeStr != upperModeToCheck) {
            continue;
        }

        size_t labelPos = line.find(expectedLabel, commaPos);
        if (labelPos == std::string::npos) {
            continue;
        }

        std::string storedIVHexStr = line.substr(labelPos + expectedLabelLen);
        storedIVHexStr = trim(storedIVHexStr);
        std::transform(storedIVHexStr.begin(), storedIVHexStr.end(), storedIVHexStr.begin(), ::toupper);

        if (storedIVHexStr == upperIvOrNonceToCheck) {
            ivFile.close();
            std::cerr << "ERROR: Nonce/IV already has been reused!" << std::endl;
            std::cerr << "Reused " << (modeToCheck == "CTR" ? "IV" : "Nonce") << ": " << ivOrNonceHexToCheck << std::endl;
            return false;
        }
    }

    ivFile.close();
    return true;
}
void StoreIVUsed(const std::string& filename, const std::string& ivOrNonceHex, const std::string& mode, bool verbose) { 
    if (mode != "CTR" && mode != "CCM" && mode != "GCM") {
        return;
    }
    std::ofstream ivFile(filename, std::ios::app);
    if (!ivFile.is_open()) {
         std::cerr << "Warning: Could not open IV/Nonce log file '" << filename << "' for appending." << std::endl;
        return;
    }
    ivFile << "Mode: " << mode << (mode == "CTR" ? ", IV: " : ", Nonce: ") << ivOrNonceHex << "\n";
    ivFile.close();
}
static void trim_kat(std::string &s) { 
    size_t a = 0; while (a < s.size() && std::isspace((unsigned char)s[a])) ++a;
    size_t b = s.size(); while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    s = s.substr(a, b - a);
}

// --- MODIFIED: Nâng cấp hàm parser ---
static std::vector<KatVector> ParseKatRsp(const std::string& path) {
    std::string text;
    try { FileSource fs(path.c_str(), true, new StringSink(text)); }
    catch(...) {
        std::cerr << "Error reading KAT file: " << path << std::endl;
        return {};
     }
    std::istringstream iss(text);
    std::string line;
    std::vector<KatVector> list;
    KatVector cur;
    bool inDataBlock = false; 
    std::string currentOperation = ""; // Lưu trữ [ENCRYPT], [DECRYPT], v.v.

    while (std::getline(iss, line)) {
        trim_kat(line);
        if (line.empty() || line[0]=='#') continue;

        if (line[0] == '[') {
             // Tiêu đề [ENCRYPT]... vẫn giữ nguyên (case-sensitive)
             if (line == "[ENCRYPT]") currentOperation = "ENCRYPT";
             else if (line == "[DECRYPT]") currentOperation = "DECRYPT";
             else currentOperation = line; 
             continue; 
        }

        if (line == "FAIL") {
            if (inDataBlock) cur.FAIL = true;
            continue;
        }

        std::size_t eqPos = line.find(" = ");
        if (eqPos == std::string::npos) continue; 
        std::string k = line.substr(0, eqPos);
        std::string v_val = line.substr(eqPos + 3); 

        // --- FIX: Chuyển k (key) sang chữ hoa ---
        std::transform(k.begin(), k.end(), k.begin(), ::toupper);

        if (k == "COUNT") { // <-- MODIFIED
             if (inDataBlock) list.push_back(cur); // Lưu vector trước đó
             inDataBlock = true;
             cur = KatVector(); // Tạo vector mới
             cur.count = v_val;
             cur.OPERATION = currentOperation; // Gán operation cho vector
        } else if (inDataBlock) {
             if (k == "KEY") cur.KEY = v_val; // <-- MODIFIED
             else if (k == "IV" || k == "NONCE") cur.IV = v_val; // <-- MODIFIED
             else if (k == "PT" || k == "PLAINTEXT") cur.PLAINTEXT = v_val; // <-- MODIFIED
             else if (k == "AAD") cur.AAD = v_val; // <-- MODIFIED
             else if (k == "CT" || k == "CIPHERTEXT") cur.CIPHERTEXT = v_val; // <-- MODIFIED
             else if (k == "TAG") cur.TAG = v_val; // <-- MODIFIED
        }
    }
    if (inDataBlock) list.push_back(cur); // Lưu vector cuối cùng
    return list;
}

// --- (Hàm run_kat không đổi so với lần trước) ---
void run_kat(const std::string& katFilePath, std::ofstream& csv, bool allowecb) {
    std::string filenameOnly = katFilePath.substr(katFilePath.find_last_of("/\\") + 1);
    
    std::vector<KatVector> vectors = ParseKatRsp(katFilePath); 
    KatVector v;

    if(vectors.empty()) {
        std::cerr << "No test vectors parsed from file: " << katFilePath << std::endl;
        return;
    }

    long total = vectors.size();
    long passOverall = 0;

    for (std::vector<KatVector>::const_iterator it = vectors.begin(); it != vectors.end(); ++it) {
        v = *it;
        bool testOK = false;
        std::string modeStr = v.OPERATION; 

        if (modeStr != "ENCRYPT" && modeStr != "DECRYPT") {
            if (filenameOnly.find("gcmEncrypt") != std::string::npos) {
                modeStr = "GCM-ENCRYPT";
            } else if (filenameOnly.find("gcmDecrypt") != std::string::npos) {
                modeStr = "GCM-DECRYPT";
            }
        }

        try {
            if (modeStr == "GCM-ENCRYPT") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);
                GCM<AES>::Encryption e;
                e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data(), ivBytes.size());
                std::string ct_plus_tag;
                std::string computed_tag;
                
                int tag_len_bytes = 16;
                if (!v.TAG.empty()) tag_len_bytes = v.TAG.length() / 2;
                if (tag_len_bytes == 0) tag_len_bytes = 16;
                
                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, tag_len_bytes);
                std::string aadBytes_e = HexToBytes(v.AAD);
                std::string ptBytes_e = HexToBytes(v.PLAINTEXT);
                if (!aadBytes_e.empty())
                    ef.ChannelPut(AAD_CHANNEL, (const byte*)aadBytes_e.data(), aadBytes_e.size());
                if (!ptBytes_e.empty())
                    ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)ptBytes_e.data(), ptBytes_e.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);
                std::string computed_ct;
                if (ct_plus_tag.length() < (size_t)tag_len_bytes) {
                         computed_ct = ""; computed_tag = "";
                } else if (ct_plus_tag.length() == (size_t)tag_len_bytes) {
                         computed_ct = ""; computed_tag = ct_plus_tag;
                } else {
                         computed_ct = ct_plus_tag.substr(0, ct_plus_tag.length() - tag_len_bytes);
                         computed_tag = ct_plus_tag.substr(ct_plus_tag.length() - tag_len_bytes);
                }
                bool ctOK = (BytesToHex(computed_ct) == v.CIPHERTEXT);
                if (v.PLAINTEXT.empty() && v.CIPHERTEXT.empty() && computed_ct.empty()) {
                    ctOK = true;
                }
                bool tagOK = (BytesToHex(computed_tag) == v.TAG);
                bool encryptOK = ctOK && tagOK;

                GCM<AES>::Decryption d;
                d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data(), ivBytes.size());
                AuthenticatedDecryptionFilter df(d, NULL, AuthenticatedDecryptionFilter::THROW_EXCEPTION, tag_len_bytes);
                std::string aadBytes_d = HexToBytes(v.AAD);
                std::string ctBytes_d = HexToBytes(v.CIPHERTEXT);
                std::string tagBytes_d = HexToBytes(v.TAG);
                if (!aadBytes_d.empty())
                    df.ChannelPut(AAD_CHANNEL, (const byte*)aadBytes_d.data(), aadBytes_d.size());
                if (!ctBytes_d.empty())
                    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ctBytes_d.data(), ctBytes_d.size());
                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)tagBytes_d.data(), tagBytes_d.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);
                
                testOK = encryptOK && true; 

            } else if (modeStr == "GCM-DECRYPT") {
                std::string keyBytes_d = HexToBytes(v.KEY);
                std::string ivBytes_d = HexToBytes(v.IV);
                
                int tag_len_bytes = 16;
                if (!v.TAG.empty()) tag_len_bytes = v.TAG.length() / 2;
                if (tag_len_bytes == 0) tag_len_bytes = 16;
                
                GCM<AES>::Decryption d;
                d.SetKeyWithIV((const byte*)keyBytes_d.data(), keyBytes_d.size(), (const byte*)ivBytes_d.data(), ivBytes_d.size());
                std::string recovered_pt;
                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION, tag_len_bytes);
                std::string aadBytes_df = HexToBytes(v.AAD);
                std::string ctBytes_df = HexToBytes(v.CIPHERTEXT);
                std::string tagBytes_df = HexToBytes(v.TAG);
                if (!aadBytes_df.empty())
                    df.ChannelPut(AAD_CHANNEL, (const byte*)aadBytes_df.data(), aadBytes_df.size());
                if (!ctBytes_df.empty())
                    df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ctBytes_df.data(), ctBytes_df.size());
                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)tagBytes_df.data(), tagBytes_df.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);
                if (v.FAIL) {
                    testOK = false; 
                } else {
                    testOK = (BytesToHex(recovered_pt) == v.PLAINTEXT);
                }
            }
            else if (modeStr == "ENCRYPT") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);
                std::string ptBytes = HexToBytes(v.PLAINTEXT);
                std::string computed_ct;

                CBC_Mode<AES>::Encryption e;
                e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                
                if (ptBytes.empty()) {
                    computed_ct = "";
                } else {
                    StringSource ss(ptBytes, true,
                        new StreamTransformationFilter(e,
                            new StringSink(computed_ct),
                            StreamTransformationFilter::NO_PADDING 
                        )
                    );
                }
                
                // So sánh kết quả, chuyển sang hex
                std::string computed_ct_hex = BytesToHex(computed_ct);
                // Các tệp KAT .rsp thường viết hoa hex
                std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                
                testOK = (computed_ct_hex == v.CIPHERTEXT);

            } else if (modeStr == "DECRYPT") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);
                std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                std::string recovered_pt;

                CBC_Mode<AES>::Decryption d;
                d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());

                if (ctBytes.empty()) {
                    recovered_pt = "";
                } else {
                    StringSource ss(ctBytes, true,
                        new StreamTransformationFilter(d,
                            new StringSink(recovered_pt),
                            StreamTransformationFilter::NO_PADDING
                        )
                    );
                }
                
                // So sánh kết quả, chuyển sang hex
                std::string recovered_pt_hex = BytesToHex(recovered_pt);
                std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);

                testOK = (recovered_pt_hex == v.PLAINTEXT);
            }

        }
        catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
            if (modeStr == "GCM-DECRYPT") {
                if (v.FAIL) testOK = true; 
                else {
                    testOK = false;
                    std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " FAILED DECRYPTION (Tag Mismatch): " << e.what() << std::endl;
                }
            } 
            else if (modeStr == "GCM-ENCRYPT") { 
                testOK = false; 
                std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " FAILED ENCRYPTION SELF-CHECK (Tag Mismatch): " << e.what() << std::endl;
            }
        } 
        catch (const std::exception& e) {
            std::cerr << "Error processing KAT vector COUNT=" << v.count << " in " << filenameOnly << ": " << e.what() << std::endl;
            testOK = false; 

            if (v.FAIL && (modeStr == "GCM-DECRYPT")) {
                testOK = true; 
            }
        }

        if (!testOK) {
            std::cerr << "DEBUG: Vector COUNT=" << v.count
                      << " OPERATION=" << v.OPERATION
                      << " FAILED \n";
            std::cerr << "  KEY=" << v.KEY << "\n";
            std::cerr << "  IV/NONCE=" << v.IV << "\n";
            if (v.OPERATION.find("GCM") != std::string::npos || v.AAD.length() > 0) std::cerr << "  AAD=" << v.AAD << "\n";
            std::cerr << "  CIPHERTEXT(expected)=" << v.CIPHERTEXT << "\n";
            if (v.OPERATION.find("GCM") != std::string::npos || v.TAG.length() > 0) std::cerr << "  TAG(expected)=" << v.TAG << "\n";
            std::cerr << "  PLAINTEXT(expected)=" << v.PLAINTEXT << "\n";
        }

        if (testOK) ++passOverall;

        csv << filenameOnly << "," << v.count << "," << v.OPERATION << ","
            << (testOK ? "1" : "0") << "\n";
    }

    double rate = total ? 100.0 * passOverall / total : 0.0;
    std::cout << katFilePath << ": Overall Pass=" << passOverall << "/" << total
          << " (" << std::fixed << std::setprecision(1) << rate << "%)" << std::endl;
}