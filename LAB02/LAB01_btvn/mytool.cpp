/*
# --- Ví dụ lệnh PowerShell để kiểm thử mytool.exe ---

# --- Ví dụ AES-GCM (AEAD) ---

# 1. Mã hóa GCM (Text -> Hex Output) với Key/Nonce/AAD cụ thể
# Lệnh này sẽ mã hóa văn bản, thêm dữ liệu xác thực (AAD),
# dùng key và nonce cho trước, và xuất kết quả dạng hex.
# Nó cũng sẽ ghi thông tin vào sidecar (.meta.json) và file log IV/Nonce (IVstored.bin).
# Lần chạy đầu tiên với Nonce này sẽ thành công.
.\mytool.exe `
--encrypt `
--verbose `
--in "6TESTFile\8MB.bin" `
--mode GCM `
--aead `
--aad- "Public accompanying data" `
--encode hex `
--out "gcm_output_1.bin" `
--key-hex "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F" `
--nonce-hex "B1B2B3B4B5B6B7B8B9B0BABC" # 12-byte nonce (24 hex) là tốt nhất cho GCM

# ---

# 2. Giải mã GCM (Hex Input -> Raw Output .txt)
# Lệnh này giải mã file hex được tạo ở trên.
# Cần cung cấp ĐÚNG Key, Nonce, và AAD đã dùng khi mã hóa.
# --encode hex chỉ định rằng file input (--in) là dạng hex.
.\mytool.exe `
--decrypt `
--verbose `
--in "gcm_output_1.bin" `
--mode GCM `
--aead `
--aad- "Public accompanying data" `
--encode hex `
--out "gcm_decrypted_1.txt" `
--key-hex "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F" `
--nonce-hex "B1B2B3B4B5B6B7B8B9B0BABC"

# ---

# 3. KIỂM THỬ TÁI SỬ DỤNG NONCE (GCM) - Lệnh này sẽ bị lỗi!
# Cố gắng mã hóa dữ liệu KHÁC ("Dữ liệu mới") nhưng lại dùng CÙNG Key và CÙNG Nonce
# với lệnh mã hóa số 1. Hàm CheckNonceUsed() nên phát hiện và báo lỗi,
# ngăn chặn việc mã hóa và thoát chương trình.
.\mytool.exe `
--encrypt `
--verbose `
--text "New data to encrypt" `
--mode GCM `
--aead `
--aad- "Different public data" `
--encode hex `
--out "gcm_output_reuse_fail.hex" `
--key-hex "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F" `
--nonce-hex "B1B2B3B4B5B6B7B8B9B0BABC" # <-- Nonce này đã được dùng ở lệnh 1

# ---

# 4. Mã hóa GCM thành công với Nonce KHÁC
# Lệnh này sẽ chạy thành công vì sử dụng Nonce mới (khác với lệnh 1).
.\mytool.exe `
--encrypt `
--verbose `
--text "Third piece of data" `
--mode GCM `
--aead `
--aad- "Public data batch 3" `
--encode hex `
--out "gcm_output_2.hex" `
--key-hex "000102030405060708090A0B0C0D0E0F000102030405060708090A0B0C0D0E0F" `
--nonce-hex "CCCCCCCCCCCCCCCCCCCCCCCC" # <-- Nonce mới, chưa có trong IVstored.bin

*/

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
#include <chrono>
#include <algorithm>
#include <sha.h>
#include <vector>
#include <utility>
#include <cstdio>
#include <stdexcept>
#include <sstream>
#include <cctype>
#include <iomanip>
#include <omp.h>
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
void SetThreadCount(const std::string& threadsNumStr, bool verbose);
struct KatVector {
    std::string count;
    std::string KEY, IV, PLAINTEXT, AAD, CIPHERTEXT, TAG;
    bool FAIL;
    int TAG_LEN = 0; // tag length in bytes (when provided by header Tlen)
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

    if (!threadsNum.empty()) {
        SetThreadCount(threadsNum, verbose);
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
            auto start = std::chrono::high_resolution_clock::now();
            DoEncryption(mode, inputData, inputKey, ivHex, nonceHex, aadData, encode, outputFile, aead, verbose);
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            std::cerr << "[Time]:" << duration << " us" << std::endl;
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
            auto start = std::chrono::high_resolution_clock::now();
            DoDecryption(mode, rawInputData, inputKey, ivHex, nonceHex, aadData, outputPlaintextfile, aead, verbose);
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            std::cerr << "[Time]:" << duration << " us" << std::endl;
            if (verbose) {
                 std::cout << "Decryption completed successfully." << std::endl;
                 std::cout << "Plaintext written to " << outputPlaintextfile << std::endl;
            } else {
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

// --- (Hàm ParseKatRsp không đổi so với lần trước) ---
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
    std::string currentOperation = ""; 
    std::string lastGlobalKey = ""; // some files declare Key once per header block
    std::string lastGlobalNonce = ""; // some files declare Nonce once per header block
    int currentTlen = 0; // tag length from header (bytes)

    while (std::getline(iss, line)) {
        trim_kat(line);
        if (line.empty() || line[0]=='#') continue;

        if (line[0] == '[') {
             // Header lines like [Tlen = 4] or operation markers
             if (line == "[ENCRYPT]") currentOperation = "ENCRYPT";
             else if (line == "[DECRYPT]") currentOperation = "DECRYPT";
             else {
                 // try parse [Tlen = N] but do NOT set currentOperation to the bracket content
                 std::size_t p = line.find("TLEN");
                 if (p != std::string::npos) {
                     std::size_t eq = line.find('=', p);
                     if (eq != std::string::npos) {
                         std::string val = line.substr(eq+1);
                         trim_kat(val);
                        try { currentTlen = std::stoi(val); } catch(...) { currentTlen = 0; }
                        // Normalize TLEN if specified in bits
                        if (currentTlen > 16 && (currentTlen % 8) == 0) currentTlen = currentTlen / 8;
                     }
                 }
             }
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

    std::transform(k.begin(), k.end(), k.begin(), ::toupper);
    // Normalize value: trim and uppercase hex fields to avoid case mismatches
    trim_kat(v_val);
    std::string v_up = v_val;
    std::transform(v_up.begin(), v_up.end(), v_up.begin(), ::toupper);
    // Remove spaces that might appear in some files
    v_up.erase(std::remove_if(v_up.begin(), v_up.end(), ::isspace), v_up.end());

       if (k == "COUNT") { 
             if (inDataBlock) list.push_back(cur); 
             inDataBlock = true;
             cur = KatVector(); 
             cur.count = v_val;
             cur.OPERATION = currentOperation;
             // inherit header-level values
             if (!lastGlobalKey.empty()) cur.KEY = lastGlobalKey;
           if (!lastGlobalNonce.empty()) cur.IV = lastGlobalNonce;
           if (currentTlen > 0) cur.TAG_LEN = currentTlen;
        } else {
            // fields either inside or outside COUNT (global Key, header fields)
            if (!inDataBlock) {
                // treat global header-level Key, Nonce/IV or Tlen
                if (k == "KEY") {
                    lastGlobalKey = v_up;
                } else if (k == "NONCE" || k == "IV") {
                    lastGlobalNonce = v_up;
                } else if (k == "TLEN") {
                    try { currentTlen = std::stoi(v_up); } catch(...) { currentTlen = 0; }
                    // Normalize TLEN if specified in bits
                    if (currentTlen > 16 && (currentTlen % 8) == 0) currentTlen = currentTlen / 8;
                }
            }

          if (inDataBlock) {
                 if (k == "KEY") cur.KEY = v_up;
              else if (k == "IV" || k == "NONCE") cur.IV = v_up;
                 else if (k == "PT" || k == "PLAINTEXT" || k == "PAYLOAD") cur.PLAINTEXT = v_up;
                 else if (k == "AAD" || k == "ADATA") cur.AAD = v_up;
                 else if (k == "CT" || k == "CIPHERTEXT") cur.CIPHERTEXT = v_up;
                 else if (k == "TAG") cur.TAG = v_up;
                 else if (k == "RESULT") {
                     std::string up = v_up;
                     std::transform(up.begin(), up.end(), up.begin(), ::toupper);
                     if (up.find("FAIL") != std::string::npos) cur.FAIL = true;
                 }
            }
        }
    }
    if (inDataBlock) list.push_back(cur); 
    return list;
}


void run_kat(const std::string& katFilePath, std::ofstream& csv, bool allowecb) {
    std::string filenameOnly = katFilePath.substr(katFilePath.find_last_of("/\\") + 1);

    // If file path indicates CCM test vectors folder, force CCM mode even if filename doesn't contain 'CCM'
    bool pathIndicatesCCM = (katFilePath.find("ccmtestvectors") != std::string::npos || katFilePath.find("ccmtest") != std::string::npos);

    std::vector<KatVector> vectors = ParseKatRsp(katFilePath);
    KatVector v;

    if(vectors.empty()) {
        std::cerr << "No test vectors parsed from file: " << katFilePath << std::endl;
        return;
    }

    // Detect cipher mode from filename so we can run proper logic for each KAT type
    // Note: check "CFB128" before "CFB1" because "CFB128" contains the substring "CFB1".
    std::string cipherMode = "CBC"; // default
    if (filenameOnly.find("GCM") != std::string::npos || filenameOnly.find("gcm") != std::string::npos) {
        cipherMode = "GCM";
    } else if (pathIndicatesCCM || filenameOnly.find("CCM") != std::string::npos || filenameOnly.find("ccm") != std::string::npos) {
        cipherMode = "CCM";
    } else if (filenameOnly.find("CFB128") != std::string::npos) {
        cipherMode = "CFB128"; // byte-oriented CFB (standard CFB-128)
    } else if (filenameOnly.find("CFB1") != std::string::npos) {
        cipherMode = "CFB1"; // 1-bit CFB tests require bit-level simulation
    } else if (filenameOnly.find("CFB") != std::string::npos) {
        cipherMode = "CFB128"; // fallback for generic CFB mentions
    } else if (filenameOnly.find("ECB") != std::string::npos) {
        cipherMode = "ECB";
    } else if (filenameOnly.find("OFB") != std::string::npos) {
        cipherMode = "OFB";
    }

    long total = vectors.size();
    long passOverall = 0;

    for (std::vector<KatVector>::const_iterator it = vectors.begin(); it != vectors.end(); ++it) {
        v = *it;
        bool testOK = false;
        std::string modeStr = v.OPERATION;

        if (cipherMode == "GCM") {
            if (filenameOnly.find("gcmEncrypt") != std::string::npos) {
                modeStr = "GCM-ENCRYPT";
            } else if (filenameOnly.find("gcmDecrypt") != std::string::npos) {
                modeStr = "GCM-DECRYPT";
            }
        }

        try {
            if (modeStr == "GCM-ENCRYPT") {
                 // --- Logic GCM ENCRYPT (không đổi) ---
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);
                GCM<AES>::Encryption e;
                e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data(), ivBytes.size());

                std::string ct_plus_tag;
                std::string computed_tag;
                int tag_len_bytes = v.TAG.length() / 2;
                 if (tag_len_bytes == 0 && !v.TAG.empty()) { tag_len_bytes = 1; }
                 else if (tag_len_bytes == 0) { tag_len_bytes = 16; }

                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, tag_len_bytes);
                std::string aadBytes_e = HexToBytes(v.AAD);
                std::string ptBytes_e = HexToBytes(v.PLAINTEXT);

                if (!aadBytes_e.empty()) ef.ChannelPut(AAD_CHANNEL, (const byte*)aadBytes_e.data(), aadBytes_e.size());
                if (!ptBytes_e.empty()) ef.ChannelPut(DEFAULT_CHANNEL, (const byte*)ptBytes_e.data(), ptBytes_e.size());
                ef.ChannelMessageEnd(DEFAULT_CHANNEL);

                std::string computed_ct;
                if (ct_plus_tag.length() < (size_t)tag_len_bytes) { computed_ct = ""; computed_tag = ""; }
                else if (ct_plus_tag.length() == (size_t)tag_len_bytes) { computed_ct = ""; computed_tag = ct_plus_tag; }
                else {
                     computed_ct = ct_plus_tag.substr(0, ct_plus_tag.length() - tag_len_bytes);
                     computed_tag = ct_plus_tag.substr(ct_plus_tag.length() - tag_len_bytes);
                }
                std::string computed_ct_hex = BytesToHex(computed_ct);
                std::string computed_tag_hex = BytesToHex(computed_tag);
                std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                std::transform(computed_tag_hex.begin(), computed_tag_hex.end(), computed_tag_hex.begin(), ::toupper);

                bool ctOK = (computed_ct_hex == v.CIPHERTEXT);
                if (v.PLAINTEXT.empty() && v.CIPHERTEXT.empty() && computed_ct.empty()) { ctOK = true; }
                bool tagOK = (computed_tag_hex == v.TAG);
                testOK = ctOK && tagOK;

            } else if (modeStr == "GCM-DECRYPT") {
                // --- Logic GCM DECRYPT (không đổi) ---
                std::string keyBytes_d = HexToBytes(v.KEY);
                std::string ivBytes_d = HexToBytes(v.IV);
                int tag_len_bytes = v.TAG.length() / 2;
                 if (tag_len_bytes == 0 && !v.TAG.empty()) { tag_len_bytes = 1; }
                 else if (tag_len_bytes == 0) { tag_len_bytes = 16; }

                GCM<AES>::Decryption d;
                d.SetKeyWithIV((const byte*)keyBytes_d.data(), keyBytes_d.size(), (const byte*)ivBytes_d.data(), ivBytes_d.size());
                std::string recovered_pt;
                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt),
                                                 AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END,
                                                 tag_len_bytes);
                std::string aadBytes_df = HexToBytes(v.AAD);
                std::string ctBytes_df = HexToBytes(v.CIPHERTEXT);
                std::string tagBytes_df = HexToBytes(v.TAG);

                if (!aadBytes_df.empty()) df.ChannelPut(AAD_CHANNEL, (const byte*)aadBytes_df.data(), aadBytes_df.size());
                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)ctBytes_df.data(), ctBytes_df.size());
                df.ChannelPut(DEFAULT_CHANNEL, (const byte*)tagBytes_df.data(), tagBytes_df.size());
                df.ChannelMessageEnd(DEFAULT_CHANNEL);

                std::string recovered_pt_hex = BytesToHex(recovered_pt);
                std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                testOK = (recovered_pt_hex == v.PLAINTEXT);

                if (v.FAIL && testOK) {
                    testOK = false;
                    std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " expected FAIL but decryption SUCCEEDED." << std::endl;
                }

            }
            // --- LOGIC CHO CCM (tương tự GCM nhưng tag length thay đổi theo header Tlen) ---
            else if (cipherMode == "CCM") {
                // Decide to decrypt if ciphertext present (most CCM vectors include CT+Payload)
                int tag_len_bytes = v.TAG_LEN;
                if (tag_len_bytes == 0) tag_len_bytes = (int)(v.TAG.length() / 2);
                if (tag_len_bytes == 0) tag_len_bytes = 16;
                // Normalize tag length: some files specify TLEN in bits (e.g., 128) — convert to bytes if needed
                if (tag_len_bytes > 16 && (tag_len_bytes % 8) == 0) {
                    tag_len_bytes = tag_len_bytes / 8;
                }

                std::string keyBytes = HexToBytes(v.KEY);
                std::string nonceBytes = HexToBytes(v.IV);
                std::string aadBytes = HexToBytes(v.AAD);

                bool didDecrypt = false;
                if (!v.CIPHERTEXT.empty()) {
                    // Decrypt path: try to verify recovered plaintext matches expected
                    std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                    std::string tagBytes = HexToBytes(v.TAG);
                    std::string recovered_pt;

                    // Some .rsp files provide CT and TAG concatenated in CIPHERTEXT
                    // while others provide TAG separately. If TAG field is empty
                    // but CIPHERTEXT length >= tag_len_bytes, split tail as tag.
                    if (tagBytes.empty() && ctBytes.size() >= (size_t)tag_len_bytes) {
                        tagBytes = ctBytes.substr(ctBytes.size() - tag_len_bytes);
                        ctBytes.resize(ctBytes.size() - tag_len_bytes);
                    }

                    try {
                        switch (tag_len_bytes) {
                            case 4: {
                                CCM<AES,4>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 4);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 6: {
                                CCM<AES,6>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 6);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 8: {
                                CCM<AES,8>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 8);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 10: {
                                CCM<AES,10>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 10);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 12: {
                                CCM<AES,12>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 12);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 14: {
                                CCM<AES,14>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 14);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                            case 16:
                            default: {
                                CCM<AES,16>::Decryption d; d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                size_t ciphertextLen = ctBytes.size();
                                d.SpecifyDataLengths(aadBytes.size(), ciphertextLen, 0);
                                AuthenticatedDecryptionFilter df(d, new StringSink(recovered_pt), AuthenticatedDecryptionFilter::THROW_EXCEPTION | AuthenticatedDecryptionFilter::MAC_AT_END, 16);
                                if (!aadBytes.empty()) df.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                if (!ctBytes.empty()) df.ChannelPut("", (const byte*)ctBytes.data(), ctBytes.size());
                                if (!tagBytes.empty()) df.ChannelPut("", (const byte*)tagBytes.data(), tagBytes.size());
                                df.ChannelMessageEnd("");
                            } break;
                        }

                        std::string recovered_pt_hex = BytesToHex(recovered_pt);
                        std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                        testOK = (recovered_pt_hex == v.PLAINTEXT);
                        didDecrypt = true;

                        if (v.FAIL && testOK) {
                            testOK = false;
                            std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " expected FAIL but decryption SUCCEEDED." << std::endl;
                        }

                    } catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
                        if (v.FAIL) testOK = true; else { testOK = false; std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " FAILED DECRYPTION (Tag Mismatch): " << e.what() << std::endl; }
                    } catch (const std::exception& e) {
                        if (v.FAIL) testOK = true; else { testOK = false; std::cerr << "CCM decryption error COUNT=" << v.count << ": " << e.what() << std::endl; }
                    }
                }

                // If no ciphertext present or decrypt not performed, attempt encryption check when plaintext present
                if (!didDecrypt && !v.PLAINTEXT.empty()) {
                    std::string ptBytes = HexToBytes(v.PLAINTEXT);
                    std::string ct_plus_tag;
                    try {
                        switch (tag_len_bytes) {
                            case 4: {
                                CCM<AES,4>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 4);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 6: {
                                CCM<AES,6>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 6);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 8: {
                                CCM<AES,8>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 8);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 10: {
                                CCM<AES,10>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 10);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 12: {
                                CCM<AES,12>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 12);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 14: {
                                CCM<AES,14>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 14);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                            case 16:
                            default: {
                                CCM<AES,16>::Encryption e; e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)nonceBytes.data(), nonceBytes.size());
                                e.SpecifyDataLengths(aadBytes.size(), ptBytes.size(), 0);
                                AuthenticatedEncryptionFilter ef(e, new StringSink(ct_plus_tag), false, 16);
                                if (!aadBytes.empty()) ef.ChannelPut("AAD", (const byte*)aadBytes.data(), aadBytes.size());
                                ef.ChannelPut("", (const byte*)ptBytes.data(), ptBytes.size());
                                ef.ChannelMessageEnd("");
                            } break;
                        }

                        // ct_plus_tag contains ciphertext concatenated with tag.
                        // Some vectors provide TAG separately, others contain combined CT||TAG in CIPHERTEXT.
                        std::string computed_ct, computed_tag;
                        if (ct_plus_tag.length() <= (size_t)tag_len_bytes) { computed_ct = ""; computed_tag = ct_plus_tag; }
                        else {
                            computed_ct = ct_plus_tag.substr(0, ct_plus_tag.length() - tag_len_bytes);
                            computed_tag = ct_plus_tag.substr(ct_plus_tag.length() - tag_len_bytes);
                        }
                        std::string computed_ct_hex = BytesToHex(computed_ct);
                        std::string computed_tag_hex = BytesToHex(computed_tag);
                        std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                        std::transform(computed_tag_hex.begin(), computed_tag_hex.end(), computed_tag_hex.begin(), ::toupper);

                        if (v.TAG.empty()) {
                            // KAT stores CT||TAG together in CIPHERTEXT
                            std::string combined_hex = BytesToHex(ct_plus_tag);
                            std::transform(combined_hex.begin(), combined_hex.end(), combined_hex.begin(), ::toupper);
                            testOK = (combined_hex == v.CIPHERTEXT);
                        } else {
                            bool ctOK = (computed_ct_hex == v.CIPHERTEXT);
                            bool tagOK = (computed_tag_hex == v.TAG);
                            testOK = ctOK && tagOK;
                        }

                    } catch (const std::exception& e) {
                        testOK = false;
                        std::cerr << "CCM encryption error COUNT=" << v.count << ": " << e.what() << std::endl;
                    }
                }

            }
            // --- LOGIC CHO CFB1 (bit-level) ---
            else if (cipherMode == "CFB1") {
                // CFB-1: single-bit feedback. We must simulate bit-by-bit using raw AES block encrypt.
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);

                auto hexCharToBit = [](const std::string &s)->int {
                    if (s.empty()) return 0;
                    char c = s[0];
                    if (c == '0') return 0;
                    if (c == '1') return 1;
                    // fallback: parse hex nibble LSB
                    int nib = 0;
                    if (std::isxdigit((unsigned char)c)) {
                        nib = (c <= '9') ? (c - '0') : (std::toupper(c) - 'A' + 10);
                    }
                    return nib & 1;
                };

                try {
                    AES::Encryption aesEnc;
                    aesEnc.SetKey((const byte*)keyBytes.data(), (unsigned int)keyBytes.size());

                    std::string out_bits = "";
                    // We assume plaintext/ciphertext are short bit-strings encoded as '0'/'1' chars
                    size_t bits = std::max(v.PLAINTEXT.length(), v.CIPHERTEXT.length());
                    if (bits == 0) bits = 1; // fallback

                    std::string iv_work = ivBytes;
                    for (size_t bi = 0; bi < bits; ++bi) {
                        byte block[16]; byte keystream[16];
                        memset(block, 0, sizeof(block));
                        // copy iv_work (should be 16 bytes)
                        memcpy(block, iv_work.data(), std::min<size_t>(iv_work.size(), 16));
                        aesEnc.ProcessBlock(block, keystream);

                        int msb = (keystream[0] & 0x80) ? 1 : 0;
                        int ptbit = hexCharToBit(v.PLAINTEXT);
                        int ctbit = 0;
                        if (modeStr == "ENCRYPT") {
                            ctbit = msb ^ ptbit;
                            out_bits.push_back(ctbit ? '1' : '0');
                            // shift iv_work left by 1 bit and append ctbit
                            unsigned char carry = 0;
                            for (size_t i = 0; i < iv_work.size(); ++i) {
                                unsigned char newCarry = (iv_work[i] & 0x80) ? 1 : 0;
                                iv_work[i] = (unsigned char)((iv_work[i] << 1) | carry);
                                carry = newCarry;
                            }
                            iv_work[iv_work.size()-1] |= (ctbit & 0x1);
                        } else { // DECRYPT
                            ctbit = hexCharToBit(v.CIPHERTEXT);
                            int recovered_ptbit = msb ^ ctbit;
                            out_bits.push_back(recovered_ptbit ? '1' : '0');
                            // shift iv_work and append ciphertext bit
                            unsigned char carry = 0;
                            for (size_t i = 0; i < iv_work.size(); ++i) {
                                unsigned char newCarry = (iv_work[i] & 0x80) ? 1 : 0;
                                iv_work[i] = (unsigned char)((iv_work[i] << 1) | carry);
                                carry = newCarry;
                            }
                            iv_work[iv_work.size()-1] |= (ctbit & 0x1);
                        }
                    }

                    if (modeStr == "ENCRYPT") {
                        // compare produced single-bit string with expected CIPHERTEXT
                        std::string expected_ct = v.CIPHERTEXT;
                        // normalize
                        trim_kat(expected_ct);
                        if (!out_bits.empty() && expected_ct == out_bits) testOK = true;
                        else testOK = (expected_ct == out_bits);
                    } else if (modeStr == "DECRYPT") {
                        std::string expected_pt = v.PLAINTEXT;
                        trim_kat(expected_pt);
                        if (!out_bits.empty() && expected_pt == out_bits) testOK = true;
                        else testOK = (expected_pt == out_bits);
                    }

                } catch (const std::exception& e) {
                    std::cerr << "CFB1 processing error COUNT=" << v.count << ": " << e.what() << std::endl;
                    testOK = false;
                }

            }
            // --- LOGIC CHO CFB128 (byte-oriented CFB) ---
            else if (cipherMode == "CFB128") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);

                if (modeStr == "ENCRYPT") {
                    std::string ptBytes = HexToBytes(v.PLAINTEXT);
                    std::string computed_ct;

                    CFB_Mode<AES>::Encryption e;
                    e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ptBytes, true,
                        new StreamTransformationFilter(e, new StringSink(computed_ct))
                    );
                    std::string computed_ct_hex = BytesToHex(computed_ct);
                    std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                    testOK = (computed_ct_hex == v.CIPHERTEXT);

                } else if (modeStr == "DECRYPT") {
                    std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                    std::string recovered_pt;

                    CFB_Mode<AES>::Decryption d;
                    d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ctBytes, true,
                        new StreamTransformationFilter(d, new StringSink(recovered_pt))
                    );
                    std::string recovered_pt_hex = BytesToHex(recovered_pt);
                    std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                    testOK = (recovered_pt_hex == v.PLAINTEXT);
                } else {
                    std::cerr << "WARNING: Unknown operation '" << modeStr << "' for CFB mode in KAT vector COUNT=" << v.count << std::endl;
                    testOK = false;
                }

            }
            // --- LOGIC CHO ECB ---
            else if (cipherMode == "ECB") {
                std::string keyBytes = HexToBytes(v.KEY);

                // Determine padding mode similar to CBC heuristic
                auto paddingMode = StreamTransformationFilter::PKCS_PADDING;
                size_t ptLenBytesExpected = v.PLAINTEXT.length() / 2;
                size_t ctLenBytesExpected = v.CIPHERTEXT.length() / 2;
                if (ptLenBytesExpected == ctLenBytesExpected && ptLenBytesExpected > 0 && (ptLenBytesExpected % AES::BLOCKSIZE == 0)) {
                    paddingMode = StreamTransformationFilter::NO_PADDING;
                }

                if (modeStr == "ENCRYPT") {
                    std::string ptBytes = HexToBytes(v.PLAINTEXT);
                    std::string computed_ct;

                    ECB_Mode<AES>::Encryption e;
                    e.SetKey((const byte*)keyBytes.data(), keyBytes.size());
                    StringSource ss(ptBytes, true,
                        new StreamTransformationFilter(e, new StringSink(computed_ct), paddingMode)
                    );
                    std::string computed_ct_hex = BytesToHex(computed_ct);
                    std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                    testOK = (computed_ct_hex == v.CIPHERTEXT);

                } else if (modeStr == "DECRYPT") {
                    std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                    std::string recovered_pt;

                    ECB_Mode<AES>::Decryption d;
                    d.SetKey((const byte*)keyBytes.data(), keyBytes.size());
                    StringSource ss(ctBytes, true,
                        new StreamTransformationFilter(d, new StringSink(recovered_pt), paddingMode)
                    );
                    std::string recovered_pt_hex = BytesToHex(recovered_pt);
                    std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                    testOK = (recovered_pt_hex == v.PLAINTEXT);
                } else {
                    std::cerr << "WARNING: Unknown operation '" << modeStr << "' for ECB mode in KAT vector COUNT=" << v.count << std::endl;
                    testOK = false;
                }
            }
            // --- LOGIC CHO OFB (stream mode) ---
            else if (cipherMode == "OFB") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);

                if (modeStr == "ENCRYPT") {
                    std::string ptBytes = HexToBytes(v.PLAINTEXT);
                    std::string computed_ct;

                    OFB_Mode<AES>::Encryption e;
                    e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ptBytes, true,
                        new StreamTransformationFilter(e, new StringSink(computed_ct), StreamTransformationFilter::NO_PADDING)
                    );
                    std::string computed_ct_hex = BytesToHex(computed_ct);
                    std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                    testOK = (computed_ct_hex == v.CIPHERTEXT);

                } else if (modeStr == "DECRYPT") {
                    std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                    std::string recovered_pt;

                    OFB_Mode<AES>::Decryption d;
                    d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ctBytes, true,
                        new StreamTransformationFilter(d, new StringSink(recovered_pt), StreamTransformationFilter::NO_PADDING)
                    );
                    std::string recovered_pt_hex = BytesToHex(recovered_pt);
                    std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                    testOK = (recovered_pt_hex == v.PLAINTEXT);
                } else {
                    std::cerr << "WARNING: Unknown operation '" << modeStr << "' for OFB mode in KAT vector COUNT=" << v.count << std::endl;
                    testOK = false;
                }

            }
            // --- LOGIC CHO CBC (với padding động TỔNG QUÁT) ---
            else if (cipherMode == "CBC") {
                std::string keyBytes = HexToBytes(v.KEY);
                std::string ivBytes = HexToBytes(v.IV);

                // --- FIX v5.4: Logic padding tổng quát ---
                auto paddingMode = StreamTransformationFilter::PKCS_PADDING; // Mặc định
                size_t ptLenBytesExpected = v.PLAINTEXT.length() / 2;
                size_t ctLenBytesExpected = v.CIPHERTEXT.length() / 2;

                // Quy tắc: Nếu độ dài PT mong đợi == CT mong đợi và là bội số block -> NO_PADDING
                if (ptLenBytesExpected == ctLenBytesExpected &&
                    ptLenBytesExpected > 0 &&
                    (ptLenBytesExpected % AES::BLOCKSIZE == 0))
                {
                    paddingMode = StreamTransformationFilter::NO_PADDING;
                }
                // --- Hết FIX v5.4 ---


                if (modeStr == "ENCRYPT") {
                    std::string ptBytes = HexToBytes(v.PLAINTEXT);
                    std::string computed_ct;

                    CBC_Mode<AES>::Encryption e;
                    e.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ptBytes, true,
                        new StreamTransformationFilter(e, new StringSink(computed_ct), paddingMode)
                    );
                    std::string computed_ct_hex = BytesToHex(computed_ct);
                    std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                    testOK = (computed_ct_hex == v.CIPHERTEXT);

                } else if (modeStr == "DECRYPT") {
                    std::string ctBytes = HexToBytes(v.CIPHERTEXT);
                    std::string recovered_pt;

                    CBC_Mode<AES>::Decryption d;
                    d.SetKeyWithIV((const byte*)keyBytes.data(), keyBytes.size(), (const byte*)ivBytes.data());
                    StringSource ss(ctBytes, true,
                        new StreamTransformationFilter(d, new StringSink(recovered_pt), paddingMode)
                    );
                    std::string recovered_pt_hex = BytesToHex(recovered_pt);
                    std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                    testOK = (recovered_pt_hex == v.PLAINTEXT);
                } else {
                     std::cerr << "WARNING: Unknown operation '" << modeStr << "' for CBC mode in KAT vector COUNT=" << v.count << std::endl;
                     testOK = false;
                }
            } else {
                 std::cerr << "WARNING: Unsupported cipher mode '" << cipherMode << "' detected for file " << filenameOnly << " in KAT vector COUNT=" << v.count << std::endl;
                 testOK = false;
            }

        }
        // --- Catch blocks không đổi ---
        catch (const CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
            if (modeStr == "GCM-DECRYPT") {
                if (v.FAIL) testOK = true;
                else {
                    testOK = false;
                    std::cerr << "KAT vector COUNT=" << v.count << " in " << filenameOnly << " FAILED DECRYPTION (Tag Mismatch): " << e.what() << std::endl;
                }
            } else {
                 testOK = false;
                 std::cerr << "Unexpected HashVerificationFailed for COUNT=" << v.count << " (" << modeStr << "): " << e.what() << std::endl;
            }
        }
        catch (const CryptoPP::InvalidArgument& e) {
            if (cipherMode == "CBC" && modeStr == "DECRYPT") {
                 if (v.FAIL) testOK = true;
                 else {
                     testOK = false;
                     std::cerr << "Error processing KAT vector COUNT=" << v.count << " in " << filenameOnly << " (Possibly invalid padding): " << e.what() << std::endl;
                 }
            } else {
                 testOK = false;
                 if(v.FAIL) testOK = true;
                 std::cerr << "Error processing KAT vector COUNT=" << v.count << " in " << filenameOnly << ": " << e.what() << std::endl;
            }
        }
        catch (const std::exception& e) {
            std::cerr << "Error processing KAT vector COUNT=" << v.count << " in " << filenameOnly << ": " << e.what() << std::endl;
            testOK = false;
             if (v.FAIL) {
                 testOK = true;
             }
        }

        // --- Output Debug và ghi CSV không đổi ---
        if (!testOK) {
             std::cerr << "DEBUG: Vector COUNT=" << v.count
                      << " OPERATION=" << v.OPERATION
                      << " CipherMode=" << cipherMode
                      << " FAILED \n";
            std::cerr << "  KEY=" << v.KEY << "\n";
            std::cerr << "  IV/NONCE=" << v.IV << "\n";
            if (!v.AAD.empty()) std::cerr << "  AAD=" << v.AAD << "\n";
            std::cerr << "  CIPHERTEXT(expected)=" << v.CIPHERTEXT << "\n";
            if (!v.TAG.empty()) std::cerr << "  TAG(expected)=" << v.TAG << "\n";
            std::cerr << "  PLAINTEXT(expected)=" << v.PLAINTEXT << "\n";
             if(v.FAIL) std::cerr << "  (Note: This vector was expected to FAIL)\n";
        }

        if (testOK) ++passOverall;

        csv << filenameOnly << "," << v.count << "," << v.OPERATION << ","
            << (testOK ? "1" : "0") << "\n";
    }

    double rate = total ? 100.0 * passOverall / total : 0.0;
    std::cout << katFilePath << ": Overall Pass=" << passOverall << "/" << total
          << " (" << std::fixed << std::setprecision(1) << rate << "%)" << std::endl;
}

void SetThreadCount(const std::string& threadsNumStr, bool verbose) {
    int numThreads = 1; // Mặc định là 1 luồng nếu không có gì được chỉ định

    if (!threadsNumStr.empty()) {
        // Nếu chuỗi không rỗng, cố gắng phân tích nó
        try {
            int parsedThreads = std::stoi(threadsNumStr);
            if (parsedThreads > 0) {
                numThreads = parsedThreads; // Đặt thành N nếu hợp lệ
            } else {
                std::cerr << "Warning: Giá trị --threads không hợp lệ '" << threadsNumStr 
                          << "'. Phải là số nguyên dương. Sử dụng 1 luồng." << std::endl;
                // numThreads vẫn là 1
            }
        } catch (const std::invalid_argument& e) {
            std::cerr << "Warning: Giá trị --threads không hợp lệ '" << threadsNumStr 
                      << "'. Không phải là số nguyên. Sử dụng 1 luồng." << std::endl;
            // numThreads vẫn là 1
        } catch (const std::out_of_range& e) {
            std::cerr << "Warning: Giá trị --threads '" << threadsNumStr 
                      << "' quá lớn. Sử dụng 1 luồng." << std::endl;
            // numThreads vẫn là 1
        }
    }

    // Đặt số luồng (sẽ là 1 hoặc N)
    omp_set_num_threads(numThreads);

    if (verbose) {
        // Báo cáo số luồng tối đa thực tế mà OpenMP sẽ sử dụng
        std::cout << "[+] Đã đặt số luồng OpenMP (tối đa) thành: " << omp_get_max_threads() << std::endl;
    }
}