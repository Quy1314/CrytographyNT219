#include <iostream>
#include <string>
#include <cryptlib.h>
#include <hex.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <files.h>
#include <secblock.h>

using namespace CryptoPP;

// In ra hex
void PrintHex(const std::string& label, const CryptoPP::byte* data, size_t length) {
    std::string encoded;
    CryptoPP::StringSource(data, length, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        )
    );
    std::cout << label << ": " << encoded << std::endl;
}

// Nhập hex thành byte
void InputHexToBytes(const std::string& label, CryptoPP::SecByteBlock& block) {
    std::string hexInput;
    std::cout << "Nhap " << label << " (dang Hex): ";
    std::cin >> hexInput;

    if (hexInput.size() != 32) {
        std::cerr << "Loi: " << label << " phai co 16 bytes (32 hex chars)" << std::endl;
        exit(1);
    }

    block.CleanNew(16);
    CryptoPP::StringSource(hexInput, true,
        new CryptoPP::HexDecoder(new CryptoPP::ArraySink(block, block.size()))
    );
}

// Sinh AES key & IV ngẫu nhiên
void GenerateAESKey(CryptoPP::SecByteBlock& key, CryptoPP::SecByteBlock& iv) {
    CryptoPP::AutoSeededRandomPool prng;
    key.CleanNew(CryptoPP::AES::DEFAULT_KEYLENGTH);
    iv.CleanNew(CryptoPP::AES::BLOCKSIZE);

    prng.GenerateBlock(key.BytePtr(), key.size());
    prng.GenerateBlock(iv.BytePtr(), iv.size());
}

// Lưu key/IV vào file
void SaveKeyToFile(const std::string& filename, const CryptoPP::SecByteBlock& key, const CryptoPP::SecByteBlock& iv) {
    CryptoPP::FileSink file(filename.c_str(), true);
    file.Put(key.BytePtr(), key.size());
    file.Put(iv.BytePtr(), iv.size());
    file.MessageEnd();
    std::cout << "Key and IV saved to: " << filename << std::endl;
}

// Load key/IV từ file (dùng Attach + Pump)
void LoadKeyFromFile(const std::string& filename, CryptoPP::byte key[], CryptoPP::byte iv[]) {
    try {
        CryptoPP::FileSource file(filename.c_str(), false);  // Don't PumpAll yet

        file.Attach(new CryptoPP::ArraySink(key, CryptoPP::AES::DEFAULT_KEYLENGTH));
        file.Pump(CryptoPP::AES::DEFAULT_KEYLENGTH);

        file.Attach(new CryptoPP::ArraySink(iv, CryptoPP::AES::BLOCKSIZE));
        file.Pump(CryptoPP::AES::BLOCKSIZE);

        std::cout << "Key and IV loaded from file: " << filename << std::endl;
        PrintHex("Loaded Key", key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        PrintHex("Loaded IV", iv, CryptoPP::AES::BLOCKSIZE);
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Error loading key and IV: " << e.what() << std::endl;
    }
}

// Load key/IV từ hex flag
void HexFlagToBytes(const std::string& hexStr, CryptoPP::SecByteBlock& block) {
    if (hexStr.size() != 32) {
        std::cerr << "Flag key/IV phai co 16 bytes (32 hex chars)" << std::endl;
        exit(1);
    }
    block.CleanNew(16);
    CryptoPP::StringSource(hexStr, true,
        new CryptoPP::HexDecoder(new CryptoPP::ArraySink(block, block.size()))
    );
}

int main(int argc, char* argv[]) {
    CryptoPP::SecByteBlock key, iv;
    bool useFlagKeyIV = false;
    std::string keyHex, ivHex;

    // Parse --key / --iv
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--key" && i + 1 < argc) {
            keyHex = argv[++i];
        } else if (arg == "--iv" && i + 1 < argc) {
            ivHex = argv[++i];
        }
    }

    if (!keyHex.empty() && !ivHex.empty()) {
        useFlagKeyIV = true;
        HexFlagToBytes(keyHex, key);
        HexFlagToBytes(ivHex, iv);
        std::cout << "[MODE] Su dung key/IV tu flag.\n";
    }

    // Nếu không có flag
    if (!useFlagKeyIV) {
        std::cout << "Ban muon tu nhap key/IV hay sinh ngau nhien? (1 = nhap, 0 = ngau nhien): ";
        int choice;
        std::cin >> choice;

        if (choice == 1) {
            InputHexToBytes("Key", key);
            InputHexToBytes("IV", iv);
        } else {
            GenerateAESKey(key, iv);
        }
    }

    // Lưu file + đọc file (vẫn dùng Attach + Pump)
    SaveKeyToFile("keydata.bin", key, iv);
    CryptoPP::byte fileKey[CryptoPP::AES::DEFAULT_KEYLENGTH], fileIV[CryptoPP::AES::BLOCKSIZE];
    LoadKeyFromFile("keydata.bin", fileKey, fileIV);

    return 0;
}
