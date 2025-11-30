
// Linux help: http://www.cryptopp.com/wiki/Linux

// Debug:
// g++ -g -ggdb -O0 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp RSAOAEP.cpp -o rsaoaep -lcryptopp

// Release:
// g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp RSAOAEP.cpp -o rsaoaep -lcryptopp && strip --strip-all rsaoaep

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <chrono>
#include <ctime>

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;

#include <fstream>
using std::ifstream;
using std::ofstream;
using std::ios;

#include <iterator>
using std::istreambuf_iterator;

// UTF-8 Vietnamese languages
#ifdef _WIN32
#include <windows.h>
#endif
#include <cstdlib>
#include <locale>
#include <cctype>

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "cryptopp/rsa.h"
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSA;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;

#include "cryptopp/base64.h"
using CryptoPP::Base64Decoder;
using CryptoPP::Base64Encoder;

#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::Exception;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

/* Integer arithmatics*/
#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/nbtheory.h>
using CryptoPP::ModularSquareRoot;

#include <cryptopp/modarith.h>
using CryptoPP::ModularArithmetic;
#include <cryptopp/hex.h>
#include <cryptopp/base64.h>

#include <cryptopp/config_int.h>
using CryptoPP::byte;
using CryptoPP::word32;

#ifndef DLL_EXPORT
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#endif

// Function prototypes
// Save (BER-BIN) key to file
void Save(const string &filename, const BufferedTransformation &bt);
void SavePrivateKey(const string &filename, const PrivateKey &key);
void SavePublicKey(const string &filename, const PublicKey &key);

// Save (BER-BASE64) key to file
void SaveBase64(const string &filename, const BufferedTransformation &bt);
void SaveBase64PrivateKey(const string &filename, const PrivateKey &key);
void SaveBase64PublicKey(const string &filename, const PublicKey &key);

// Load (BER-BIN) key to buffer
void Load(const string &filename, BufferedTransformation &bt);
void LoadPrivateKey(const string &filename, PrivateKey &key);
void LoadPublicKey(const string &filename, PublicKey &key);

// Load (BER-BASE64) key to buffer
void LoadBase64(const string &filename, BufferedTransformation &bt);
void LoadBase64PrivateKey(const string &filename, RSA::PrivateKey &key);
void LoadBase64PublicKey(const string &filename, RSA::PublicKey &key);

// For RSA functions
void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile);
string RSAencrypt(const string format, const char *publicKeyFile, const char *PlaintextFile, const char *CipherFile);
string RSAdecrypt(const string format, const char *secretKeyFile, const char *CipherFile, const char *PlaintextFile);

// For Hybrid encryption/decryption
void HybridEncrypt(const string& format, const char* publicKeyFile, const char* plaintextFile, const char* cipherFile);
void HybridDecrypt(const string& format, const char* privateKeyFile, const char* cipherFile, const char* decryptedFile);
void BenchmarkHybridEncryption(const string& format, const char* publicKeyFile, const char* plaintextFile, const char* cipherFile);
void BenchmarkHybridDecryption(const string& format, const char* privateKeyFile, const char* cipherFile, const char* decryptedFile);

// Function implementations
void GenerateAndSaveRSAKeys(int keySize, const char *format, const char *privateKeyFile, const char *publicKeyFile)
{
    // convert commandline char to string
    string strFormat(format);
    string strPrivateKey(privateKeyFile);
    string strPublicKey(publicKeyFile);

    AutoSeededRandomPool rnd;
    // Generate Private key
    RSA::PrivateKey rsaPrivate;
    rsaPrivate.GenerateRandomWithKeySize(rnd, keySize);
    // Generate public key
    RSA::PublicKey rsaPublic(rsaPrivate);

    if (strFormat == "DER")
    {
        // Save keys to file (bin)
        SavePrivateKey(strPrivateKey, rsaPrivate);
        SavePublicKey(strPublicKey, rsaPublic);
    }
    else if (strFormat == "Base64")
    {
        // Save keys to file (base64)
        SaveBase64PrivateKey(strPrivateKey, rsaPrivate);
        SaveBase64PublicKey(strPublicKey, rsaPublic);
    }
    else
    {
        cout << "Unsupported format. Please choose 'DER', 'Base64'. " << endl;
        exit(1);
    }

    Integer modul1 = rsaPrivate.GetModulus();      // modul n (from private)
    Integer prime1 = rsaPrivate.GetPrime1();       // prime p
    Integer prime2 = rsaPrivate.GetPrime2();       // prime p
    Integer SK = rsaPrivate.GetPrivateExponent(); // secret exponent d
    Integer PK = rsaPublic.GetPublicExponent();
    Integer modul2 = rsaPublic.GetModulus(); // modul n (from public)
    cout << " Modulo (private) n = " << modul1 << endl;
    cout << " Modulo (public) n = " << modul2 << endl;
    cout << " Prime number (private) p = " << std::hex << prime1 << endl;
    cout << " Prime number (public) q = " << prime2 << std::dec << endl;
    cout << " Secret exponent d =  " << SK << endl;
    cout << " Public exponent e = " << PK << endl; // 17?

    cout << "Successfully generated and saved RSA keys" << endl;
}

// Encryption
string RSAencrypt(const string format, const char *publicKeyFile, const char *PlaintextFile, const char *CipherFile)
{
    // Load key
    RSA::PublicKey rsaPublic;

    if (format == "DER")
    {
        LoadPublicKey(publicKeyFile, rsaPublic);
    }
    else if (format == "Base64")
    {
        LoadBase64PublicKey(publicKeyFile, rsaPublic);
    }
    else
    {
        cout << "Unsupported format";
        return "";
    }

    // Generate and save random number as hex
    RSAES_OAEP_SHA_Encryptor e(rsaPublic);
    AutoSeededRandomPool rng(true, 32);

    string plain, cipher, hex_cipher;
    FileSource(PlaintextFile, true, new StringSink(plain));

    // Encrypt and save cipher
    StringSource(plain, true,
                new PK_EncryptorFilter(rng, e,
                                        new StringSink(cipher)) // PK_EncryptorFilter
    );                                                          // StringSource

    StringSource(cipher, true,
                new FileSink(CipherFile, true));

    // Convert cipher to hex
    StringSource(cipher, true,
                new HexEncoder(
                    new StringSink(hex_cipher)));

    return hex_cipher;
}

// Decryption
string RSAdecrypt(const string format, const char *secretKeyFile, const char *CipherFile, const char *PlaintextFile)
{
    RSA::PrivateKey rsaPrivate;

    if (format == "DER")
        LoadPrivateKey(secretKeyFile, rsaPrivate);
    else if (format == "Base64")
        LoadBase64PrivateKey(secretKeyFile, rsaPrivate);
    else {
        cout << "Unsupported format";
        return "";
    }

    string cipher, plain;
    FileSource(CipherFile, true, new StringSink(cipher), true);

    // Decrypt and save plaintext
    AutoSeededRandomPool rng(true, 32);

    RSAES_OAEP_SHA_Decryptor d(rsaPrivate);
    StringSource(cipher, true,
                 new PK_DecryptorFilter(rng, d,
                                        new StringSink(plain)) // PK_EncryptorFilter
    );                                                         // StringSource

    StringSource(plain, true,
                 new FileSink(PlaintextFile, true));

    return plain;
}
string ToBinaryString(const string& input)
{
    string output;
    for (unsigned char c : input)
    {
        for (int i = 7; i >= 0; --i)
        {
            output += ((c >> i) & 1) ? '1' : '0';
        }
    }
    return output;
}

void HybridEncrypt(const string& format, const char* publicKeyFile, const char* plaintextFile, const char* cipherFile) {
    // Load RSA public key
    RSA::PublicKey publicKey;
    if (format == "Base64")
        LoadBase64PublicKey(publicKeyFile, publicKey);
    else
        LoadPublicKey(publicKeyFile, publicKey);
    
    // Generate random AES key and IV
    AutoSeededRandomPool rng;
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    byte aesIV[AES::BLOCKSIZE];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    rng.GenerateBlock(aesIV, sizeof(aesIV));
    
    // Encrypt the AES key with RSA-OAEP
    string encryptedKey;
    RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
    StringSource(aesKey, sizeof(aesKey), true,
        new PK_EncryptorFilter(rng, rsaEncryptor,
            new StringSink(encryptedKey)
        )
    );

    // Encrypt the file data with AES
    string encryptedData;
    CBC_Mode<AES>::Encryption aesEncryption(aesKey, sizeof(aesKey), aesIV);
    
    FileSource(plaintextFile, true,
        new StreamTransformationFilter(aesEncryption,
            new StringSink(encryptedData)
        )
    );
    
    // Write the IV, encrypted key, and encrypted data to output file
    ofstream output(cipherFile, ios::binary);
    
    // Format: [IV size][IV][Encrypted key size][Encrypted key][Encrypted data]
    word32 ivSize = AES::BLOCKSIZE;
    word32 keySize = encryptedKey.size();
    
    output.write((const char*)&ivSize, sizeof(ivSize));
    output.write((const char*)aesIV, ivSize);
    output.write((const char*)&keySize, sizeof(keySize));
    output.write(encryptedKey.data(), keySize);
    output.write(encryptedData.data(), encryptedData.size());
    // In ra các định dạng của encryptedKey và encryptedData
string encryptedKey_Hex, encryptedKey_Base64;
string encryptedData_Hex, encryptedData_Base64;
string encryptedKey_Bin , encryptedData_Bin;

// HEX
StringSource(encryptedKey, true, new HexEncoder(new StringSink(encryptedKey_Hex)));
StringSource(encryptedData, true, new HexEncoder(new StringSink(encryptedData_Hex)));

// BASE64
StringSource(encryptedKey, true, new Base64Encoder(new StringSink(encryptedKey_Base64), false));
StringSource(encryptedData, true, new Base64Encoder(new StringSink(encryptedData_Base64), false));
//BIN
StringSource(encryptedKey, true, new StringSink(encryptedKey_Bin));
StringSource(encryptedData, true, new StringSink(encryptedData_Bin));
// In ra màn hình
cout << "\n✅ Encrypted AES Key (HEX):\n" << encryptedKey_Hex << endl;
cout << "✅ Encrypted AES Key (Base64):\n" << encryptedKey_Base64 << endl;
cout << "\n✅ Encrypted Data (HEX) first 1000 characters:\n" << encryptedData_Hex.substr(0, 1000) << "..." << endl;
cout << "✅ Encrypted Data (Base64) first 1000 characters:\n" << encryptedData_Base64.substr(0, 1000) << "..." << endl;
cout << "✅ Encrypted Data (BIN - bit size): " << encryptedData.size() * 8 << " bits\n";
cout << "✅ Encrypted Data (BIN) first 1000 characters: " << ToBinaryString(encryptedData).substr(0,1000) << "\n";
    cout << "Hybrid encryption completed" << endl;
}

void HybridDecrypt(const string& format, const char* privateKeyFile, const char* cipherFile, const char* decryptedFile) {
   // Load RSA private key
RSA::PrivateKey privateKey;
if (format == "Base64")
    LoadBase64PrivateKey(privateKeyFile, privateKey);
else
    LoadPrivateKey(privateKeyFile, privateKey);

// Read the ciphertext file
ifstream input(cipherFile, ios::binary);
if (!input) {
    cerr << "Error opening ciphertext file" << endl;
    return;
}

// Read IV
word32 ivSize;
input.read((char*)&ivSize, sizeof(ivSize));

byte aesIV[AES::BLOCKSIZE];
input.read((char*)aesIV, ivSize);

// Read encrypted key
word32 keySize;
input.read((char*)&keySize, sizeof(keySize));

string encryptedKey(keySize, 0);
input.read(&encryptedKey[0], keySize);

// Read encrypted data
string encryptedData;
encryptedData.assign(
    (istreambuf_iterator<char>(input)),
    istreambuf_iterator<char>()
);

// Decrypt the AES key with RSA-OAEP
AutoSeededRandomPool rng;
string recoveredKey;
RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
StringSource(encryptedKey, true,
    new PK_DecryptorFilter(rng, rsaDecryptor,
        new StringSink(recoveredKey)
    )
);

// Decrypt the file data with AES
string recoveredData;
CBC_Mode<AES>::Decryption aesDecryption((byte*)recoveredKey.data(), recoveredKey.size(), aesIV);
StringSource(encryptedData, true,
    new StreamTransformationFilter(aesDecryption,
        new StringSink(recoveredData)
    )
);

// Write the decrypted data to output file
StringSource(recoveredData, true, new FileSink(decryptedFile));

// ✅ In nội dung đã giải mã ra màn hình
cout << "\n✅ Decrypted Data:\n";
if (recoveredData.empty()) {
    cout << "✅ Warning: Recovered data is empty.\n";
} else if (recoveredData.find('\0') != string::npos) {
    cout << "✅ Decrypted data may be binary. Display skipped to avoid terminal issues.\n";
} else {
    if (recoveredData.size() > 1000) {
        cout << recoveredData.substr(0, 1000) << "...\n";
        cout << "✅ (Output truncated — full data written to file)\n";
    } else {
        cout << recoveredData << endl;
    }
}

cout << "[+] Hybrid decryption completed\n";

}

void BenchmarkHybridEncryption(const string& format, const char* publicKeyFile, const char* plaintextFile, const char* cipherFile) {
    const int iterations = 10000;
    // Load the RSA public key once
    RSA::PublicKey publicKey;
    if (format == "Base64")
        LoadBase64PublicKey(publicKeyFile, publicKey);
    else
        LoadPublicKey(publicKeyFile, publicKey);
    // Read plaintext into memory once
    string plaintext;
    FileSource(plaintextFile, true, new StringSink(plaintext));
    // Generate AES key once
    AutoSeededRandomPool rng;
    byte aesKey[AES::DEFAULT_KEYLENGTH];
    rng.GenerateBlock(aesKey, sizeof(aesKey));
    // Time the RSA encryption of the AES key
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        string encryptedKey;
        RSAES_OAEP_SHA_Encryptor rsaEncryptor(publicKey);
        StringSource(aesKey, sizeof(aesKey), true,
            new PK_EncryptorFilter(rng, rsaEncryptor,
                new StringSink(encryptedKey)
            )
        );
    }
    clock_t end = clock();
    double elapsed = double(end - start) / CLOCKS_PER_SEC;
    cout << "RSA encryption time for " << iterations << " iterations: " << elapsed << " seconds" << endl;
    cout << "Average time per operation: " << (elapsed * 1000 / iterations) << " ms" << endl;
    // Actual encryption (once) to produce the output file
    HybridEncrypt(format, publicKeyFile, plaintextFile, cipherFile);
}

void BenchmarkHybridDecryption(const string& format, const char* privateKeyFile, const char* cipherFile, const char* decryptedFile) {
    const int iterations = 10000;
    // Load RSA private key once
    RSA::PrivateKey privateKey;
    if (format == "Base64")
        LoadBase64PrivateKey(privateKeyFile, privateKey);
    else
        LoadPrivateKey(privateKeyFile, privateKey);
    // Read encrypted key from file
    ifstream input(cipherFile, ios::binary);
    if (!input) {
        cerr << "Error opening ciphertext file" << endl;
        return;
    }
    // Skip IV size and IV
    word32 ivSize;
    input.read((char*)&ivSize, sizeof(ivSize));
    input.seekg(sizeof(ivSize) + ivSize, ios::beg);
    // Read encrypted key
    word32 keySize;
    input.read((char*)&keySize, sizeof(keySize));
    string encryptedKey(keySize, 0);
    input.read(&encryptedKey[0], keySize);
    
    // Time the RSA decryption of the AES key
    AutoSeededRandomPool rng;
    clock_t start = clock();
    for (int i = 0; i < iterations; i++) {
        string recoveredKey;
        RSAES_OAEP_SHA_Decryptor rsaDecryptor(privateKey);
        StringSource(encryptedKey, true,
            new PK_DecryptorFilter(rng, rsaDecryptor,
                new StringSink(recoveredKey)
            )
        );
    }
    clock_t end = clock();
    double elapsed = double(end - start) / CLOCKS_PER_SEC;
    cout << "RSA decryption time for " << iterations << " iterations: " << elapsed << " seconds" << endl;
    cout << "Average time per operation: " << (elapsed * 1000 / iterations) << " ms" << endl;
    
    // Actual decryption (once) to produce the output file
    HybridDecrypt(format, privateKeyFile, cipherFile, decryptedFile);
}

int main(int argc, char* argv[])
{
#ifdef _WIN32
    // Set console code page to UTF-8 on Windows
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif

if (argc < 2) {
	cerr << "Usage: " << endl;
	cerr << "./rsaoaep gen <keysize> <format> <privateKeyFile> <publicKeyFile>" << endl;
	cerr << "./rsaoaep enc <format> <publicKeyFile> <plainFile> <cipherFile>" << endl;
	cerr << "./rsaoaep dec <format> <privateKeyFile> <cipherFile> <plainFile>" << endl;
	cerr << "./rsaoaep benchmark_enc <format> <publicKeyFile> <plainFile> <cipherFile>" << endl;
	cerr << "./rsaoaep benchmark_dec <format> <privateKeyFile> <cipherFile> <plainFile>" << endl;
	return 1;
}

    string command = argv[1];

    try {
			if (command == "gen" && argc == 6) {
					int keySize = atoi(argv[2]);
					GenerateAndSaveRSAKeys(keySize, argv[3], argv[4], argv[5]);
			}
			else if (command == "enc" && argc == 6) {
					HybridEncrypt(argv[2], argv[3], argv[4], argv[5]);
			}
			else if (command == "dec" && argc == 6) {
					HybridDecrypt(argv[2], argv[3], argv[4], argv[5]);
			}
			else if (command == "benchmark_enc" && argc == 6) {
					BenchmarkHybridEncryption(argv[2], argv[3], argv[4], argv[5]);
			}
			else if (command == "benchmark_dec" && argc == 6) {
					BenchmarkHybridDecryption(argv[2], argv[3], argv[4], argv[5]);
			}
			else {
					cerr << "Invalid command or arguments" << endl;
					cerr << "Command format: ./rsaoaep <command> [options]" << endl;
					cerr << "Commands:" << endl;
					cerr << "  gen <keysize> <format> <privatekey> <publickey>" << endl;
					cerr << "  enc <format> <publickey> <plaintext> <ciphertext>" << endl;
					cerr << "  dec <format> <privatekey> <ciphertext> <decrypted>" << endl;
					cerr << "  benchmark_enc <format> <publickey> <plaintext> <ciphertext>" << endl;
					cerr << "  benchmark_dec <format> <privatekey> <ciphertext> <decrypted>" << endl;
					return 1;
			}
	} catch (const Exception& e) {
    cerr << "Error: " << e.what() << endl;
    return 1;
	} catch (const std::exception& e) {
			cerr << "Standard error: " << e.what() << endl;
			return 1;
	}

    return 0;
}

// Key handling functions
void SavePrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SavePublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void Save(const string &filename, const BufferedTransformation &bt)
{
    FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SaveBase64PrivateKey(const string &filename, const PrivateKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void SaveBase64PublicKey(const string &filename, const PublicKey &key)
{
    ByteQueue queue;
    key.Save(queue);
    SaveBase64(filename, queue);
}

void SaveBase64(const string &filename, const BufferedTransformation &bt)
{
    Base64Encoder encoder;
    bt.CopyTo(encoder);
    encoder.MessageEnd();
    Save(filename, encoder);
}

void LoadPrivateKey(const string &filename, PrivateKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPublicKey(const string &filename, PublicKey &key)
{
    ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Load(const string &filename, BufferedTransformation &bt)
{
    FileSource file(filename.c_str(), true /*pumpAll*/);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadBase64PrivateKey(const string &filename, RSA::PrivateKey &key)
{
    FileSource file(filename.c_str(), true, new Base64Decoder);
    ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.Load(queue);
    
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
    {
        throw runtime_error("Loaded private key is invalid.");
    }
}

void LoadBase64PublicKey(const string &filename, RSA::PublicKey &key)
{
    FileSource file(filename.c_str(), true, new Base64Decoder);
    ByteQueue queue;
    file.TransferTo(queue);
    queue.MessageEnd();
    key.Load(queue);
    
    AutoSeededRandomPool prng;
    if (!key.Validate(prng, 3))
    {
        throw runtime_error("Loaded public key is invalid.");
    }
}

void LoadBase64(const string &filename, BufferedTransformation &bt)
{
    throw runtime_error("Not implemented");
}