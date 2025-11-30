/*
.\RSA.exe --genkey --bits 3072 
.\RSA.exe --encrypt --text HelloWorld --verbose --encode hex
.\RSA.exe --decrypt --in output.bin --verbose --encode hex
*/

#include <cryptlib.h>
#include <hex.h>
#include <base64.h>
#include <filters.h>
#include <rsa.h>
#include <files.h>
#include <osrng.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <chrono>
#include <thread>
#include <aes.h>
#include <gcm.h>
#include <modes.h>
#include <cctype> 
#include <algorithm> 
#include <ctime>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
#undef byte
#endif

using namespace CryptoPP;
using namespace std; 

// --- Function Prototypes ---
void PrintHelp();
void SavedToDER(const RSA::PrivateKey& key, const string& filename);
void SavedToDER(const RSA::PublicKey& key, const string& filename);
void DERToPEM(const string& derFilename, const string& pemFilename,
              const string& header, const string& footer);
string HexToBytes(const string& hex);
string BytesToHex(const string& bytes);
string Base64ToBytes(const string& base64);
string BytesToBase64(const string& bytes);
string Base64ToHex(const string& base64);
string HexToBase64(const string& hex);
void ModifyExtension(string& filename); 
void HardCoredKeyExtension(string& pubFilename, string& privFilename);
void WriteToFile(const string& filename, const string& data);
void ReadFromFile(const string& filename, string& data);
RSA::PublicKey LoadPublicKeyFromPEM(const string& pemFilename);
RSA::PublicKey LoadPublicKeyFromDER(const string& derFilename);
RSA::PrivateKey LoadPrivateKeyFromPEM(const string& pemFilename);
RSA::PrivateKey LoadPrivateKeyFromDER(const string& derFilename);
string Encrypt(const RSA::PublicKey& publicKey, const string& plaintext);
string Decrypt(const RSA::PrivateKey& privateKey, const string& ciphertext);
string HybridEncrypt(const RSA::PublicKey& publicKey, const string& plaintext);
string HybridDecrypt(const RSA::PrivateKey& privateKey, const string& ciphertext);
string DetectFormat(const string& data);
void DoEncryption(const string input, const RSA::PublicKey& publicKey, const string& outputFilename, const string& format, string& mode);
void DoDecryption(const string& input, const RSA::PrivateKey& privateKey, const string& outputFilename, string& format);
void DoKeyGeneration(int keySize, const string& privFilename, const string& pubFilename,
                     const Integer& n, const Integer& e, const Integer& d,
                     const Integer& p, const Integer& q);

// --- JSON & Metadata Prototypes ---
string GetCurrentTimestamp();
string EscapeJsonString(const string& input);
void StoreKeyMetadata(const string& filename, int keySize, const string& hashName, const string& keyType);
string ParseJson(const string& jsonContent, const string& key);

int main(int argc, char* argv[]) {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    
    // Check arguments immediately
    if (argc < 2) {
        PrintHelp();
        return 0;
    }

    AutoSeededRandomPool prng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    
    bool keyGen = false;
    bool encrypt = false;
    bool decrypt = false;
    bool verbose = false;
    Integer n, e, d, p, q;

    int keySize = 3072;
    string privFilename = "private_key.pem";
    string pubFilename = "public_key.pem";

    string inFilename = "";
    string outFilename = "output.bin";
    string inText = "";
    string format="auto";
    string mode="normal"; 

    for(int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "--genkey") {
            keyGen = true;
        }
        else if (arg == "--help" || arg == "-h") {
            PrintHelp();
            return 0;
        }
        else if (arg == "--verbose") {
            verbose = true;
        }
        else if (arg == "--encrypt") {
            encrypt = true;
        }
        else if (arg == "--decrypt") {
            decrypt = true;
        }
        // FIXED: Added --keylen support and removed space from --bits
        else if ((arg == "--bits" || arg == "--keylen") && i + 1 < argc) {
            keySize = stoi(argv[++i]);
        }
        else if (arg == "--pub" && i + 1 < argc) {
            pubFilename = argv[++i];
        }
        else if (arg == "--priv" && i + 1 < argc) {
            privFilename = argv[++i];
        }
        else if (arg == "--n" && i + 1 < argc) {
            string val = HexToBytes(argv[++i]);
            n = Integer((const CryptoPP::byte*)val.data(), val.size());
        }
        else if (arg == "--e" && i + 1 < argc) {
            string val = HexToBytes(argv[++i]);
            e = Integer((const CryptoPP::byte*)val.data(), val.size());
        }
        else if (arg == "--d" && i + 1 < argc) {
            string val = HexToBytes(argv[++i]);
            d = Integer((const CryptoPP::byte*)val.data(), val.size());
        }
        else if (arg == "--p" && i + 1 < argc) {
            string val = HexToBytes(argv[++i]);
            p = Integer((const CryptoPP::byte*)val.data(), val.size());
        }
        else if (arg == "--q" && i + 1 < argc) {
            string val = HexToBytes(argv[++i]);
            q = Integer((const CryptoPP::byte*)val.data(), val.size());
        }
        else if (arg == "--in" && i + 1 < argc) {
            inFilename = argv[++i];
        }
        else if (arg == "--out" && i + 1 < argc) {
            outFilename = argv[++i];
        }
        else if (arg == "--text" && i + 1 < argc) {
            inText = argv[++i];
        }
        else if (arg == "--encode" && i + 1 < argc) {
            format = argv[++i];
        }
    }

    // Only modify extensions if we are actually doing something relevant
    if (keyGen || encrypt || decrypt) {
        HardCoredKeyExtension(pubFilename, privFilename);
    }
    
    ModifyExtension(outFilename); 
    
    string plaintext;
    if(!inFilename.empty()) {
        ifstream inFile(inFilename, ios::binary);
        if (!inFile) {
            cerr << "Error: Cannot open input file: " << inFilename << endl;
            return 1;
        }
        plaintext.assign((istreambuf_iterator<char>(inFile)),
                         istreambuf_iterator<char>());
        inFile.close();
        } else if(!inText.empty()) {
        plaintext = inText;
    }

    try{
        if(keyGen) {
            DoKeyGeneration(keySize, privFilename, pubFilename, n, e, d, p, q);
        }
        if(encrypt) {
            // Load the specific public key file provided by user (or default if not provided)
            if (verbose) cout << "Loading public key from: " << pubFilename << endl;
            publicKey = LoadPublicKeyFromPEM(pubFilename);
            
            DoEncryption(plaintext, publicKey, outFilename, format, mode);
            
            if(verbose){
                cout<<"Key Size: "<<publicKey.GetModulus().BitCount()<<" bits"<<endl;
                cout<<"Public Key File: "<<pubFilename<<endl;
                cout<<"Input Data Size: "<<plaintext.size()<<" bytes"<<endl;
                cout<<"Output File: "<<outFilename<<endl;
                cout<<"Encryption Mode: "<<mode<<endl;
                cout<<"Output Format: "<<(format == "auto" ? "raw" : format)<<endl;
                cout<<"Encryption completed successfully."<<endl;
            }
        }
        if(decrypt) {
            // Load the specific private key file provided by user (or default if not provided)
             if (verbose) cout << "Loading private key from: " << privFilename << endl;
            privateKey = LoadPrivateKeyFromPEM(privFilename);
            
            DoDecryption(plaintext, privateKey, outFilename, format);
            
            if(verbose){
                cout<<"Key Size: "<<privateKey.GetModulus().BitCount()<<" bits"<<endl;
                cout<<"Private Key File: "<<privFilename<<endl;
                cout<<"Input Data Size: "<<plaintext.size()<<" bytes"<<endl;
                cout<<"Detected Format: "<<format<<endl;
                cout<<"Output File: "<<outFilename<<endl;
                cout<<"Decryption completed successfully."<<endl;
            }
        }
    }
    catch(const exception& ex) {
        cerr << "Error: " << ex.what() << endl;
        return 1;
    }
    return 0;
}

// --- Implementation of Helper Functions ---

void SavedToDER(const RSA::PrivateKey& key, const string& filename) {
    FileSink file(filename.c_str());
    key.DEREncode(file);
}

void SavedToDER(const RSA::PublicKey& key, const string& filename) {
    FileSink file(filename.c_str());
    key.DEREncode(file);
}

void DERToPEM(const string& derFilename, const string& pemFilename,
              const string& header, const string& footer) {
    ifstream derFile(derFilename, ios::binary);
    if (!derFile) throw runtime_error("Cannot open DER file: " + derFilename);

    vector<char> derData((istreambuf_iterator<char>(derFile)),
                         istreambuf_iterator<char>());
    derFile.close();

    string base64Data;
    StringSource ss(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true,
        new Base64Encoder(
            new StringSink(base64Data),
            true, // line breaks
            64    // max line length
        )
    );

    ofstream pemFile(pemFilename);
    if (!pemFile) throw runtime_error("Cannot open PEM file for writing: " + pemFilename);
    
    pemFile << header << endl;
    pemFile << base64Data;
    pemFile << footer << endl;
    pemFile.close();
}

string HexToBytes(const string& hex) { 
    string bytes;
    StringSource(hex, true, new HexDecoder(new StringSink(bytes)));
    return bytes;
}

string BytesToHex(const string& bytes) { 
    string hex;
    StringSource(bytes, true, new HexEncoder(new StringSink(hex), false));
    return hex;
}

string Base64ToBytes(const string& base64) {
    string bytes;
    StringSource(base64, true, new Base64Decoder(new StringSink(bytes)));
    return bytes;
}

string BytesToBase64(const string& bytes) {
    string base64;
    StringSource(bytes, true, new Base64Encoder(new StringSink(base64), false));
    return base64;
}

string Base64ToHex(const string& base64) {
    string bytes = Base64ToBytes(base64);
    return BytesToHex(bytes);
}

string HexToBase64(const string& hex) {
    string bytes = HexToBytes(hex);
    return BytesToBase64(bytes);
}

void WriteToFile(const string& filename, const string& data) { 
    try {
        FileSink file(filename.c_str());
        file.Put(reinterpret_cast<const CryptoPP::byte*>(data.data()), data.size());
        file.MessageEnd();
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error("File write error (" + filename + "): " + e.what());
    }
}

RSA::PublicKey LoadPublicKeyFromDER(const string& derFilename) {
    RSA::PublicKey publicKey;
    FileSource file(derFilename.c_str(), true);
    publicKey.Load(file);
    return publicKey;
}

RSA::PrivateKey LoadPrivateKeyFromDER(const string& derFilename) {
    RSA::PrivateKey privateKey;
    FileSource file(derFilename.c_str(), true);
    privateKey.Load(file);
    return privateKey;
}

RSA::PublicKey LoadPublicKeyFromPEM(const string& pemFilename) {
    ifstream pemFile(pemFilename);
    if (!pemFile) throw runtime_error("Cannot open public key file: " + pemFilename);

    string line, base64Data;
    bool inKey = false;
    
    while (getline(pemFile, line)) { 
        if (line == "-----BEGIN PUBLIC KEY-----") {
            inKey = true;
        } else if (line == "-----END PUBLIC KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    RSA::PublicKey publicKey;
    ArraySource as(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true);
    publicKey.Load(as);
    
    return publicKey;
}

RSA::PrivateKey LoadPrivateKeyFromPEM(const string& pemFilename) {
    ifstream pemFile(pemFilename);
    if (!pemFile) throw runtime_error("Cannot open private key file: " + pemFilename);

    string line, base64Data;
    bool inKey = false;
    
    while (getline(pemFile, line)) { 
        if (line.find("-----BEGIN RSA PRIVATE KEY-----") != string::npos) {
            inKey = true;
        } else if (line.find("-----END RSA PRIVATE KEY-----") != string::npos) {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);
    return privateKey;
}

string Encrypt(const RSA::PublicKey& publicKey, const string& plaintext) {
    AutoSeededRandomPool prng;
    string ciphertext;
    
    RSAES_OAEP_SHA256_Encryptor encryptor(publicKey);
    StringSource ss(plaintext, true,
        new PK_EncryptorFilter(prng, encryptor,
            new StringSink(ciphertext)
        )
    );
    
    return ciphertext;
}

string HybridEncrypt(const RSA::PublicKey& publicKey, const string& plaintext) {
    AutoSeededRandomPool prng;
    // Generate a random AES key
    SecByteBlock aesKey(AES::MAX_KEYLENGTH);
    prng.GenerateBlock(aesKey, aesKey.size());
    
    // Generate IV
    string iv;
    iv.resize(AES::BLOCKSIZE);
    prng.GenerateBlock(reinterpret_cast<CryptoPP::byte*>(&iv[0]), iv.size());
    
    // Encrypt the plaintext with AES
    string aesCiphertext;
    GCM<AES>::Encryption aesEncryptor;
    aesEncryptor.SetKeyWithIV(aesKey, aesKey.size(), reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());
    StringSource ss1(plaintext, true,
        new AuthenticatedEncryptionFilter(aesEncryptor,
            new StringSink(aesCiphertext)
        )
    );

    // Encrypt the AES key with RSA
    string encryptedAesKey;
    RSAES_OAEP_SHA256_Encryptor rsaEncryptor(publicKey);
    StringSource ss2(aesKey, aesKey.size(), true,
        new PK_EncryptorFilter(prng, rsaEncryptor,
            new StringSink(encryptedAesKey)
        )
    );
    
    // Combine: [Encrypted AES Key] + [IV] + [AES Ciphertext + MAC]
    string combinedCiphertext;
    combinedCiphertext += encryptedAesKey;
    combinedCiphertext += iv;
    combinedCiphertext += aesCiphertext;
    return combinedCiphertext;
}

string HybridDecrypt(const RSA::PrivateKey& privateKey, const string& ciphertext) {
    AutoSeededRandomPool prng;
    size_t rsaKeySize = privateKey.GetModulus().ByteCount();
    
    // Safety check: Ciphertext must be at least size of (RSA Key + IV + MAC)
    if (ciphertext.size() <= rsaKeySize + AES::BLOCKSIZE) {
        throw runtime_error("HybridDecrypt: Ciphertext too short. May be raw RSA or corrupted.");
    }

    // Extract components
    string encryptedAesKey = ciphertext.substr(0, rsaKeySize);
    string iv = ciphertext.substr(rsaKeySize, AES::BLOCKSIZE);
    string aesCiphertext = ciphertext.substr(rsaKeySize + AES::BLOCKSIZE);
    
    // Decrypt the AES key with RSA
    string aesKey;
    try {
        RSAES_OAEP_SHA256_Decryptor rsaDecryptor(privateKey);
        StringSource ss1(encryptedAesKey, true,
            new PK_DecryptorFilter(prng, rsaDecryptor,
                new StringSink(aesKey)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error("HybridDecrypt: Failed to decrypt session key. Causes:\n  1. Wrong Private Key.\n  2. Input format mismatch (did you forget --encode hex/base64?).\n  3. Corrupted ciphertext.");
    }
    
    // Decrypt the AES ciphertext
    string plaintext;
    try {
        GCM<AES>::Decryption aesDecryptor;
        aesDecryptor.SetKeyWithIV(reinterpret_cast<const CryptoPP::byte*>(aesKey.data()), aesKey.size(),
                                  reinterpret_cast<const CryptoPP::byte*>(iv.data()), iv.size());
        StringSource ss2(aesCiphertext, true,
            new AuthenticatedDecryptionFilter(aesDecryptor,
                new StringSink(plaintext)
            )
        );
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error("HybridDecrypt: AES GCM decryption failed (Integrity Check Error). Data corrupted?");
    }
    
    return plaintext;
}

string DetectFormat(const string& data) {
    // 1. Check for High Entropy/Binary data (Raw)
    for (unsigned char c : data) {
        if (!isprint(c) && !isspace(c)) {
            return "raw";
        }
    }

    string cleanData;
    for (char c : data) {
        if (!isspace(c)) cleanData += c;
    }
    
    if (cleanData.empty()) return "raw";

    // 2. Check if it looks like Hex
    bool isHex = true;
    for (char c : cleanData) {
        if (!isxdigit(c)) {
            isHex = false;
            break;
        }
    }
    if (isHex && (cleanData.size() % 2 == 0)) {
        return "hex";
    }

    // 3. Check if it looks like Base64
    bool isBase64 = true;
    for (char c : cleanData) {
        if (!isalnum(c) && c != '+' && c != '/' && c != '=') {
            isBase64 = false;
            break;
        }
    }
    if (isBase64 && (cleanData.size() % 4 == 0)) {
        return "base64";
    }

    return "raw";
}

void DoEncryption(const string input, const RSA::PublicKey& publicKey, const string& outputFilename, const string& format, string& mode) {
    size_t maxRsaEncryptSize = publicKey.GetModulus().ByteCount() - 2 * SHA256::DIGESTSIZE - 2;
    
    string ciphertext;
    if(input.size() <= maxRsaEncryptSize) {
        mode = "normal";
        auto start = chrono::high_resolution_clock::now();
        ciphertext = Encrypt(publicKey, input);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "[Time]: " << duration << " us" << endl;
    } else {

        mode = "hybrid";
        auto start = chrono::high_resolution_clock::now();
        ciphertext = HybridEncrypt(publicKey, input);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "[Time]: " << duration << " us" << endl;
    }

    if(format == "hex") {
        ciphertext = BytesToHex(ciphertext);
    } else if(format == "base64") {
        ciphertext = BytesToBase64(ciphertext);
    }
    WriteToFile(outputFilename, ciphertext);
}

void DoDecryption(const string& inputDataRaw, const RSA::PrivateKey& privateKey, const string& outputFile, string& format) {
    string ciphertext;
    
    if (format == "auto") {
        format = DetectFormat(inputDataRaw);
    }

    if(format == "hex") {
        ciphertext = HexToBytes(inputDataRaw);
    } else if(format == "base64") {
        ciphertext = Base64ToBytes(inputDataRaw);
    } else {
        ciphertext = inputDataRaw;
    }

    string plaintext;
    size_t rsaModulusSize = privateKey.GetModulus().ByteCount();

    if (ciphertext.size() > rsaModulusSize) {
        auto start = chrono::high_resolution_clock::now();
        plaintext = HybridDecrypt(privateKey, ciphertext);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "[Time]: " << duration << " us" << endl;
    } 
    else if (ciphertext.size() == rsaModulusSize) {
        auto start = chrono::high_resolution_clock::now();
        plaintext = Decrypt(privateKey, ciphertext);
        auto end = chrono::high_resolution_clock::now();
        auto duration = chrono::duration_cast<chrono::microseconds>(end - start).count();
        cout << "[Time]: " << duration << " us" << endl;
    } 
    else {
        throw runtime_error("Input data size (" + to_string(ciphertext.size()) + " bytes) is too small or mismatched for the loaded key (" + to_string(rsaModulusSize) + " bytes).");
    }

    WriteToFile(outputFile, plaintext);
}

void DoKeyGeneration(int keySize, const string& privFilename, const string& pubFilename,
                     const Integer& n, const Integer& e, const Integer& d,
                     const Integer& p, const Integer& q) {
    AutoSeededRandomPool prng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;

    if(!n.IsZero() && !e.IsZero() && !d.IsZero()) {
        cout << "Setting RSA keys manually..." << endl;
        privateKey.Initialize(n, e, d);
        publicKey.AssignFrom(privateKey);
    }
    else {
        cout << "Generating new RSA key pair (" << keySize << " bits)..." << endl;
        privateKey.GenerateRandomWithKeySize(prng, keySize);
        publicKey.AssignFrom(privateKey);
    }

    if(!privateKey.Validate(prng, 3) || !publicKey.Validate(prng, 3)) {
        throw runtime_error("RSA key validation failed.");
    }
    cout << "Key pair generated and validated." << endl;

    string privDer = privFilename.substr(0, privFilename.find_last_of('.')) + ".der";
    string pubDer = pubFilename.substr(0, pubFilename.find_last_of('.')) + ".der";

    SavedToDER(privateKey, privDer);
    DERToPEM(privDer, privFilename,
             "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----");

    SavedToDER(publicKey, pubDer);
    DERToPEM(pubDer, pubFilename,
             "-----BEGIN PUBLIC KEY-----", "-----END PUBLIC KEY-----");

    cout << "Saved private key to: " << privFilename << " (and " << privDer << ")" << endl;
    cout << "Saved public key to:  " << pubFilename << " (and " << pubDer << ")" << endl;

    // --- Store Metadata ---
    // SHA-256 is hardcoded in RSAES_OAEP_SHA256 used by this tool
    StoreKeyMetadata(privFilename, keySize, "SHA-256", "RSA Private Key");
    StoreKeyMetadata(pubFilename, keySize, "SHA-256", "RSA Public Key");
}

void ReadFromFile(const string& filename, string& data) {
    try {
        FileSource file(filename.c_str(), true,
            new StringSink(data)
        );
    } catch (const CryptoPP::Exception& e) {
        throw runtime_error("File read error (" + filename + "): " + e.what());
    }
}

void ModifyExtension(string& filename) {
    size_t pos = filename.find_last_of('.');
    if (pos != string::npos) {
        filename = filename.substr(0, pos) + ".bin";
    } else {
        filename += ".bin";
    }
}

string Decrypt(const RSA::PrivateKey& privateKey, const string& ciphertext) {
    AutoSeededRandomPool prng;
    string plaintext;
    
    RSAES_OAEP_SHA256_Decryptor decryptor(privateKey);
    StringSource ss(ciphertext, true,
        new PK_DecryptorFilter(prng, decryptor,
            new StringSink(plaintext)
        )
    );
    return plaintext;
}

// --- JSON & Metadata Implementation ---

string GetCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&now_c), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

string EscapeJsonString(const string& input) {
    string output;
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:   output += c; break;
        }
    }
    return output;
}

void StoreKeyMetadata(const string& filename, int keySize, const string& hashName, const string& keyType) {
    string metaFilename = filename + ".meta.json";
    ofstream outFile(metaFilename);
    
    if (!outFile) {
        cerr << "Warning: Could not save metadata to " << metaFilename << endl;
        return;
    }

    string timestamp = GetCurrentTimestamp();

    outFile << "{" << endl;
    outFile << "  \"creation_time\": \"" << EscapeJsonString(timestamp) << "\"," << endl;
    outFile << "  \"modulus_size_bits\": " << keySize << "," << endl;
    outFile << "  \"hash_algorithm\": \"" << EscapeJsonString(hashName) << "\"," << endl;
    outFile << "  \"key_type\": \"" << EscapeJsonString(keyType) << "\"," << endl;
    outFile << "  \"associated_file\": \"" << EscapeJsonString(filename) << "\"" << endl;
    outFile << "}" << endl;

    cout << "Stored key metadata in: " << metaFilename << endl;
}

// Simple JSON parser (heuristic based) to find value by key
// Note: This is not a full JSON parser, it just searches for "key": "value" or "key": number
string ParseJson(const string& jsonContent, const string& key) {
    string searchKey = "\"" + key + "\"";
    size_t keyPos = jsonContent.find(searchKey);
    
    if (keyPos == string::npos) return ""; // Key not found

    // Find colon after key
    size_t colonPos = jsonContent.find(':', keyPos);
    if (colonPos == string::npos) return "";

    // Find start of value (skip whitespace)
    size_t valueStart = colonPos + 1;
    while (valueStart < jsonContent.size() && isspace(jsonContent[valueStart])) {
        valueStart++;
    }

    if (valueStart >= jsonContent.size()) return "";

    char startChar = jsonContent[valueStart];
    string value;

    if (startChar == '"') {
        // String value
        size_t endQuote = jsonContent.find('"', valueStart + 1);
        if (endQuote != string::npos) {
            value = jsonContent.substr(valueStart + 1, endQuote - valueStart - 1);
        }
    } else {
        // Number or boolean (read until comma, newline or brace)
        size_t valueEnd = valueStart;
        while (valueEnd < jsonContent.size() && 
               jsonContent[valueEnd] != ',' && 
               jsonContent[valueEnd] != '}' && 
               jsonContent[valueEnd] != '\n') {
            valueEnd++;
        }
        value = jsonContent.substr(valueStart, valueEnd - valueStart);
    }

    return value;
}

void HardCoredKeyExtension(string& pubFilename, string& privFilename){
    size_t pubPos = pubFilename.find_last_of('.');
    if (pubPos != string::npos) {
        pubFilename = pubFilename.substr(0, pubPos) + ".pem";
    } else {
        pubFilename += ".pem";
    }
    size_t privPos = privFilename.find_last_of('.');
    if (privPos != string::npos) {
        privFilename = privFilename.substr(0, privPos) + ".pem";
    } else {
        privFilename += ".pem";
    }
}

void PrintHelp() { 
    std::cout <<
R"(mytool - RSA CLI
===================================

Usage:
  mytool <command> [--in INFILE | --text "..."] [--out OUTFILE]
         [--pub PUBFILE] [--priv PRIVFILE] [--bits BITS]
         [--encode hex|base64] [--verbose] [--help]

Commands:
  --genkey              Generate a new RSA key pair.
  --encrypt             Encrypt input (uses Public Key).
                        Note: Automatically switches to Hybrid (RSA+AES) for large data.
  --decrypt             Decrypt input (uses Private Key).

Options:
  --in INFILE           Input file path.
  --text "..."          Input text provided inline.
  --out OUTFILE         Output file (default: output.bin).

  --pub PUBFILE         Public key file path (default: public_key.pem).
  --priv PRIVFILE       Private key file path (default: private_key.pem).
  --keylen BITS         RSA Key length in bits (default: 3072).

  --encode FORMAT       Output encoding for encryption: hex | base64.
                        (Decryption auto-detects format if not raw).

  --verbose             Verbose output (show parameters and steps).
  --help                Show this help message and exit.

Manual Key Components (for --genkey manual setup):
  --n HEX               Modulus (n) in Hex.
  --e HEX               Public Exponent (e) in Hex.
  --d HEX               Private Exponent (d) in Hex.
  --p HEX               Prime 1 (p) in Hex.
  --q HEX               Prime 2 (q) in Hex.

Notes:
  - Hybrid Encryption: Small data uses RSA-OAEP-SHA256 directly. 
    Data larger than the RSA modulus uses AES-GCM (random 256-bit key), 
    and the AES key is then RSA encrypted.
  - Metadata: Encryption/GenKey creates a '.meta.json' sidecar file.
)";
}