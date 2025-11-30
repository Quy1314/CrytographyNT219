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

#ifdef _WIN32
#undef byte
#endif

using namespace CryptoPP;
using namespace std;

// --- Function Prototypes ---
void SavedToDER(const RSA::PrivateKey& key, const string& filename);
void SavedToDER(const RSA::PublicKey& key, const string& filename);
void DERToPEM(const string& derFilename, const string& pemFilename,
              const string& header, const string& footer);
string HexToBytes(const string& hex);
string BytesToHex(const string& bytes);
void WriteToFile(const string& filename, const string& data);
RSA::PublicKey LoadPublicKeyFromPEM(const string& pemFilename);
RSA::PublicKey LoadPublicKeyFromDER(const string& derFilename);
RSA::PrivateKey LoadPrivateKeyFromPEM(const string& pemFilename);
RSA::PrivateKey LoadPrivateKeyFromDER(const string& derFilename);

int main(int argc, char* argv[]) {
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    
    AutoSeededRandomPool prng;
    RSA::PrivateKey privateKey;
    RSA::PublicKey publicKey;
    
    bool keyGen = false;
    bool encrypt = false; // Kept but unused
    bool decrypt = false; // Kept but unused
    Integer n, e, d, p, q;

    int keySize = 3072;
    string privFilename = "private_key.pem";
    string pubFilename = "public_key.pem";

    for(int i = 1; i < argc; ++i) {
        string arg = argv[i];
        
        if (arg == "--genkey") {
            keyGen = true;
        }
        else if (arg == "--keylen" && i + 1 < argc) {
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
    }

    try {
        if(keyGen) {
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
        }
    }
    catch(const CryptoPP::Exception& e) {
        cerr << "CryptoPP Error: " << e.what() << endl;
        return 1;
    }
    catch(const exception& e) {
        cerr << "Error: " << e.what() << endl;
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
    string line, base64Data;
    bool inKey = false;
    
    while (std::getline(pemFile, line)) { 
        if (line == "-----BEGIN PUBLIC KEY-----") {
            inKey = true;
        } else if (line == "-----END PUBLIC KEY-----") {
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    // Decode the Base64 data
    string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    // Load the key
    RSA::PublicKey publicKey;
    ArraySource as(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true);
    publicKey.Load(as); 
    return publicKey;
}

RSA::PrivateKey LoadPrivateKeyFromPEM(const string& pemFilename) {
    ifstream pemFile(pemFilename);
    string line, base64Data;
    bool inKey = false;
    
    while (std::getline(pemFile, line)) { 
        if (line == "-----BEGIN RSA PRIVATE KEY-----") {
            inKey = true;
        } else if (line == "-----END RSA PRIVATE KEY-----") { // FIXED: String is now on one line
            inKey = false;
        } else if (inKey) {
            base64Data += line;
        }
    }
    
    // Decode the Base64 data
    string derData;
    StringSource ss(base64Data, true,
        new Base64Decoder(
            new StringSink(derData)
        )
    );
    
    // Load the key
    RSA::PrivateKey privateKey;
    ArraySource as(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true);
    privateKey.Load(as);
    return privateKey;
}