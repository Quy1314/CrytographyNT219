#include <iostream>
#include <fstream>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>

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

int main(char* argv[], int argc) {
    try {
        std::cout << "Generating RSA keys..." << std::endl;
        // Create a random number generator
        AutoSeededRandomPool rng;
        
        // Generate RSA keys (3072 bits for good security)
        RSA::PrivateKey privateKey;
        privateKey.GenerateRandomWithKeySize(rng, 3072);
        
        // Extract the public key from the private key
        RSA::PublicKey publicKey;
        publicKey.AssignFrom(privateKey);
        
        // Validate the keys
        bool result = privateKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Private key validation failed" << std::endl;
            return 1;
        }
        
        result = publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Public key validation failed" << std::endl;
            return 1;
        }
        
        std::cout << "Keys generated and validated successfully." << std::endl;
        
        // Save keys in DER format
        std::cout << "Saving keys in DER format..." << std::endl;
        SaveKeyToDERFile(privateKey, "private_key.der");
        SaveKeyToDERFile(publicKey, "public_key.der");
        
        // Convert to PEM format
        std::cout << "Converting keys to PEM format..." << std::endl;
        DERToPEM("private_key.der", "private_key.pem", 
                 "-----BEGIN RSA PRIVATE KEY-----", 
                 "-----END RSA PRIVATE KEY-----");
        
        DERToPEM("public_key.der", "public_key.pem", 
                 "-----BEGIN PUBLIC KEY-----", 
                 "-----END PUBLIC KEY-----");
        
        std::cout << "Keys saved in both DER and PEM formats." << std::endl;
        
    } catch (const Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}