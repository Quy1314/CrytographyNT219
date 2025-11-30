#include <iostream>
#include <fstream>
#include <vector>
#include <cryptopp/rsa.h>
#include <cryptopp/osrng.h>
#include <cryptopp/queue.h>
#include <cryptopp/files.h>
#include <cryptopp/base64.h>
#include <cryptopp/filters.h>
#include <cryptopp/integer.h>

using namespace CryptoPP;
using CryptoPP::byte;

// Lưu key ra file DER
template<class KEY>
void SaveKeyToDERFile(const KEY& key, const std::string& filename) {
    ByteQueue queue;
    key.Save(queue);
    FileSink file(filename.c_str());
    queue.CopyTo(file);
    file.MessageEnd();
}

// Chuyển DER sang PEM
void DERToPEM(const std::string& derFilename, const std::string& pemFilename,
              const std::string& header, const std::string& footer) {
    std::ifstream derFile(derFilename, std::ios::binary);
    std::vector<char> derData((std::istreambuf_iterator<char>(derFile)),
                               std::istreambuf_iterator<char>());
    derFile.close();

    std::string base64Data;
    StringSource ss(reinterpret_cast<const CryptoPP::byte*>(derData.data()), derData.size(), true,
        new Base64Encoder(new StringSink(base64Data), true, 64)
    );

    std::ofstream pemFile(pemFilename);
    pemFile << header << std::endl;
    pemFile << base64Data;
    pemFile << footer << std::endl;
    pemFile.close();
}

int main(int argc, char* argv[]) {
    try {
        std::cout << "Generating RSA keys..." << std::endl;

        Integer p, q, n, e, d;
        bool keyGen = false , encrypt= false , decrypt= false;
        for (int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--p") p = Integer(argv[++i]);
            else if (arg == "--q") q = Integer(argv[++i]);
            else if (arg == "--n") n = Integer(argv[++i]);
            else if (arg == "--e") e = Integer(argv[++i]);
            else if (arg == "--d") d = Integer(argv[++i]);
            else if (arg == "--keygen") keyGen = true;
            else if (arg == "--encrypt") encrypt = true;
            else if (arg == "--decrypt") decrypt = true;
        }
        try{
            if()
        }

        AutoSeededRandomPool rng;

        // Nếu người dùng truyền đủ n, e, d thì đặt thủ công
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;

        if (!n.IsZero() && !e.IsZero() && !d.IsZero()) {
            std::cout << "Setting RSA keys manually..." << std::endl;
            privateKey.Initialize(n, e, d);
            publicKey.AssignFrom(privateKey);
        } else {
            std::cout << "Generating new RSA key pair..." << std::endl;
            privateKey.GenerateRandomWithKeySize(rng, 3072);
            publicKey.AssignFrom(privateKey);
        }

        // Kiểm tra khóa
        bool result = privateKey.Validate(rng, 3) && publicKey.Validate(rng, 3);
        if (!result) {
            std::cerr << "Key validation failed!" << std::endl;
            return 1;
        }

        std::cout << "Keys generated and validated successfully." << std::endl;

        std::cout << "Saving keys in DER format..." << std::endl;
        SaveKeyToDERFile(privateKey, "private_key.der");
        SaveKeyToDERFile(publicKey, "public_key.der");

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
