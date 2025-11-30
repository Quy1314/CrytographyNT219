#include <iostream>
#include <string>
#include <cryptlib.h>
#include <hex.h>
#include <filters.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <gcm.h>

using namespace CryptoPP;

void GenerateAESKey(byte key[], byte iv[]) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);  // 16-byte key
    prng.GenerateBlock(iv, AES::BLOCKSIZE);          // 16-byte IV
}

// Encrypt function supporting CBC, ECB, GCM
std::string AESEncrypt(const std::string& plaintext, const byte key[], const byte iv[], int choice, const std::string& AAD) {
    std::string ciphertext;

    switch(choice){
        case 0: { // CBC
            try {
                CBC_Mode<AES>::Encryption encryptor;
                encryptor.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

                StringSource(plaintext, true,
                    new StreamTransformationFilter(encryptor,
                        new StringSink(ciphertext),
                        StreamTransformationFilter::PKCS_PADDING
                    )
                );
            } catch (const Exception& e) {
                std::cerr << "CBC Encryption Error: " << e.what() << std::endl;
            }
            break;
        }
        case 1: { // ECB
            try {
                ECB_Mode<AES>::Encryption encryptor;
                encryptor.SetKey(key, AES::DEFAULT_KEYLENGTH);

                StringSource(plaintext, true,
                    new StreamTransformationFilter(encryptor,
                        new StringSink(ciphertext),
                        StreamTransformationFilter::PKCS_PADDING
                    )
                );
            } catch (const Exception& e) {
                std::cerr << "ECB Encryption Error: " << e.what() << std::endl;
            }
            break;
        }
        case 2: { // GCM
            try {
                GCM<AES>::Encryption encryptor;
                encryptor.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);

                AuthenticatedEncryptionFilter ef(encryptor,
                    new StringSink(ciphertext),
                    AuthenticatedEncryptionFilter::NO_PADDING  // thay DEFAULT_FLAGS
                );

                if(!AAD.empty())
                    ef.ChannelPut("AAD", (const byte*)AAD.data(), AAD.size());

                ef.ChannelPut("", (const byte*)plaintext.data(), plaintext.size());
                ef.ChannelMessageEnd("");
            } catch (const Exception& e) {
                std::cerr << "GCM Encryption Error: " << e.what() << std::endl;
            }
            break;
        }
        default:
            std::cerr << "Invalid AES mode choice." << std::endl;
            return "";
    }

    return ciphertext;
}

// Decrypt function supporting CBC, ECB, GCM
std::string AESDecrypt(const std::string& ciphertext, const byte key[], const byte iv[], int choice, const std::string& AAD) {
    std::string decryptedText;

    switch(choice){
        case 0: { // CBC
            try {
                CBC_Mode<AES>::Decryption decryptor;
                decryptor.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);

                StringSource(ciphertext, true,
                    new StreamTransformationFilter(decryptor,
                        new StringSink(decryptedText),
                        StreamTransformationFilter::PKCS_PADDING
                    )
                );
            } catch (const Exception& e) {
                std::cerr << "CBC Decryption Error: " << e.what() << std::endl;
            }
            break;
        }
        case 1: { // ECB
            try {
                ECB_Mode<AES>::Decryption decryptor;
                decryptor.SetKey(key, AES::DEFAULT_KEYLENGTH);

                StringSource(ciphertext, true,
                    new StreamTransformationFilter(decryptor,
                        new StringSink(decryptedText),
                        StreamTransformationFilter::PKCS_PADDING
                    )
                );
            } catch (const Exception& e) {
                std::cerr << "ECB Decryption Error: " << e.what() << std::endl;
            }
            break;
        }
        case 2: { // GCM
            try {
                GCM<AES>::Decryption decryptor;
                decryptor.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);

                AuthenticatedDecryptionFilter df(decryptor,
                    new StringSink(decryptedText),
                    AuthenticatedDecryptionFilter::THROW_EXCEPTION  // bỏ PUT_MESSAGE
                );

                if(!AAD.empty())
                    df.ChannelPut("AAD", (const byte*)AAD.data(), AAD.size());

                df.ChannelPut("", (const byte*)ciphertext.data(), ciphertext.size());
                df.ChannelMessageEnd("");
            } catch (const Exception& e) {
                std::cerr << "GCM Decryption Error: " << e.what() << std::endl;
                return "";
            }
            break;
        }
        default:
            std::cerr << "Invalid AES mode choice." << std::endl;
            return "";
    }

    return decryptedText;
}

void PrintHex(const std::string& label, const std::string& data) {
    std::string encoded;
    StringSource(data, true, new HexEncoder(new StringSink(encoded)));
    std::cout << label << encoded << std::endl;
}

int main() {
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    GenerateAESKey(key, iv);

    std::string plaintext = "Crypto++ AES Test";
    std::cout << "Original Text: " << plaintext << std::endl;

    int choice;
    std::cout << "Choose AES mode (CBC=0, ECB=1, GCM=2): ";
    std::cin >> choice;
    std::cin.ignore();

    std::string AAD;
    if(choice == 2){
        std::cout << "Enter AAD: ";
        std::getline(std::cin, AAD);
    }

    std::string ciphertext = AESEncrypt(plaintext, key, iv, choice, AAD);
    PrintHex("Ciphertext (Hex): ", ciphertext);
    if(choice ==2){
        std::cout<<"Let's input ADD correctly and decrypt."<<std::endl;
        std::getline(std::cin, AAD);
    }
    std::string decryptedText = AESDecrypt(ciphertext, key, iv, choice, AAD);
    std::cout << "Decrypted Text: " << decryptedText << std::endl;

    return 0;
}
