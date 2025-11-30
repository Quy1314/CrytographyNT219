#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <files.h>
#include <iostream>
#include <string>
#include <fstream>

#undef byte
using namespace CryptoPP;

void printHex(const byte* data, size_t length) {
    for (size_t i = 0; i < length; i++)
        printf("%02x", data[i]);
    std::cout << std::endl;
}

void SaveToFile(const std::string& filename, const std::string& data) {
    std::ofstream file(filename, std::ios::binary);
    if (file.is_open()) {
        file.write(data.data(), data.size());
        file.close();
        std::cout << "Ciphertext saved to " << filename << std::endl;
    } else {
        std::cerr << "Error: Could not open file " << filename << " for writing.\n";
    }
}

int main() {
    AutoSeededRandomPool prng;

    byte key[AES::MAX_KEYLENGTH];
    byte iv[AES::BLOCKSIZE];

    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    std::cout << "Choose input type:\n";
    std::cout << "1. Input plaintext manually\n";
    std::cout << "2. Encrypt from text file\n";
    std::cout << "Your choice (1/2): ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();

    switch (choice) {
        case 1: {
            std::string plaintext, ciphertext;
            std::cout << "Enter plaintext: ";
            std::getline(std::cin, plaintext);

            StringSource(plaintext, true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext)
                )
            );

            std::string outputFile;
            std::cout << "Enter filename to save ciphertext (*.txt): ";
            std::getline(std::cin, outputFile);

            size_t pos = outputFile.find(".txt");
            if (pos == std::string::npos || pos != outputFile.length() - 4)
                outputFile += ".txt";

            SaveToFile(outputFile, ciphertext);

            char hexChoice;
            std::cout << "Print ciphertext in hex? (y/n): ";
            std::cin >> hexChoice;
            if (hexChoice == 'y' || hexChoice == 'Y') {
                std::cout << "Ciphertext (hex): ";
                printHex((const byte*)ciphertext.data(), ciphertext.size());
            }
            break;
        }

        case 2: {
            std::string inputFile, ciphertext;
            std::cout << "Enter input file name (*.txt): ";
            std::getline(std::cin, inputFile);

            size_t pos = inputFile.find(".txt");
            if (pos == std::string::npos || pos != inputFile.length() - 4)
                inputFile += ".txt";

            std::ofstream checkFile(inputFile, std::ios::app);
            if (!checkFile) {
                std::cerr << "Error: Cannot create file " << inputFile << "\n";
                return 1;
            }
            checkFile.close();

            FileSource file(inputFile.c_str(), true,
                new StreamTransformationFilter(encryptor,
                    new StringSink(ciphertext)
                )
            );

            std::string outputFile;
            std::cout << "Enter filename to save ciphertext (*.txt): ";
            std::getline(std::cin, outputFile);
            pos = outputFile.find(".txt");
            if (pos == std::string::npos || pos != outputFile.length() - 4)
                outputFile += ".txt";

            SaveToFile(outputFile, ciphertext);

            char hexChoice;
            std::cout << "Print ciphertext in hex? (y/n): ";
            std::cin >> hexChoice;
            if (hexChoice == 'y' || hexChoice == 'Y') {
                std::cout << "Ciphertext (hex): ";
                printHex((const byte*)ciphertext.data(), ciphertext.size());
            }
            break;
        }

        default:
            std::cerr << "Invalid choice.\n";
            break;
    }

    return 0;
}
