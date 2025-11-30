#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <secblock.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <bitset>
#include <string>
#include <base64.h>
#include <files.h>

#undef byte
using namespace CryptoPP;

void printHex(const byte* ciphertext,size_t len){
    for(size_t i=0;i<len;i++)
        printf("%02x",ciphertext[i]);
    std::cout<<std::endl;
}

int main() {
    AutoSeededRandomPool prng;
    byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
    prng.GenerateBlock(key, sizeof(key));
    prng.GenerateBlock(iv, sizeof(iv));

    byte input[] = "Hello World! This is a test message.";
    byte output[64];
    size_t outputLen = 0;

    CBC_Mode<AES>::Encryption encryptor;
    encryptor.SetKeyWithIV(key, sizeof(key), iv);

    ArraySink sink(output, sizeof(output)); // Đích để lưu trữ ciphertext
    ArraySource(input, sizeof(input) - 1, true,
        new StreamTransformationFilter(encryptor,
            new Redirector(sink)
        )
    );
    std::ofstream outFile("3output.bin", std::ios::binary);
    outFile.write((const char*)output, sink.TotalPutLength());
    outFile.close(); // Luu file dưới dạng binary

    outputLen = sink.TotalPutLength();
    std::cout << "Plaintext: " << input << std::endl;
    std::cout << "Ciphertext (hex): ";
    printHex(output, outputLen); // In ciphertext dưới dạng hex
    std::cout << "Ciphertext saved to 3output.bin" << std::endl; 
    std::cout<<"3output.bin file content: ";
    std::ifstream inFile("3output.bin", std::ios::binary);
    std::vector<byte> data((std::istreambuf_iterator<char>(inFile)),
                       std::istreambuf_iterator<char>());
    inFile.close();
    // In ciphertext dưới dạng binary
    std::cout<<"Cipher text in binary: ";
    for(byte b : data){
        std::bitset<8> bits(b);
        std::cout<<bits <<" ";
    }
    std::cout<<std::endl;
    // Đọc file 3output.bin và in nội dung dưới dạng base64
    std::string base64Encoded;
    FileSource("3output.bin", true,
        new Base64Encoder(
            new StringSink(base64Encoded),false
        )
    );
    std::cout << "Ciphertext (Base64): " << base64Encoded << std::endl;
    return 0;
}