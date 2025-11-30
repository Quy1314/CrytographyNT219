#include <cryptlib.h>
#include <aes.h>
#include <modes.h>
#include <osrng.h>
#include <filters.h>
#include <hex.h>
#include <base64.h>
#include <iostream>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;
    std::string plaintext = "Crypto++ StringSource example";

    // === AES-128 ===
    {
        byte key[AES::DEFAULT_KEYLENGTH], iv[AES::BLOCKSIZE];
        prng.GenerateBlock(key, sizeof(key));
        prng.GenerateBlock(iv, sizeof(iv));

        std::string ciphertext, hexEncoded, base64Encoded;

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );

        StringSource(ciphertext, true,
            new HexEncoder(new StringSink(hexEncoded))
        );

        StringSource(ciphertext, true,
            new Base64Encoder(new StringSink(base64Encoded), false)
        );

        std::cout << "=== AES-128 ===" << std::endl;
        std::string keyHex, ivHex;
        StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(keyHex)));
        StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));

        std::cout << "Key (128-bit): " << keyHex << std::endl;
        std::cout << "IV  (128-bit): " << ivHex << std::endl;
        std::cout << "Encrypted (Hex): " << hexEncoded << std::endl;
        std::cout << "Encrypted (Base64): " << base64Encoded << std::endl;
    }

    // === AES-256 ===
    {
        byte key[32], iv[AES::BLOCKSIZE];
        prng.GenerateBlock(key, sizeof(key));
        prng.GenerateBlock(iv, sizeof(iv));

        std::string ciphertext, hexEncoded, base64Encoded;

        CBC_Mode<AES>::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), iv);

        StringSource(plaintext, true,
            new StreamTransformationFilter(encryptor,
                new StringSink(ciphertext)
            )
        );

        StringSource(ciphertext, true,
            new HexEncoder(new StringSink(hexEncoded))
        );

        StringSource(ciphertext, true,
            new Base64Encoder(new StringSink(base64Encoded), false)
        );

        std::cout << "\n=== AES-256 ===" << std::endl;
        std::string keyHex, ivHex;
        StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(keyHex)));
        StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(ivHex)));

        std::cout << "Key (256-bit): " << keyHex << std::endl;
        std::cout << "IV  (128-bit): " << ivHex << std::endl;
        std::cout << "Encrypted (Hex): " << hexEncoded << std::endl;
        std::cout << "Encrypted (Base64): " << base64Encoded << std::endl;
    }

    return 0;
}
