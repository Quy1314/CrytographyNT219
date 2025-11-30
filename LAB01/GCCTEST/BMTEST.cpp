#include <iostream>
#include <vector>
#include <chrono>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>

using namespace CryptoPP;

int main() {
    AutoSeededRandomPool prng;

    // Generate random key and IV
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    // Example plaintext (16 bytes)
    std::string plaintext = "0123456789ABCDEF";
    std::string ciphertext, recovered;

    // Benchmark parameters
    constexpr int BLOCK_SIZE = 1000;
    constexpr int N_TRIALS = 30;
    std::vector<double> latencies;

    // Warm-up
    auto warm_start = std::chrono::high_resolution_clock::now();
    while (true) {
        CBC_Mode<AES>::Encryption e(key, key.size(), iv);
        StringSource ss(plaintext, true,
            new StreamTransformationFilter(e, new StringSink(ciphertext))
        );
        auto warm_end = std::chrono::high_resolution_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(warm_end - warm_start).count() >= 2) break;
    }

    // Benchmark loop
    for (int t = 0; t < N_TRIALS; t++) {
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < BLOCK_SIZE; i++) {
            CBC_Mode<AES>::Encryption e(key, key.size(), iv);
            StringSource ss(plaintext, true,
                new StreamTransformationFilter(e, new StringSink(ciphertext))
            );
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto duration_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        latencies.push_back(static_cast<double>(duration_us) / BLOCK_SIZE);
    }

    // Compute average latency
    double sum = 0;
    for (auto v : latencies) sum += v;
    double mean_latency = sum / latencies.size();

    std::cout << "AES-CBC encryption latency (µs per op): " << mean_latency << std::endl;
    return 0;
}