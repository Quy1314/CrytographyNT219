#include <iostream>
#include <cpu.h>
using namespace CryptoPP;

int main() {
    std::cout << "AES-NI available: " << (HasAESNI() ? "Yes" : "No") << std::endl;
    std::cout << "AVX available:    " << (HasAVX() ? "Yes" : "No") << std::endl;
    std::cout << "AVX2 available:   " << (HasAVX2() ? "Yes" : "No") << std::endl;
    std::cout << "SSE2 available:   " << (HasSSE2() ? "Yes" : "No") << std::endl;
    return 0;
}
