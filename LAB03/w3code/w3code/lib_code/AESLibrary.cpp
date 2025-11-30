// AESLibrary.cpp  (Crypto++)
// Export C ABI for interop (Python / C# / Java)
extern "C" {

__declspec(dllexport) void __cdecl GenerateAESKey(unsigned char* key, unsigned char* iv);
__declspec(dllexport) void __cdecl SaveKeyToFile(const char* filename,
                                                 const unsigned char* key,
                                                 const unsigned char* iv);
__declspec(dllexport) void __cdecl LoadKeyFromFile(const char* filename,
                                                   unsigned char* key,
                                                   unsigned char* iv);
__declspec(dllexport) void __cdecl AESEncryptFile(const unsigned char* key, const unsigned char* iv,
                                                  const char* inFile, const char* outFile);
__declspec(dllexport) void __cdecl AESDecryptFile(const unsigned char* key, const unsigned char* iv,
                                                  const char* inFile, const char* outFile);

} // extern "C"

#include <aes.h>
#include <osrng.h>
#include <modes.h>
#include <filters.h>
#include <files.h>

using namespace CryptoPP
;

extern "C" {

// 16-byte key, 16-byte IV
void __cdecl GenerateAESKey(unsigned char* key, unsigned char* iv) {
    AutoSeededRandomPool prng;
    prng.GenerateBlock(key, AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(iv,  AES::BLOCKSIZE);
}

void __cdecl SaveKeyToFile(const char* filename,
                           const unsigned char* key,
                           const unsigned char* iv) {
    FileSink fs(filename, true);
    fs.Put(key, AES::DEFAULT_KEYLENGTH);
    fs.Put(iv,  AES::BLOCKSIZE);
    fs.MessageEnd();
}

void __cdecl LoadKeyFromFile(const char* filename,
                             unsigned char* key,
                             unsigned char* iv) {
    FileSource file(filename, false);
    file.Attach(new ArraySink(key, AES::DEFAULT_KEYLENGTH));
    file.Pump(AES::DEFAULT_KEYLENGTH);
    file.Attach(new ArraySink(iv, AES::BLOCKSIZE));
    file.Pump(AES::BLOCKSIZE);
}

void __cdecl AESEncryptFile(const unsigned char* key, const unsigned char* iv,
                            const char* inFile, const char* outFile) {
    CBC_Mode<AES>::Encryption enc(key, AES::DEFAULT_KEYLENGTH, iv);
    FileSource fs(inFile, true,
        new StreamTransformationFilter(enc, new FileSink(outFile)));
}

void __cdecl AESDecryptFile(const unsigned char* key, const unsigned char* iv,
                            const char* inFile, const char* outFile) {
    CBC_Mode<AES>::Decryption dec(key, AES::DEFAULT_KEYLENGTH, iv);
    FileSource fs(inFile, true,
        new StreamTransformationFilter(dec, new FileSink(outFile)));
}
} // extern "C"
int main(){
    return 0;
}