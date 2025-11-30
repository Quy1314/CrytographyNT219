// rsa_lib.h - Public API header

#ifndef RSA_LIB_H
#define RSA_LIB_H

#include <cstddef>
#ifdef __cplusplus
extern "C" {
#endif

// Define export macro for different platforms
#ifdef _WIN32
    #ifdef RSA_LIB_EXPORTS
        #define RSA_API __declspec(dllexport)
    #else
        #define RSA_API __declspec(dllimport)
    #endif
#else
    #define RSA_API __attribute__((visibility("default")))
#endif

// Opaque handle types
typedef struct RSAPublicKey_st* RSAPublicKeyHandle;
typedef struct RSAPrivateKey_st* RSAPrivateKeyHandle;

// Error codes
typedef enum {
    RSA_SUCCESS = 0,
    RSA_ERROR_INVALID_PARAMETER = -1,
    RSA_ERROR_MEMORY_ALLOCATION = -2,
    RSA_ERROR_KEY_GENERATION = -3,
    RSA_ERROR_KEY_VALIDATION = -4,
    RSA_ERROR_ENCRYPTION = -5,
    RSA_ERROR_DECRYPTION = -6,
    RSA_ERROR_FILE_IO = -7,
    RSA_ERROR_BUFFER_TOO_SMALL = -8,
    RSA_ERROR_INVALID_FORMAT = -9,
    RSA_ERROR_UNKNOWN = -99
} RSAStatusCode;

// Padding schemes
typedef enum {
    RSA_PADDING_PKCS1 = 1,
    RSA_PADDING_OAEP = 2
} RSAPaddingScheme;

// Output formats
typedef enum {
    RSA_FORMAT_BINARY = 1,
    RSA_FORMAT_BASE64 = 2,
    RSA_FORMAT_HEX = 3
} RSAOutputFormat;

// Key generation
RSA_API RSAStatusCode RSA_GenerateKeyPair(
    unsigned int keySize,
    const char* privateKeyFile,
    const char* publicKeyFile,
    int usePEM
);

// Key loading
RSA_API RSAStatusCode RSA_LoadPublicKey(
    const char* filename,
    RSAPublicKeyHandle* keyHandle
);

RSA_API RSAStatusCode RSA_LoadPrivateKey(
    const char* filename,
    RSAPrivateKeyHandle* keyHandle
);

// Key freeing
RSA_API void RSA_FreePublicKey(RSAPublicKeyHandle keyHandle);
RSA_API void RSA_FreePrivateKey(RSAPrivateKeyHandle keyHandle);

// Encryption
RSA_API RSAStatusCode RSA_Encrypt(
    RSAPublicKeyHandle publicKey,
    const unsigned char* data,
    size_t dataLength,
    unsigned char* encryptedData,
    size_t* encryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
);

// Decryption
RSA_API RSAStatusCode RSA_Decrypt(
    RSAPrivateKeyHandle privateKey,
    const unsigned char* encryptedData,
    size_t encryptedDataLength,
    unsigned char* decryptedData,
    size_t* decryptedDataLength,
    RSAPaddingScheme paddingScheme,
    int useHybrid
);

// File-based operations
RSA_API RSAStatusCode RSA_EncryptFile(
    RSAPublicKeyHandle publicKey,
    const char* inputFile,
    const char* outputFile,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat outputFormat,
    int useHybrid
);

RSA_API RSAStatusCode RSA_DecryptFile(
    RSAPrivateKeyHandle privateKey,
    const char* inputFile,
    const char* outputFile,
    RSAPaddingScheme paddingScheme,
    RSAOutputFormat inputFormat,
    int useHybrid
);

// Utility functions
RSA_API const char* RSA_GetErrorMessage(RSAStatusCode code);
RSA_API size_t RSA_GetMaxPlaintextLength(RSAPublicKeyHandle publicKey, RSAPaddingScheme paddingScheme);

#ifdef __cplusplus
}
#endif

#endif // RSA_LIB_H