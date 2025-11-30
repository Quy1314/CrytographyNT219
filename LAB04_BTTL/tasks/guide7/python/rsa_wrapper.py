# rsa_wrapper.py
import ctypes
import os
from enum import IntEnum
from typing import Tuple, Optional

# Load the shared library
if os.name == 'nt':  # Windows
    _lib = ctypes.CDLL('./rsa_lib.dll')
else:  # Linux/macOS
    _lib = ctypes.CDLL('./librsa.so')

# Define enums
class RSAStatusCode(IntEnum):
    RSA_SUCCESS = 0
    RSA_ERROR_INVALID_PARAMETER = -1
    RSA_ERROR_MEMORY_ALLOCATION = -2
    RSA_ERROR_KEY_GENERATION = -3
    RSA_ERROR_KEY_VALIDATION = -4
    RSA_ERROR_ENCRYPTION = -5
    RSA_ERROR_DECRYPTION = -6
    RSA_ERROR_FILE_IO = -7
    RSA_ERROR_BUFFER_TOO_SMALL = -8
    RSA_ERROR_INVALID_FORMAT = -9
    RSA_ERROR_UNKNOWN = -99

class RSAPaddingScheme(IntEnum):
    RSA_PADDING_PKCS1 = 1
    RSA_PADDING_OAEP = 2

class RSAOutputFormat(IntEnum):
    RSA_FORMAT_BINARY = 1
    RSA_FORMAT_BASE64 = 2
    RSA_FORMAT_HEX = 3

# Define handle types
RSAPublicKeyHandle = ctypes.c_void_p
RSAPrivateKeyHandle = ctypes.c_void_p

# Set function prototypes
_lib.RSA_GenerateKeyPair.argtypes = [
    ctypes.c_uint,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int
]
_lib.RSA_GenerateKeyPair.restype = ctypes.c_int

_lib.RSA_LoadPublicKey.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(RSAPublicKeyHandle)
]
_lib.RSA_LoadPublicKey.restype = ctypes.c_int

_lib.RSA_LoadPrivateKey.argtypes = [
    ctypes.c_char_p,
    ctypes.POINTER(RSAPrivateKeyHandle)
]
_lib.RSA_LoadPrivateKey.restype = ctypes.c_int

_lib.RSA_FreePublicKey.argtypes = [RSAPublicKeyHandle]
_lib.RSA_FreePublicKey.restype = None

_lib.RSA_FreePrivateKey.argtypes = [RSAPrivateKeyHandle]
_lib.RSA_FreePrivateKey.restype = None

_lib.RSA_Encrypt.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_Encrypt.restype = ctypes.c_int

_lib.RSA_Decrypt.argtypes = [
    RSAPrivateKeyHandle,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(ctypes.c_size_t),
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_Decrypt.restype = ctypes.c_int

_lib.RSA_EncryptFile.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_EncryptFile.restype = ctypes.c_int

_lib.RSA_DecryptFile.argtypes = [
    RSAPrivateKeyHandle,
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_int,
    ctypes.c_int,
    ctypes.c_int
]
_lib.RSA_DecryptFile.restype = ctypes.c_int

_lib.RSA_GetErrorMessage.argtypes = [ctypes.c_int]
_lib.RSA_GetErrorMessage.restype = ctypes.c_char_p

_lib.RSA_GetMaxPlaintextLength.argtypes = [
    RSAPublicKeyHandle,
    ctypes.c_int
]
_lib.RSA_GetMaxPlaintextLength.restype = ctypes.c_size_t

# Define Python wrapper functions
def generate_key_pair(key_size: int, private_key_file: str, public_key_file: str, use_pem: bool = True) -> RSAStatusCode:
    """Generate an RSA key pair and save to files."""
    status = _lib.RSA_GenerateKeyPair(
        key_size,
        ctypes.c_char_p(private_key_file.encode('utf-8')),
        ctypes.c_char_p(public_key_file.encode('utf-8')),
        1 if use_pem else 0
    )
    return RSAStatusCode(status)

def load_public_key(filename: str) -> Tuple[RSAStatusCode, Optional[RSAPublicKeyHandle]]:
    """Load a public key from a file."""
    key_handle = RSAPublicKeyHandle()
    status = _lib.RSA_LoadPublicKey(
        ctypes.c_char_p(filename.encode('utf-8')),
        ctypes.byref(key_handle)
    )
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    return RSAStatusCode(status), key_handle

def load_private_key(filename: str) -> Tuple[RSAStatusCode, Optional[RSAPrivateKeyHandle]]:
    """Load a private key from a file."""
    key_handle = RSAPrivateKeyHandle()
    status = _lib.RSA_LoadPrivateKey(
        ctypes.c_char_p(filename.encode('utf-8')),
        ctypes.byref(key_handle)
    )
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    return RSAStatusCode(status), key_handle

def free_public_key(key_handle: RSAPublicKeyHandle) -> None:
    """Free a public key handle."""
    _lib.RSA_FreePublicKey(key_handle)

def free_private_key(key_handle: RSAPrivateKeyHandle) -> None:
    """Free a private key handle."""
    _lib.RSA_FreePrivateKey(key_handle)

def encrypt(public_key: RSAPublicKeyHandle, data: bytes, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, use_hybrid: bool = False) -> Tuple[RSAStatusCode, Optional[bytes]]:
    """Encrypt data using an RSA public key."""
    # First call to get required buffer size
    encrypted_length = ctypes.c_size_t(0)
    status = _lib.RSA_Encrypt(
        public_key,
        data,
        len(data),
        None,
        ctypes.byref(encrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL:
        return RSAStatusCode(status), None
    
    # Allocate buffer and call again
    encrypted_data = ctypes.create_string_buffer(encrypted_length.value)
    status = _lib.RSA_Encrypt(
        public_key,
        data,
        len(data),
        encrypted_data,
        ctypes.byref(encrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    
    return RSAStatusCode(status), bytes(encrypted_data[:encrypted_length.value])

def decrypt(private_key: RSAPrivateKeyHandle, encrypted_data: bytes, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, use_hybrid: bool = False) -> Tuple[RSAStatusCode, Optional[bytes]]:
    """Decrypt data using an RSA private key."""
    # First call to get required buffer size
    decrypted_length = ctypes.c_size_t(0)
    status = _lib.RSA_Decrypt(
        private_key,
        encrypted_data,
        len(encrypted_data),
        None,
        ctypes.byref(decrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_ERROR_BUFFER_TOO_SMALL:
        return RSAStatusCode(status), None
    
    # Allocate buffer and call again
    decrypted_data = ctypes.create_string_buffer(decrypted_length.value)
    status = _lib.RSA_Decrypt(
        private_key,
        encrypted_data,
        len(encrypted_data),
        decrypted_data,
        ctypes.byref(decrypted_length),
        padding_scheme,
        1 if use_hybrid else 0
    )
    
    if status != RSAStatusCode.RSA_SUCCESS:
        return RSAStatusCode(status), None
    
    return RSAStatusCode(status), bytes(decrypted_data[:decrypted_length.value])

def encrypt_file(public_key: RSAPublicKeyHandle, input_file: str, output_file: str, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, output_format: RSAOutputFormat = RSAOutputFormat.RSA_FORMAT_BINARY, use_hybrid: bool = False) -> RSAStatusCode:
    """Encrypt a file using an RSA public key."""
    status = _lib.RSA_EncryptFile(
        public_key,
        ctypes.c_char_p(input_file.encode('utf-8')),
        ctypes.c_char_p(output_file.encode('utf-8')),
        padding_scheme,
        output_format,
        1 if use_hybrid else 0
    )
    return RSAStatusCode(status)

def decrypt_file(private_key: RSAPrivateKeyHandle, input_file: str, output_file: str, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP, input_format: RSAOutputFormat = RSAOutputFormat.RSA_FORMAT_BINARY, use_hybrid: bool = False) -> RSAStatusCode:
    """Decrypt a file using an RSA private key."""
    status = _lib.RSA_DecryptFile(
        private_key,
        ctypes.c_char_p(input_file.encode('utf-8')),
        ctypes.c_char_p(output_file.encode('utf-8')),
        padding_scheme,
        input_format,
        1 if use_hybrid else 0
    )
    return RSAStatusCode(status)

def get_error_message(status_code: RSAStatusCode) -> str:
    """Get the error message for a status code."""
    message = _lib.RSA_GetErrorMessage(status_code)
    return message.decode('utf-8')

def get_max_plaintext_length(public_key: RSAPublicKeyHandle, padding_scheme: RSAPaddingScheme = RSAPaddingScheme.RSA_PADDING_OAEP) -> int:
    """Get the maximum plaintext length that can be encrypted with the given key and padding scheme."""
    return _lib.RSA_GetMaxPlaintextLength(public_key, padding_scheme)