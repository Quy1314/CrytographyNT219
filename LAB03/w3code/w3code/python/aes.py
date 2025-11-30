from ctypes import CDLL, c_ubyte, c_char_p, POINTER
import os

# 1) Đường dẫn tới DLL
DLL_PATH = "C:\Documentss\Cryptography\LAB03\w3code\w3code\python\AESLibrary.dll"
dll = CDLL(DLL_PATH)

# 2) Khai báo chữ ký hàm
dll.GenerateAESKey.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
dll.GenerateAESKey.restype = None

dll.SaveKeyToFile.argtypes = [c_char_p, POINTER(c_ubyte), POINTER(c_ubyte)]
dll.SaveKeyToFile.restype = None

dll.LoadKeyFromFile.argtypes = [c_char_p, POINTER(c_ubyte), POINTER(c_ubyte)]
dll.LoadKeyFromFile.restype = None

dll.AESEncryptFile.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_char_p, c_char_p]
dll.AESEncryptFile.restype = None

dll.AESDecryptFile.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte), c_char_p, c_char_p]
dll.AESDecryptFile.restype = None

# 3) Sinh khóa và IV
AES_KEY_SIZE = 16
AES_IV_SIZE = 16
key = (c_ubyte * AES_KEY_SIZE)()
iv = (c_ubyte * AES_IV_SIZE)()

dll.GenerateAESKey(key, iv)
print("Generated Key:", bytes(key).hex().upper())
print("Generated IV :", bytes(iv).hex().upper())

# 4) Lưu key ra file
key_file = b"keyfile.bin"
dll.SaveKeyToFile(key_file, key, iv)
print("[SaveKeyToFile]: ", key_file.decode(errors="ignore"))

# 5) Tải lại key từ file
key2 = (c_ubyte * AES_KEY_SIZE)()
iv2 = (c_ubyte * AES_IV_SIZE)()
dll.LoadKeyFromFile(key_file, key2, iv2)
print("[LoadKeyFromFile]: ", key_file.decode(errors="ignore"))

# 6) Mã hóa và giải mã file
input_file = b"plaintext.txt"
enc_file = b"encrypted.bin"
dec_file = b"decrypted.txt"

# Mã hóa
dll.AESEncryptFile(key2, iv2, input_file, enc_file)
# Hiển thị ciphertext
with open(enc_file, "rb") as f:
    ctext = f.read()
print("===[Encryption]===")
print("Ciphertext (HEX):", ctext.hex().upper())

# Giải mã
dll.AESDecryptFile(key2, iv2, enc_file, dec_file)
# Hiển thị plaintext
with open(dec_file, "rb") as f:
    ptext = f.read().decode(errors="ignore")
print("===[Decryption]===")
print("Plaintext:", ptext)