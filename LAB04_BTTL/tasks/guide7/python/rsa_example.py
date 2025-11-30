# rsa_example.py
import rsa_wrapper as rsa

def main():
    # Generate RSA keys
    print("Generating RSA keys...")
    status = rsa.generate_key_pair(3072, "private_key.pem", "public_key.pem", True)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Key generation failed: {rsa.get_error_message(status)}")
        return
    
    # Load the public key
    print("Loading public key...")
    status, public_key = rsa.load_public_key("public_key.pem")
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Failed to load public key: {rsa.get_error_message(status)}")
        return
    
    # Encrypt a message
    message = b"Hello from Python!"
    print(f"Encrypting message: {message.decode('utf-8')}")
    status, encrypted_data = rsa.encrypt(public_key, message)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Encryption failed: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        return
    
    # Load the private key
    print("Loading private key...")
    status, private_key = rsa.load_private_key("private_key.pem")
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Failed to load private key: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        return
    
    # Decrypt the message
    print("Decrypting message...")
    status, decrypted_data = rsa.decrypt(private_key, encrypted_data)
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"Decryption failed: {rsa.get_error_message(status)}")
        rsa.free_public_key(public_key)
        rsa.free_private_key(private_key)
        return
    
    # Print the decrypted message
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")
    
    # File encryption example
    print("\nFile encryption example:")
    
    # Create a test file
    with open("plaintext.txt", "w") as f:
        f.write("This is a test file for RSA encryption.")
    
    # Encrypt the file
    print("Encrypting file...")
    status = rsa.encrypt_file(
        public_key, 
        "plaintext.txt", 
        "encrypted.bin", 
        rsa.RSAPaddingScheme.RSA_PADDING_OAEP, 
        rsa.RSAOutputFormat.RSA_FORMAT_BINARY, 
        True  # Use hybrid encryption for files
    )
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"File encryption failed: {rsa.get_error_message(status)}")
    else:
        print("File encrypted successfully.")
    
    # Decrypt the file
    print("Decrypting file...")
    status = rsa.decrypt_file(
        private_key, 
        "encrypted.bin", 
        "decrypted.txt", 
        rsa.RSAPaddingScheme.RSA_PADDING_OAEP, 
        rsa.RSAOutputFormat.RSA_FORMAT_BINARY, 
        True  # Use hybrid decryption for files
    )
    if status != rsa.RSAStatusCode.RSA_SUCCESS:
        print(f"File decryption failed: {rsa.get_error_message(status)}")
    else:
        print("File decrypted successfully.")
        with open("decrypted.txt", "r") as f:
            print(f"Decrypted file content: {f.read()}")
    
    # Clean up
    rsa.free_public_key(public_key)
    rsa.free_private_key(private_key)
    print("Done.")

if __name__ == "__main__":
    main()