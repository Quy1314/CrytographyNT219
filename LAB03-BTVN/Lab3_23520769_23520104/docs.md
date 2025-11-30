
Biên dịch 
```
  g++ -O2 -Wall -Wextra -Wno-unused -Wno-type-limits -I. -I/usr/include/cryptopp RSAOAEP.cpp -o rsaoaep -lcryptopp && strip --strip-all rsaoaep 
```
Tạo key 
```
./rsaoaep gen 3072 Base64 private.key public.key 
```
Encryption
```
# 50KB file
./rsaoaep benchmark_enc Base64 public.key test_50kb.txt test_50kb_cipher.bin

# 100KB file
./rsaoaep benchmark_enc Base64 public.key test_100kb.txt test_100kb_cipher.bin

# 2MB file
./rsaoaep benchmark_enc Base64 public.key test_2mb.txt test_2mb_cipher.bin
```

Decryption
```
# 50KB file
./rsaoaep benchmark_dec Base64 private.key test_50kb_cipher.bin test_50kb_decrypted.txt

# 100KB file
./rsaoaep benchmark_dec Base64 private.key test_100kb_cipher.bin test_100kb_decrypted.txt

# 2MB file
./rsaoaep benchmark_dec Base64 private.key test_2mb_cipher.bin test_2mb_decrypted.txt
```