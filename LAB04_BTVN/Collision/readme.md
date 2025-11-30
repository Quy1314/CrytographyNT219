# Hướng dẫn
* Vào thư mục fastcoll:
```bash
cd fastcoll
```
## Tạo file prefix
* Tạo file infor.txt:
```bash
echo HelloUIT > infor.txt
```
## Tạo 2 file msg bằng fastcoll
* Tạo file bằng lệnh -prefixfile và -output:
```bash=
./fastcoll -p infor.txt -o msg1.bin msg2.bin
```
## Kiểm tra
* Kiểm tra hash md5 bằng md5sum
```bash=
md5sum msg1.bin msg2.bin 
```
* Kết quả mong đợi hai mã hash giống nhau
* Kiểm tra chắc chắn 2 file khác nhau về binary
```bash
diff msg1.bin msg2.bin
```
* Kết quả ví dụ: 
```bash=
poro@LAPTOP-TL39B5OL:/mnt/c/Documentss/Cryptography/LAB04_BTVN/Collision/fastcoll$ diff msg1.bin msg2.bin 
1c1
e#1����8#�k\�H!�
    �!�{ն)�s������
=q8>��W�Q�         Zy?8Z,z��␦^���q{^T�Bw�?�9Z�1q�?N��<8"/y�{~��W[`���b�vt�X��P� �0s
\ No newline at end of file
---
e#�����8#�k\�H!�
    �!�{ն)�s������
=q8>����Q�         Zy?�Z,z��␦^����{^T�Bw�?�9Z�1q�?N��<8�/y�{~��W[`���b�vt�X��P���0s
\ No newline at end of file
```
