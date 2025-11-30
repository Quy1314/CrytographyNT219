# Lab 3 – Tasks

1. **Export AES Library**
   - Build and export AES functionality (KeyGen / Encryption / Decryption) as a shared library:
     - **DLL** (Windows, using MSVC and MinGW)
     - **.so** (Linux, using g++ or clang)

2. **Interoperability – Language Bindings**
   - **Python**
     - Import and call AES functions from DLL/.so
     - Use `ctypes` or `cffi`
   - **C#**
     - Import DLL via **P/Invoke**
     - Call AES functions from managed code
   - **Java**
     - Import via **JNI (Java Native Interface)**
     - Invoke AES functions from Java programs

3. **Cross-Compiler Testing**
   - Ensure AES DLL/.so builds and runs correctly with:
     - **g++**
     - **msvc**

**Chi tiết**
- Sử dụng code w3code/lib_code/AESLibrary.cpp để build thành .dll
- Export thành AESLibrary.dll bằng gcc (dùng tasks.json) và msvc (dùng tasks.json hoặc build trực tiếp trong Visual Studio)
- Python: import .dll vào code python/aes.py
- C#: import.dll vào project c# (tự code)
- Java: import .dll vào code AESLibraryJNI.java
  *Lưu ý*
  Để Compile the JNI DLL/SO, dùng command sau và chạy trong msys2 mingw64
  g++ -I"[Your java path]\include" -I"[Your java path]\include\win32" -shared -o AESLibraryJNI.dll AESLibraryJNI.cpp -L"[Your gcc path]" -lcryptopp
  *ví dụ*
  g++ -I"C:\Program Files\Java\jdk-21\include" -I"C:\Program Files\Java\jdk-21\include\win32" -shared -o AESLibraryJNI.dll AESLibraryJNI.cpp -L"E:\Class\HK1_25-26\NT219\cryptopp-8.9.0\lib\cryptopp\gcc" -lcryptopp

Để kiểm tra các dependents của .dll được tạo
dumpbin /dependents AESLibrary.dll

nếu có dependent là libwinpthread-1.dll thì cần copy về cùng thư mục với Library.dll
copy "C:\msys64\mingw64\bin\libwinpthread-1.dll" .