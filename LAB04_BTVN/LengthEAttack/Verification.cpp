#include <iostream>
#include <string>
#include <hex.h>
#include <sha.h>
#include <filters.h>
using namespace std;
using namespace CryptoPP;
int main(){
    string secret = "secret"; 
    string data = "data";
    string append_data = "_append";
    string padding;
    padding += (char)0x80; // Thêm bit 1 đầu tiên
    
    // Tính số lượng số 0 cần thêm.
    // Ta cần điền cho đến byte thứ 56 (vì 8 byte cuối dành cho length)
    // Hiện tại: 10 byte (msg) + 1 byte (0x80) = 11 bytes.
    // Cần thêm: 56 - 11 = 45 số 0.
    for(int i = 0; i < 45; i++) {
        padding += (char)0x00;
    }

    // Thêm 8 byte độ dài (Big Endian của 80 bits)
    // 80 = 0x50. Vậy 8 byte là: 00 00 00 00 00 00 00 50
    for(int i = 0; i < 7; i++) padding += (char)0x00;
    padding += (char)0x50;

    // 3. Ghép chuỗi (Forged Message)
    string full_forged_message = secret + data + padding + append_data;

    // 4. Tính Hash bằng Crypto++
    SHA256 hash;
    string digest;

    // Pipeline: Input -> Hash -> HexEncoder -> StringSink (Lưu vào biến digest)
    StringSource s(full_forged_message, true, 
        new HashFilter(hash,
            new HexEncoder(
                new StringSink(digest)
            )
        ) 
    );

    // 5. Xuất kết quả
    cout << "Forged Message Length: " << full_forged_message.length() << " bytes" << endl;
    cout << "New Signature (Crypto++): " << digest << endl;

    return 0;
}