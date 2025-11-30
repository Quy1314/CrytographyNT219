/*
Lệnh Encrypt: ./AES.exe --verbose --encrypt --text "HelloWorld" --key-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --keylen 256 --iv-hex 000102030405060708090a0b0c0d0e0f --encode hex000102030405060708090a0b0c0d0e0f --encode hex
Lệnh Decrypt: ./AES.exe --verbose --decrypt --in output.bin --key-hex 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f --iv-hex 000102030405060708090a0b0c0d0e0f --encode hex --out decrypted.bin
./AES.exe --help
*/
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <stdint.h>     
#include <iomanip>      
#include <stdexcept>    
#include <cstring>      
#include <ctime>        
#include <cstdlib>      
#include <cctype>     
#include <chrono>  
#include <algorithm> 
#include <memory> 

using namespace std;
typedef vector<uint8_t> bytes;

// --- TỐI ƯU HÓA GMUL (OPT 1): BẢNG TRA CỨU ---
uint8_t gmul_table[256][256];

uint8_t gmul_slow(uint8_t a, uint8_t b)
{
    int p = 0;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1) p ^= a;
        int hi_bit_set = a & 0x80;
        a <<= 1;
        if (hi_bit_set) a ^= 0x1b;
        b >>= 1;
    }
    return p % 256;
}

void init_gmul_table() {
    for(int i = 0; i < 256; i++) {
        for(int j = 0; j < 256; j++) {
            gmul_table[i][j] = gmul_slow(i, j);
        }
    }
}

inline uint8_t gmul(uint8_t a, uint8_t b) {
    return gmul_table[a][b];
}
// --- KẾT THÚC TỐI ƯU HÓA GMUL ---


bytes urandom(int n)
{
    bytes arr(n);
    for (int i = 0; i < n; i++)
    {
        arr[i] = rand() % 256;
    }
    return arr;
}
bytes str_to_bytes(string s)
{
    vector<uint8_t> bytes(s.begin(), s.end());
    return bytes;
}
string bytes_to_str(bytes b)
{
    return string(b.begin(), b.end());
}
string hex(const bytes &b)
{
    stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &byte : b)
    {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}
bytes decode_hex(string hexstr)
{
    vector<uint8_t> bytes_;
    bytes_.reserve(hexstr.length() / 2);
    uint8_t current_byte = 0;
    bool first_nibble = true;
    for (char c : hexstr) {
        if (!isxdigit(c)) {
            continue; 
        }
        uint8_t nibble_value;
        if (c >= '0' && c <= '9') {
            nibble_value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            nibble_value = c - 'a' + 10;
        } else {
            nibble_value = c - 'A' + 10;
        }
        if (first_nibble) {
            current_byte = nibble_value << 4;
            first_nibble = false;
        } else {
            current_byte |= nibble_value;
            bytes_.push_back(current_byte);
            first_nibble = true;
        }
    }
    if (!first_nibble) {
         throw std::runtime_error("Invalid hex string (odd number of hex digits after cleaning).");
    }
    return bytes_;
}
std::string base64_encode(const bytes &data) {
    const std::string b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    size_t in_len = data.size();
    size_t k = 0;
    ret.reserve(in_len * 1.34 + 4);
    while (in_len--) {
        char_array_3[i++] = data[k++];
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            for(i = 0; (i < 4) ; i++) ret += b64_table[char_array_4[i]];
            i = 0;
        }
    }
    if (i) {
        for(j = i; j < 3; j++) char_array_3[j] = '\0';
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        for (j = 0; (j < i + 1); j++) ret += b64_table[char_array_4[j]];
        while((i++ < 3)) ret += '=';
    }
    return ret;
}
bytes base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    bytes ret;
    const std::string b64_table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    ret.reserve(in_len * 0.75);
    while (in_len-- && ( encoded_string[in_] != '=') && (isalnum(encoded_string[in_]) || (encoded_string[in_] == '+') || (encoded_string[in_] == '/'))) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = b64_table.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++) ret.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) {
            size_t pos = b64_table.find(char_array_4[j]);
            if (pos == std::string::npos) pos = 0; 
            char_array_4[j] = pos;
        }
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++) ret.push_back(char_array_3[j]);
    }
    return ret;
}
bytes concat(bytes vector1, bytes vector2)
{
    vector1.insert(vector1.end(), vector2.begin(), vector2.end());
    return vector1;
}

// --- CLASS AES ĐÃ TÁI CẤU TRÚC HOÀN TOÀN (OPT 1, 2, 3, 4, 7) ---
class AES
{
public:
    int key_length_bytes;
    uint8_t round_keys[240]; 
    
    const uint8_t S_BOX[256] =
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
    const uint8_t INV_S_BOX[256] = {
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d};
    const uint8_t RCON[10][4] = {
        {0x01, 0x00, 0x00, 0x00}, {0x02, 0x00, 0x00, 0x00}, {0x04, 0x00, 0x00, 0x00},
        {0x08, 0x00, 0x00, 0x00}, {0x10, 0x00, 0x00, 0x00}, {0x20, 0x00, 0x00, 0x00},
        {0x40, 0x00, 0x00, 0x00}, {0x80, 0x00, 0x00, 0x00}, {0x1B, 0x00, 0x00, 0x00},
        {0x36, 0x00, 0x00, 0x00}};
    
    AES() {
        memset(round_keys, 0, sizeof(round_keys));
        key_length_bytes = 0;
    }
    
    AES(const bytes& _key, int _key_length_bits)
    {
        key_length_bytes = _key.size();
        key_expansion(_key, _key_length_bits);
    }
    
    inline void sub_word(uint8_t word[4])
    {
        word[0] = S_BOX[word[0]];
        word[1] = S_BOX[word[1]];
        word[2] = S_BOX[word[2]];
        word[3] = S_BOX[word[3]];
    }
    
    inline void rot_word(uint8_t word[4])
    {
        uint8_t temp = word[0];
        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;
    }

    void key_expansion_128(const bytes& key)
    {
        int key_words = 4;
        memcpy(round_keys, key.data(), 16);

        for (int i = key_words; i < 44; i++)
        {
            uint8_t temp[4];
            memcpy(temp, round_keys + (i - 1) * 4, 4);

            if (i % key_words == 0)
            {
                rot_word(temp);
                sub_word(temp);
                for (int j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - key_words) / key_words][j];
                }
            }
            
            uint8_t* prev_key_word = round_keys + (i - key_words) * 4;
            uint8_t* curr_key_word = round_keys + i * 4;
            
            curr_key_word[0] = prev_key_word[0] ^ temp[0];
            curr_key_word[1] = prev_key_word[1] ^ temp[1];
            curr_key_word[2] = prev_key_word[2] ^ temp[2];
            curr_key_word[3] = prev_key_word[3] ^ temp[3];
        }
    }
    
    void key_expansion_192(const bytes& key)
    {
        int key_words = 6;
        memcpy(round_keys, key.data(), 24);

        for (int i = key_words; i < 52; i++)
        {
            uint8_t temp[4];
            memcpy(temp, round_keys + (i - 1) * 4, 4);

            if (i % key_words == 0)
            {
                rot_word(temp);
                sub_word(temp);
                for (int j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - key_words) / key_words][j];
                }
            }

            uint8_t* prev_key_word = round_keys + (i - key_words) * 4;
            uint8_t* curr_key_word = round_keys + i * 4;

            curr_key_word[0] = prev_key_word[0] ^ temp[0];
            curr_key_word[1] = prev_key_word[1] ^ temp[1];
            curr_key_word[2] = prev_key_word[2] ^ temp[2];
            curr_key_word[3] = prev_key_word[3] ^ temp[3];
        }
    }

    void key_expansion_256(const bytes& key)
    {
        int key_words = 8;
        memcpy(round_keys, key.data(), 32);

        for (int i = key_words; i < 60; i++)
        {
            uint8_t temp[4];
            memcpy(temp, round_keys + (i - 1) * 4, 4);

            if (i % key_words == 0)
            {
                rot_word(temp);
                sub_word(temp);
                for (int j = 0; j < 4; j++)
                {
                    temp[j] ^= RCON[(i - key_words) / key_words][j];
                }
            }
            else if (i % key_words == 4) {
                sub_word(temp);
            }
            
            uint8_t* prev_key_word = round_keys + (i - key_words) * 4;
            uint8_t* curr_key_word = round_keys + i * 4;

            curr_key_word[0] = prev_key_word[0] ^ temp[0];
            curr_key_word[1] = prev_key_word[1] ^ temp[1];
            curr_key_word[2] = prev_key_word[2] ^ temp[2];
            curr_key_word[3] = prev_key_word[3] ^ temp[3];
        }
    }

    void key_expansion(const bytes& _key, int length_bits)
    {
        if (length_bits == 128)
            key_expansion_128(_key);
        else if (length_bits == 192)
            key_expansion_192(_key);
        else if (length_bits == 256)
            key_expansion_256(_key);
        else
            throw std::invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
    }

    inline void sub_bytes_inplace(uint8_t state[4][4])
    {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
            {
                state[c][r] = S_BOX[state[c][r]];
            }
    }

    inline void shift_rows_inplace(uint8_t state[4][4])
    {
        uint8_t temp;
        temp = state[0][1];
        state[0][1] = state[1][1];
        state[1][1] = state[2][1];
        state[2][1] = state[3][1];
        state[3][1] = temp;
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;
        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;
        temp = state[0][3];
        state[0][3] = state[3][3];
        state[3][3] = state[2][3];
        state[2][3] = state[1][3];
        state[1][3] = temp;
    }

    inline void mix_columns_inplace(uint8_t state[4][4])
    {
        uint8_t t[4];
        for (int c = 0; c < 4; c++) {
            t[0] = gmul(0x02, state[c][0]) ^ gmul(0x03, state[c][1]) ^ state[c][2] ^ state[c][3];
            t[1] = state[c][0] ^ gmul(0x02, state[c][1]) ^ gmul(0x03, state[c][2]) ^ state[c][3];
            t[2] = state[c][0] ^ state[c][1] ^ gmul(0x02, state[c][2]) ^ gmul(0x03, state[c][3]);
            t[3] = gmul(0x03, state[c][0]) ^ state[c][1] ^ state[c][2] ^ gmul(0x02, state[c][3]);
            
            state[c][0] = t[0];
            state[c][1] = t[1];
            state[c][2] = t[2];
            state[c][3] = t[3];
        }
    }

    inline void inv_mix_columns_inplace(uint8_t state[4][4])
    {
        uint8_t t[4];
        for (int c = 0; c < 4; c++) {
            t[0] = gmul(0x0E, state[c][0]) ^ gmul(0x0B, state[c][1]) ^ gmul(0x0D, state[c][2]) ^ gmul(0x09, state[c][3]);
            t[1] = gmul(0x09, state[c][0]) ^ gmul(0x0E, state[c][1]) ^ gmul(0x0B, state[c][2]) ^ gmul(0x0D, state[c][3]);
            t[2] = gmul(0x0D, state[c][0]) ^ gmul(0x09, state[c][1]) ^ gmul(0x0E, state[c][2]) ^ gmul(0x0B, state[c][3]);
            t[3] = gmul(0x0B, state[c][0]) ^ gmul(0x0D, state[c][1]) ^ gmul(0x09, state[c][2]) ^ gmul(0x0E, state[c][3]);
            
            state[c][0] = t[0];
            state[c][1] = t[1];
            state[c][2] = t[2];
            state[c][3] = t[3];
        }
    }

    inline void add_round_key_inplace(uint8_t state[4][4], int round_number)
    {
        uint8_t* rk = round_keys + (round_number * 16);
        for (int c = 0; c < 4; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                state[c][r] ^= rk[c * 4 + r];
            }
        }
    }

    inline void inv_sub_bytes_inplace(uint8_t state[4][4])
    {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
            {
                state[c][r] = INV_S_BOX[state[c][r]];
            }
    }

    inline void inv_shift_rows_inplace(uint8_t state[4][4])
    {
        uint8_t temp;
        temp = state[3][1];
        state[3][1] = state[2][1];
        state[2][1] = state[1][1];
        state[1][1] = state[0][1];
        state[0][1] = temp;
        temp = state[0][2];
        state[0][2] = state[2][2];
        state[2][2] = temp;
        temp = state[1][2];
        state[1][2] = state[3][2];
        state[3][2] = temp;
        temp = state[0][3];
        state[0][3] = state[1][3];
        state[1][3] = state[2][3];
        state[2][3] = state[3][3];
        state[3][3] = temp;
    }
    
    bytes encrypt(bytes data)
    {
        uint8_t state[4][4];
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[c][r] = data[r + c*4];
            }
        }
       
        const int num_rounds = (key_length_bytes == 16 ? 10 : (key_length_bytes == 24 ? 12 : 14));

        add_round_key_inplace(state, 0);

        for (int round = 1; round < num_rounds; round++)
        {
            sub_bytes_inplace(state);
            shift_rows_inplace(state);
            mix_columns_inplace(state);
            add_round_key_inplace(state, round);
        }

        sub_bytes_inplace(state);
        shift_rows_inplace(state);
        add_round_key_inplace(state, num_rounds);

        bytes result(16);
        for (int c = 0; c < 4; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                result[c * 4 + r] = state[c][r];
            }
        }
        return result;
    }
    
    bytes decrypt(bytes ciphertext)
    {
        uint8_t state[4][4];
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[c][r] = ciphertext[r + c*4];
            }
        }

        const int num_rounds = (key_length_bytes == 16 ? 10 : (key_length_bytes == 24 ? 12 : 14));
        
        add_round_key_inplace(state, num_rounds);

        for (int round = num_rounds - 1; round > 0; round--)
        {
            inv_shift_rows_inplace(state);
            inv_sub_bytes_inplace(state);
            add_round_key_inplace(state, round);
            inv_mix_columns_inplace(state);
        }
        inv_shift_rows_inplace(state);
        inv_sub_bytes_inplace(state);
        add_round_key_inplace(state, 0);
        
        bytes result(16);
        for (int c = 0; c < 4; c++)
        {
            for (int r = 0; r < 4; r++)
            {
                result[c * 4 + r] = state[c][r];
            }
        }
        return result;
    }
};

class modes
{
public:
    bytes iv;
    int key_length;
    AES aes;

    modes(bytes key) : 
        key_length(key.size() * 8),
        aes(key, key.size() * 8)
    {
        if (key_length != 128 && key_length != 192 && key_length != 256)
        {
            throw invalid_argument("Invalid key length. Supported lengths are 128, 192, and 256 bits.");
        }
    }

    bytes pkcs7_padding(bytes data)
    {
        int padding_length_int = 16 - (data.size() % 16);
        if (padding_length_int == 0) padding_length_int = 16;
        data.reserve(data.size() + padding_length_int);
        bytes padding_data(padding_length_int, padding_length_int);
        data.insert(data.end(), padding_data.begin(), padding_data.end());
        return data;
    }

    bytes pkcs7_unpadding(bytes data)
    {
        if (data.empty()) {
            throw std::runtime_error("Empty data, cannot unpad.");
        }
        size_t padding_length = data[data.size() - 1];
        if (padding_length < 1 || padding_length > 16) {
            throw std::runtime_error("Invalid padding value (not in 1-16 range).");
        }
        if (data.size() < padding_length) {
            throw std::runtime_error("Data is too short for specified padding.");
        }
        for(size_t i = 0; i < padding_length; i++) {
            if(data[data.size() - 1 - i] != padding_length) {
                throw std::runtime_error("Invalid padding bytes (bytes are not uniform).");
            }
        }
        data.resize(data.size() - padding_length);
        return data;
    }

    bytes cbc_encrypt(bytes plaintext)
    {
        bytes padded_data = pkcs7_padding(plaintext);
        bytes res(padded_data.size()); 
        bytes previous_block = iv; 
        bytes block(16);

        for (size_t i = 0; i < padded_data.size(); i += 16)
        {
            memcpy(block.data(), padded_data.data() + i, 16);
            
            uint64_t* block_ptr = reinterpret_cast<uint64_t*>(block.data());
            const uint64_t* prev_ptr = reinterpret_cast<const uint64_t*>(previous_block.data());
            block_ptr[0] ^= prev_ptr[0];
            block_ptr[1] ^= prev_ptr[1];

            bytes encrypted_block = aes.encrypt(block);
            memcpy(res.data() + i, encrypted_block.data(), 16);
            previous_block = encrypted_block;
        }
        return res;
    }
    
    bytes cbc_decrypt(bytes ciphertext)
    {
        if (ciphertext.size() % 16 != 0)
            throw invalid_argument("Ciphertext length must be a multiple of 16 bytes for CBC mode.");
        bytes decrypted_data(ciphertext.size());
        bytes previous_block = iv;
        bytes block(16);
        bytes temp_iv_block(16);

        for (size_t i = 0; i < ciphertext.size(); i += 16)
        {
            memcpy(block.data(), ciphertext.data() + i, 16);
            memcpy(temp_iv_block.data(), ciphertext.data() + i, 16);

            bytes decrypted_block = aes.decrypt(block);
            
            uint64_t* dec_ptr = reinterpret_cast<uint64_t*>(decrypted_block.data());
            const uint64_t* prev_ptr = reinterpret_cast<const uint64_t*>(previous_block.data());
            dec_ptr[0] ^= prev_ptr[0];
            dec_ptr[1] ^= prev_ptr[1];
            
            memcpy(decrypted_data.data() + i, decrypted_block.data(), 16);
            previous_block = temp_iv_block;
        }
        return pkcs7_unpadding(decrypted_data);
    }

    bytes cbc_encrypt_kat(bytes plaintext)
    {
        if (plaintext.size() % 16 != 0) {
             throw std::runtime_error("KAT Error: Plaintext is not a multiple of 16 bytes.");
        }
        bytes res(plaintext.size()); 
        bytes previous_block = iv; 
        bytes block(16);

        for (size_t i = 0; i < plaintext.size(); i += 16)
        {
            memcpy(block.data(), plaintext.data() + i, 16);

            uint64_t* block_ptr = reinterpret_cast<uint64_t*>(block.data());
            const uint64_t* prev_ptr = reinterpret_cast<const uint64_t*>(previous_block.data());
            block_ptr[0] ^= prev_ptr[0];
            block_ptr[1] ^= prev_ptr[1];
            
            bytes encrypted_block = aes.encrypt(block);
            
            memcpy(res.data() + i, encrypted_block.data(), 16);
            previous_block = encrypted_block;
        }
        return res; 
    }
    
    bytes cbc_decrypt_kat(bytes ciphertext)
    {
        if (ciphertext.size() % 16 != 0)
            throw invalid_argument("KAT Error: Ciphertext length must be a multiple of 16 bytes.");
        
        bytes decrypted_data(ciphertext.size());
        bytes previous_block = iv;
        bytes block(16);
        bytes temp_iv_block(16);

        for (size_t i = 0; i < ciphertext.size(); i += 16)
        {
            memcpy(block.data(), ciphertext.data() + i, 16);
            memcpy(temp_iv_block.data(), ciphertext.data() + i, 16);

            bytes decrypted_block = aes.decrypt(block);

            uint64_t* dec_ptr = reinterpret_cast<uint64_t*>(decrypted_block.data());
            const uint64_t* prev_ptr = reinterpret_cast<const uint64_t*>(previous_block.data());
            dec_ptr[0] ^= prev_ptr[0];
            dec_ptr[1] ^= prev_ptr[1];

            memcpy(decrypted_data.data() + i, decrypted_block.data(), 16);
            previous_block = temp_iv_block;
        }
        return decrypted_data; 
    }
};

struct KatVector {
    std::string count;
    std::string KEY, IV, PLAINTEXT, AAD, CIPHERTEXT, TAG;
    bool FAIL;
    int TAG_LEN = 0; 
    std::string OPERATION; 

    KatVector() : FAIL(false) {}
};

static void trim_kat(std::string &s) { 
    size_t a = 0; while (a < s.size() && std::isspace((unsigned char)s[a])) ++a;
    size_t b = s.size(); while (b > a && std::isspace((unsigned char)s[b-1])) --b;
    s = s.substr(a, b - a);
}

static std::vector<KatVector> ParseKatRsp(const std::string& path) {
    std::string text;
    std::ifstream fs(path);
    if (!fs) {
        std::cerr << "Error reading KAT file: " << path << std::endl;
        return {};
    }
    text.assign((std::istreambuf_iterator<char>(fs)), std::istreambuf_iterator<char>());
    fs.close();

    std::istringstream iss(text);
    std::string line;
    std::vector<KatVector> list;
    KatVector cur;
    bool inDataBlock = false; 
    std::string currentOperation = ""; 
    std::string lastGlobalKey = "";
    std::string lastGlobalNonce = "";
    int currentTlen = 0;

    while (std::getline(iss, line)) {
        trim_kat(line);
        if (line.empty() || line[0]=='#') continue;

        if (line[0] == '[') {
             if (line == "[ENCRYPT]") currentOperation = "ENCRYPT";
             else if (line == "[DECRYPT]") currentOperation = "DECRYPT";
             else {
                 std::size_t p = line.find("TLEN");
                 if (p != std::string::npos) {
                     std::size_t eq = line.find('=', p);
                     if (eq != std::string::npos) {
                         std::string val = line.substr(eq+1);
                         trim_kat(val);
                        try { currentTlen = std::stoi(val); } catch(...) { currentTlen = 0; }
                        if (currentTlen > 16 && (currentTlen % 8) == 0) currentTlen = currentTlen / 8;
                     }
                 }
             }
             continue;
        }

        if (line == "FAIL") {
            if (inDataBlock) cur.FAIL = true;
            continue;
        }

        std::size_t eqPos = line.find(" = ");
        if (eqPos == std::string::npos) continue; 
        std::string k = line.substr(0, eqPos);
        std::string v_val = line.substr(eqPos + 3); 

        std::transform(k.begin(), k.end(), k.begin(), ::toupper);
        trim_kat(v_val);
        std::string v_up = v_val;
        std::transform(v_up.begin(), v_up.end(), v_up.begin(), ::toupper);
        v_up.erase(std::remove_if(v_up.begin(), v_up.end(), ::isspace), v_up.end());

       if (k == "COUNT") { 
             if (inDataBlock) list.push_back(cur); 
             inDataBlock = true;
             cur = KatVector(); 
             cur.count = v_val;
             cur.OPERATION = currentOperation;
             if (!lastGlobalKey.empty()) cur.KEY = lastGlobalKey;
             if (!lastGlobalNonce.empty()) cur.IV = lastGlobalNonce;
             if (currentTlen > 0) cur.TAG_LEN = currentTlen;
        } else {
            if (!inDataBlock) {
                if (k == "KEY") {
                    lastGlobalKey = v_up;
                } else if (k == "NONCE" || k == "IV") {
                    lastGlobalNonce = v_up;
                } else if (k == "TLEN") {
                    try { currentTlen = std::stoi(v_up); } catch(...) { currentTlen = 0; }
                    if (currentTlen > 16 && (currentTlen % 8) == 0) currentTlen = currentTlen / 8;
                }
            }

          if (inDataBlock) {
                 if (k == "KEY") cur.KEY = v_up;
              else if (k == "IV" || k == "NONCE") cur.IV = v_up;
                 else if (k == "PT" || k == "PLAINTEXT" || k == "PAYLOAD") cur.PLAINTEXT = v_up;
                 else if (k == "AAD" || k == "ADATA") cur.AAD = v_up;
                 else if (k == "CT" || k == "CIPHERTEXT") cur.CIPHERTEXT = v_up;
                 else if (k == "TAG") cur.TAG = v_up;
                 else if (k == "RESULT") {
                     std::string up = v_up;
                     std::transform(up.begin(), up.end(), up.begin(), ::toupper);
                     if (up.find("FAIL") != std::string::npos) cur.FAIL = true;
                 }
            }
        }
    }
    if (inDataBlock) list.push_back(cur); 
    return list;
}

void run_kat(const std::string& katFilePath, std::ofstream& csv) {
    std::string filenameOnly = katFilePath.substr(katFilePath.find_last_of("/\\") + 1);
    std::vector<KatVector> vectors = ParseKatRsp(katFilePath);
    KatVector v;

    if(vectors.empty()) {
        std::cerr << "No test vectors parsed from file: " << katFilePath << std::endl;
        return;
    }

    std::string cipherMode = "CBC";
    if (filenameOnly.find("CBC") == std::string::npos) {
        std::cout << "Warning: This KAT harness is only configured for CBC tests." << std::endl;
        std::cout << "Attempting to run file " << filenameOnly << " as CBC..." << std::endl;
    }

    long total = vectors.size();
    long passOverall = 0;

    for (std::vector<KatVector>::const_iterator it = vectors.begin(); it != vectors.end(); ++it) {
        v = *it;
        bool testOK = false;
        std::string modeStr = v.OPERATION;

        try {
            bytes keyBytes = decode_hex(v.KEY);
            bytes ivBytes = decode_hex(v.IV);

            modes* tester = new modes(keyBytes);
            tester->iv = ivBytes; 

            if (modeStr == "ENCRYPT") {
                bytes ptBytes = decode_hex(v.PLAINTEXT);
                
                bytes computed_ct_bytes = tester->cbc_encrypt_kat(ptBytes);
                
                std::string computed_ct_hex = hex(computed_ct_bytes); 
                std::transform(computed_ct_hex.begin(), computed_ct_hex.end(), computed_ct_hex.begin(), ::toupper);
                
                testOK = (computed_ct_hex == v.CIPHERTEXT);

            } else if (modeStr == "DECRYPT") {
                bytes ctBytes = decode_hex(v.CIPHERTEXT);

                bytes recovered_pt_bytes = tester->cbc_decrypt_kat(ctBytes);
                
                std::string recovered_pt_hex = hex(recovered_pt_bytes); 
                std::transform(recovered_pt_hex.begin(), recovered_pt_hex.end(), recovered_pt_hex.begin(), ::toupper);
                
                testOK = (recovered_pt_hex == v.PLAINTEXT);
            
            } else {
                 std::cerr << "WARNING: Unknown operation '" << modeStr << "' for CBC mode in KAT vector COUNT=" << v.count << std::endl;
                 testOK = false;
            }
            
            delete tester; 

        }
        catch (const std::exception& e) {
            std::cerr << "Error processing KAT vector COUNT=" << v.count << " in " << filenameOnly << ": " << e.what() << std::endl;
            testOK = false;
             if (v.FAIL) { 
                 testOK = true;
             }
        }

        if (!testOK) {
             std::cerr << "DEBUG: Vector COUNT=" << v.count
                      << " OPERATION=" << v.OPERATION
                      << " CipherMode=" << cipherMode
                      << " FAILED \n";
            std::cerr << "  KEY=" << v.KEY << "\n";
            std::cerr << "  IV/NONCE=" << v.IV << "\n";
            std::cerr << "  CIPHERTEXT(expected)=" << v.CIPHERTEXT << "\n";
            std::cerr << "  PLAINTEXT(expected)=" << v.PLAINTEXT << "\n";
             if(v.FAIL) std::cerr << "  (Note: This vector was expected to FAIL)\n";
        }

        if (testOK) ++passOverall;

        csv << filenameOnly << "," << v.count << "," << v.OPERATION << ","
            << (testOK ? "1" : "0") << "\n";
    }

    double rate = total ? 100.0 * passOverall / total : 0.0;
    std::cout << katFilePath << ": Overall Pass=" << passOverall << "/" << total
          << " (" << std::fixed << std::setprecision(1) << rate << "%)" << std::endl;
}

void run_kat(const std::string& katFilePath, std::ofstream& csv);


void printHelp();

int main(int argc, char* argv[]) {
    std::ios_base::sync_with_stdio(false); 
    std::cin.tie(NULL); 
    srand(time(NULL)); 
    
    init_gmul_table(); 

    bool encrypt = false, decrypt = false, verbose = false, kat = false;
    std::string inputText, inputFile, outputFile = "output.bin", keyHex,keylen ,keyFile, ivHex, katFilePath;
    std::string encode = "raw"; 

    for(int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--help") { printHelp(); return 0; }
        else if (arg == "--in" && i + 1 < argc) inputFile = argv[++i];
        else if (arg == "--text" && i + 1 < argc) inputText = argv[++i];
        else if (arg == "--out" && i + 1 < argc) outputFile = argv[++i];
        else if (arg == "--key-hex" && i + 1 < argc) keyHex = argv[++i];
        else if (arg == "--key" && i + 1 < argc) keyFile = argv[++i];
        else if (arg == "--iv-hex" && i + 1 < argc) ivHex = argv[++i];
        else if (arg == "--encode" && i + 1 < argc) encode = argv[++i];
        else if (arg == "--keylen" && i + 1 < argc) keylen = argv[++i]; 
        else if (arg == "--encrypt") encrypt = true;
        else if (arg == "--decrypt") decrypt = true;
        else if (arg == "--verbose") verbose = true;
        else if (arg == "--kat" && i + 1 < argc) { katFilePath = argv[++i]; kat = true; } 
    }
    
    if (kat) { 
        std::string csvFilename = "mytool_kat_results.csv"; 
        try {
            std::ofstream katCsv(csvFilename); 
            if (!katCsv.is_open()) {
                std::cerr << "Error: Could not open KAT results file: " << csvFilename << std::endl;
                return 1;
            }
            katCsv << "filename,COUNT,operation,pass\n"; 
            run_kat(katFilePath, katCsv); 
            katCsv.close(); 
            std::cout << "KAT results written to " << csvFilename << std::endl; 

        } catch (const std::exception& e) {
            std::cerr << "KAT execution failed: " << e.what() << std::endl;
            return 1;
        }
        return 0; 
    }


    try{
        bytes key;
        std::string keydata_str;
        bool keyFound = false;
        
        if (!keyFile.empty()) {
            std::ifstream key_file(keyFile, std::ios::binary | std::ios::ate);
            if (!key_file) throw std::runtime_error("Cannot open key file: " + keyFile);
            std::streamsize size = key_file.tellg();
            key_file.seekg(0, std::ios::beg);
            keydata_str.resize(size);
            if (!key_file.read(&keydata_str[0], size)) throw std::runtime_error("Error reading key file.");
            key_file.close();
            
            key = str_to_bytes(keydata_str);
            keyFound = true;

        } else if (!keyHex.empty()) {
            key = decode_hex(keyHex);
            keyFound = true;
        }

        modes* aes_cbc_ptr = nullptr; 

        if (keyFound) {
            aes_cbc_ptr = new modes(key);
        } else if (encrypt) {
            size_t keyLengthBytes = 16; 
            if (!keylen.empty()) {
                int keylen_int = std::stoi(keylen);
                if (keylen_int != 128 && keylen_int != 192 && keylen_int != 256) {
                    throw std::runtime_error("Invalid --keylen for random key. Must be 128, 192, or 256.");
                }
                keyLengthBytes = keylen_int / 8;
            }
            key = urandom(keyLengthBytes);
            std::cerr << "--- Key Not Provided: Generating Random Key ---" << std::endl;
            std::cerr << "Generated " << (keyLengthBytes * 8) << "-bit Key (Hex): " << hex(key) << std::endl;
            std::cerr << "--- (Save this key for decryption!) ---" << std::endl;
            aes_cbc_ptr = new modes(key);
        } else {
            throw std::runtime_error("No key specified for decryption. Use --key or --key-hex.");
        }

        if (!aes_cbc_ptr) {
            throw std::runtime_error("AES object failed to initialize.");
        }
        
        bytes iv_bytes;
        bool iv_from_param = false;
        if (!ivHex.empty()) {
            iv_bytes = decode_hex(ivHex);
            aes_cbc_ptr->iv = iv_bytes;
            iv_from_param = true;
        } else if (encrypt) {
            iv_bytes = urandom(16);
            aes_cbc_ptr->iv = iv_bytes;
            iv_from_param = false;
        } else {
             throw std::runtime_error("Decryption failed: --iv-hex is required.");
        }

        if (inputFile.empty() && inputText.empty()) {
             throw std::runtime_error("No input specified. Use --in or --text.");
        }
        if (!encrypt && !decrypt) {
             throw std::runtime_error("Error: You must choose --encrypt or --decrypt.");
        }

        
        if(encrypt){
            std::string plaintext_str;
            
            if (!inputText.empty()) {
                plaintext_str = inputText;
            } else {
                std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
                if (!inFile) throw std::runtime_error("Cannot open file: " + inputFile);
                std::streamsize size = inFile.tellg();
                inFile.seekg(0, std::ios::beg);
                plaintext_str.resize(size);
                if (!inFile.read(&plaintext_str[0], size)) throw std::runtime_error("Error reading file.");
                inFile.close();
            }

            
            bytes plain_bytes = str_to_bytes(plaintext_str);
            auto start = std::chrono::high_resolution_clock::now();
            bytes cipher_bytes = aes_cbc_ptr->cbc_encrypt(plain_bytes);
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            std::cerr << "[Time]:" << duration << " us" << std::endl;
            
            std::ofstream outFile(outputFile);
            if (!outFile) throw std::runtime_error("Cannot open output file: " + outputFile);
            
            if (encode == "hex") {
                outFile << std::hex << std::setfill('0');
                for (const auto &byte : cipher_bytes) {
                    outFile << std::setw(2) << static_cast<int>(byte);
                }
            } else if (encode == "base64") {
                outFile << base64_encode(cipher_bytes);
            } else {
                outFile.close();
                outFile.open(outputFile, std::ios::binary);
                outFile.write(reinterpret_cast<const char*>(cipher_bytes.data()), cipher_bytes.size());
            }
            outFile.close();

        }
        else if(decrypt){
            std::string ciphertext_str;
            
            if(!inputText.empty()) {
                ciphertext_str = inputText;
            } else {
                std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
                if (!inFile) throw std::runtime_error("Cannot open file: " + inputFile);
                std::streamsize size = inFile.tellg();
                inFile.seekg(0, std::ios::beg);
                ciphertext_str.resize(size);
                if (!inFile.read(&ciphertext_str[0], size)) throw std::runtime_error("Error reading file.");
                inFile.close();
            }

            
            bytes cipher_bytes;
            if (encode == "hex") cipher_bytes = decode_hex(ciphertext_str);
            else if (encode == "base64") cipher_bytes = base64_decode(ciphertext_str);
            else cipher_bytes = str_to_bytes(ciphertext_str);
            
            auto start = std::chrono::high_resolution_clock::now();
            bytes recovered_bytes = aes_cbc_ptr->cbc_decrypt(cipher_bytes);
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
            std::cerr << "[Time]:" << duration << " us" << std::endl;
            
            std::ofstream outFile(outputFile, std::ios::binary);
            if (!outFile) throw std::runtime_error("Cannot open output file: " + outputFile);
            outFile.write(reinterpret_cast<const char*>(recovered_bytes.data()), recovered_bytes.size());
            outFile.close();
        }
        
        if(verbose) {
            std::cout << (encrypt ? "--- Encryption Mode ---" : "--- Decryption Mode ---") << std::endl;
            std::cout << "Key (" << key.size() << " bytes): " << hex(key) << std::endl;
            std::cout << "IV (" << iv_bytes.size() << " bytes): " << hex(iv_bytes) << (iv_from_param ? " (from parameter)" : " (random)") << std::endl;
            std::cout << "Input: " << (inputFile.empty() ? "[text]" : inputFile) << std::endl;
            std::cout << "Output: " << outputFile << std::endl;
            std::cout << "Encoding: " << encode << std::endl;
            std::cout << "(Mode: Loaded to RAM)" << std::endl;
        }

        delete aes_cbc_ptr;
    }
    catch(const std::exception& e){ 
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    return 0;
}

void printHelp() {
    std::cout << "AES CBC Encryption/Decryption Tool (Self-Implemented, RAM-Loaded):\n";
    std::cout << R"(Usage:
    mytool <command> [--in INFILE | --text "..."] [--out OUTFILE]
         [--key KEYFILE | --key-hex HEX] [--keylen BITS]
         [--iv-hex IV-hex] [--encode <format>]
         [--kat path/to/vectors.rsp] [--verbose] [--help]
    
    Commands:
      --encrypt            Encrypt input (use --in or --text)
      --decrypt            Decrypt input (use --in or --text)
      --kat PATH           Run Known Answer Tests from the specified .rsp file and exit.

    Encoding:
    --encode <format>  Format for input/output. <format> can be:
                       'raw'    : Raw binary (default).
                       'hex'    : Hexadecimal string.
                       'base64' : Base64 string.
    Note: 
    -- All operations load the entire file into RAM.
    )";
}