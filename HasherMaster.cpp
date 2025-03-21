#include <iostream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cstdint>

using namespace std;
const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0x49b40821, 0x6a5b2d5f, 0x78af7c7f, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    0x9c100d4c, 0x34c8b9b8, 0x48158f2d, 0x8c292b94,
    0x91b0c08d, 0x52a3ea2d, 0x4d4f5365, 0x739d57b6,
    0x84585d0b, 0xa83099ab, 0xf9c74f44, 0x48d0c441,
    0x7f5d7af0, 0x87fcf4f7, 0x58f1d88b, 0x5136fc38,
    0xc2c6c8b3, 0x1e2f23d1, 0x6a42865d, 0x08400f36,
    0x198038b0, 0x54c870b9, 0x30a4e4ec, 0x74294d3f,
    0x896e2cba, 0x543d8976, 0xbeb29b5e, 0x3e31ed9d,
    0x65b2790b, 0xdcb62d34, 0x4405e8be, 0x0e9d74f6
};
uint32_t rotate_right(uint32_t word, unsigned int bits) {
    return (word >> bits) | (word << (32 - bits));
}
string sha256(const string &input) {
    stringstream msg;
    msg << input;
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;

    string bit_str = msg.str();
    uint64_t bit_len = bit_str.length() * 8;
    bit_str.push_back(0x80);  
    while (bit_str.length() % 64 != 56) {  
        bit_str.push_back(0x00);
    }
    for (int i = 7; i >= 0; --i) {
        bit_str.push_back((char)(bit_len >> (i * 8)));
    }
    vector<uint32_t> w(64);
    for (size_t i = 0; i < bit_str.length() / 64; ++i) {
        for (int t = 0; t < 16; ++t) {
            w[t] = (static_cast<uint32_t>(bit_str[i * 64 + t * 4]) << 24) |
                   (static_cast<uint32_t>(bit_str[i * 64 + t * 4 + 1]) << 16) |
                   (static_cast<uint32_t>(bit_str[i * 64 + t * 4 + 2]) << 8) |
                   (static_cast<uint32_t>(bit_str[i * 64 + t * 4 + 3]));
        }

        for (int t = 16; t < 64; ++t) {
            uint32_t s0 = rotate_right(w[t - 15], 7) ^ rotate_right(w[t - 15], 18) ^ (w[t - 15] >> 3);
            uint32_t s1 = rotate_right(w[t - 2], 17) ^ rotate_right(w[t - 2], 19) ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }

        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;

        for (int t = 0; t < 64; ++t) {
            uint32_t S1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + S1 + ch + K[t] + w[t];
            uint32_t S0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0');
    ss << h0 << h1 << h2 << h3 << h4 << h5 << h6 << h7;
    return ss.str();
}

int main() {
    string input;
    cout << "[Hasher/IN]: Enter text to hash: ";
    getline(cin, input);

    string hash = sha256(input);
    cout << "[Hasher/OUT]: SHA-256 Hash: " << hash << endl;

    return 0;
}
/* By TheLastFight | Copyright (C) */
/* SHA-256 generator | CyberSecurity coding projects */
