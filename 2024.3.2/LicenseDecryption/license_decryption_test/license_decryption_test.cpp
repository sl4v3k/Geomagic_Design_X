#include <iostream>
#include <stdint.h>
#include "key.h"
#include <fstream>
#include <vector>
#include <stdint.h>
#include <cstring>

void encrypt_data(uint32_t *rcx, uint32_t *rdx, uint32_t *rbx) {
    uint32_t r11d = *(uint32_t*)((uint8_t*)rcx + 0x10);
    r11d ^= *(uint32_t*)rdx;

    uint32_t r9d = 0;
    uint32_t rddx = 0;
    uint32_t index_base = r11d;

    for (int iteration = 0; iteration < 16; iteration++) {
        uint8_t index1 = (index_base >> 16) & 0xFF;
        uint8_t index2 = (index_base >> 24) & 0xFF;
        uint8_t index3 = (index_base >> 8) & 0xFF;
        uint8_t index4 = index_base & 0xFF;

        rddx  = *(uint32_t*)((uint8_t*)rcx + index1 * 4 + 0x458);
        rddx += *(uint32_t*)((uint8_t*)rcx + index2 * 4 + 0x58);
        rddx ^= *(uint32_t*)((uint8_t*)rcx + index3 * 4 + 0x858);
        rddx += *(uint32_t*)((uint8_t*)rcx + index4 * 4 + 0xC58);
        rddx ^= *(uint32_t*)((uint8_t*)rcx + 0x14 + (iteration * 4));
        rddx ^= *(uint32_t*)((uint8_t*)rdx + 4);

        if (iteration & 1) {
            r11d ^= rddx;
            index_base = r11d;
        } else {
            if (iteration == 0) rddx ^= *(uint32_t*)((uint8_t*)rdx + 4);
            r9d ^= rddx;
            index_base = r9d;
        }
    }

    *(uint32_t*)((uint8_t*)rbx + 4) = r11d;
    *(uint32_t*)rbx = *(uint32_t*)((uint8_t*)rcx + 0x54) ^ r9d;
}

void decrypt_data(uint32_t *rcx, uint32_t *rdx, uint32_t *rbx) 
{
    uint32_t r11d = *(uint32_t*)((uint8_t*)rcx + 0x54);
    r11d ^= *(uint32_t*)rdx;

    uint32_t r9d = 0;
    uint32_t rddx = 0;
    uint32_t index_base = r11d;

    for (int iteration = 0; iteration < 16; iteration++) {
        uint8_t index1 = (index_base >> 16) & 0xFF;
        uint8_t index2 = (index_base >> 24) & 0xFF;
        uint8_t index3 = (index_base >> 8) & 0xFF;
        uint8_t index4 = index_base & 0xFF;

        rddx  = *(uint32_t*)((uint8_t*)rcx + index1 * 4 + 0x458);
        rddx += *(uint32_t*)((uint8_t*)rcx + index2 * 4 + 0x58);
        rddx ^= *(uint32_t*)((uint8_t*)rcx + index3 * 4 + 0x858);
        rddx += *(uint32_t*)((uint8_t*)rcx + index4 * 4 + 0xC58);
        rddx ^= *(uint32_t*)((uint8_t*)rcx + 0x50 - (iteration * 4));
        
        if (iteration & 1)
        {
            r11d ^= rddx;
            index_base = r11d;
        }
        else
        {
            if (iteration == 0) rddx ^= *(uint32_t*)((uint8_t*)rdx + 4);
            r9d ^= rddx;
            index_base = r9d;
        }


    }

    *(uint32_t*)((uint8_t*)rbx + 4) = r11d;
    *(uint32_t*)rbx = *(uint32_t*)((uint8_t*)rcx + 0x10) ^ r9d;
}


void read_big_endian_dwords(const char* filename, std::vector<uint32_t>& dwords) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return;
    }

    uint32_t dword;
    while (file.read(reinterpret_cast<char*>(&dword), sizeof(dword))) {
        // Convert from big-endian to little-endian
        dword = (dword >> 24) |
                ((dword << 8) & 0x00FF0000) |
                ((dword >> 8) & 0x0000FF00) |
                (dword << 24);
        dwords.push_back(dword);
    }

    file.close();
}

void write_dwords_to_file_big_endian(const char* filename, const std::vector<uint32_t>& dwords) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open file for writing: " << filename << std::endl;
        return;
    }

    for (const auto& dword : dwords) {
        uint32_t big_endian_dword = (dword >> 24) |
                                    ((dword << 8) & 0x00FF0000) |
                                    ((dword >> 8) & 0x0000FF00) |
                                    (dword << 24);
        file.write(reinterpret_cast<const char*>(&big_endian_dword), sizeof(big_endian_dword));
    }

    file.close();
}

uint32_t ret[2] = { 0 };
uint32_t input[2] = { 0 };

int main()
{
    const char* input_filename = "02sm1be04c0ea1a4151656c8.cml";
    const char* output_filename = "decrypted_output.txt";
    std::vector<uint32_t> dwords;
    std::vector<uint32_t> decrypted_dwords;

    read_big_endian_dwords(input_filename, dwords);
    std::cout << "Read " << dwords.size() << " dwords from file." << std::endl;

    for (size_t i = 0; i < dwords.size(); i += 2) {
        input[0] = dwords[i];
        input[1] = dwords[i + 1];
        decrypt_data((uint32_t*)key, input, ret);
        decrypted_dwords.push_back(ret[0]);
        decrypted_dwords.push_back(ret[1]);
    }

 //   input[0] = decrypted_dwords[0];
 //   input[1] = decrypted_dwords[1];
 //   std::cout << "Encrypted data: " << std::hex << input[0] << " " << input[1] << std::endl;
	//encrypt_data((uint32_t*)key, (uint32_t*)input, ret);
	//std::cout << "Encrypted data: " << std::hex << ret[0] << " " << ret[1] << std::endl;

    write_dwords_to_file_big_endian(output_filename, decrypted_dwords);
    std::cout << "Decrypted data written to " << output_filename << std::endl;

    return 0;
}


