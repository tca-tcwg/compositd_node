#include <fstream>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>
#include "bin-hex.hpp"

inline char bin2char(unsigned char n){
    return (n > 9) ? (n + 87) : (n + '0');
}

inline unsigned char char2bin(char c){
    return (unsigned char)(c > '9' ? (c  > 'a' ? c - 87 : c - 55) : c - '0');
}

char* bin2hex(const unsigned char* bin, const int len){
    char* hex = new char[(len << 1) + 1];
    for(int i = 0; i < len; ++i){
        hex[i << 1] = bin2char(bin[i] >> 4);
        hex[(i << 1) + 1] = bin2char(bin[i] & 0xF);
    }
    hex[len << 1] = 0;
    return hex;
}

void bin2hexBuffer(char* dst, const unsigned char* src, const int src_len, const int dst_len){
    if(dst_len < (src_len << 1) + 1)
        return;
    for(int i = 0; i < src_len; ++i){
        dst[i << 1] = bin2char(src[i] >> 4);
        dst[(i << 1) + 1] = bin2char(src[i] & 0xF);
    }
    dst[src_len << 1] = 0;
}

void reverse_buffer(unsigned char* buffer, int len){
    unsigned char tem;
    for(int i = 0, j = len - 1; i < j; ++i, --j){
        tem = buffer[i];
        buffer[i] = buffer[j];
        buffer[j] = tem;
    }
}

unsigned char* hex2bin(const char* hex, int* len){
    int hex_len = strlen(hex);
    *len = (hex_len + 1) >> 1;
    unsigned char* bin = new unsigned char[*len];
    int start = hex_len & 0x1;
    if(start)
        bin[0] = char2bin(hex[0]);
    for(int i = start; i < *len; ++i){
        bin[i] = (char2bin(hex[(i << 1) - start]) << 4) + (char2bin(hex[(i << 1) + 1 - start])  & 0xF);
    }
        
    return bin;
}

char* file2hex(const char* file_name, int* len){
    std::ifstream f(file_name, std::ios::in | std::ios::binary);
    if(!f)
        return nullptr;
    unsigned char buffer[8192];
    struct stat statbuf;
    stat(file_name, &statbuf);
    *len = statbuf.st_size << 1;
    char* hex = new char[*len + 1];
    f.read((char*)buffer, statbuf.st_size);
    bin2hexBuffer(hex, buffer, statbuf.st_size, *len + 1);
    f.close();
    return hex;
}