#ifndef __BIN_HEX_HPP__
#define __BIN_HEX_HPP__

#include <fstream>
#include <sys/stat.h>
#include <string.h>
#include <stdio.h>

inline char bin2char(unsigned char n);
inline unsigned char char2bin(char c);
char* bin2hex(const unsigned char* bin, const int len);
void bin2hexBuffer(char* dst, const unsigned char* src, const int src_len, const int dst_len);
void reverse_buffer(unsigned char* buffer, int len);
unsigned char* hex2bin(const char* hex, int* len);
char* file2hex(const char* file_name, int* len);

#endif