#ifndef GET_INFO_H
#define GET_INFO_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int get_os_info(char* os_info, int buffer_len);
int get_cpu_info(char* cpu_info, int buffer_len);
int get_ip(const char* name, char* ip, int buffer_len);
int get_mac(const char* name, char* mac, int buffer_len);
int get_cpu_manufacture(char* cpu_info, int buffer_len);
int get_manufacture(char* buffer, int buffer_len);
int execmd(const char* cmd, char* result);
void out_put_system_info();

#endif