#ifndef __GET_HASH_H__
#define __GET_HASH_H__

#include <stdio.h>
#include <string.h>    
#include <errno.h>
#include <sys/io.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/evp.h>

#define HASH_CMD_BUFFER_SIZE 0x100
#define HASH_RESULT_BUFFER_SIZE 0x200
#define HASH_BLOCK_SIZE 0X1000 
#define SM3_HASH_LEN 32

#define JSON_RESULT_BUFFER_SIZE 0x10000

const unsigned char elf_magic[16] = {0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

typedef enum{
    FAIL = 0,
    EXE_FILE,
    SCRIPT_FILE,
    MODEL_FILE,
    CONFIG_FILE,
    COMPRESSED_FILE,
    BINARY_FILE,
    TEXT_FILE,
    ELF_FILE,
    FILE_TYPE_MAX
} FileType;

typedef struct _FileNode{
    char name[HASH_CMD_BUFFER_SIZE];
    char hash[SM3_HASH_LEN << 1 + 1];
    size_t size;
    unsigned int hash_size;
    FileType type;
    struct _FileNode* next;
} FileNode;

typedef struct _FileList{
    int len;
    struct _FileNode* head;
    struct _FileNode* p;
} FileList;

static const char FileTypeName[][20] = {
    "unknown type", 
    "executable file",
    "script file",
    "model file",
    "config file",
    "compressed file",
    "binary file",
    "text file",
    "elf file",
    "others"
};

struct FileTypeFindTableItem{
    char file_suffix[32];
    char file_type_name[32];
    char index_name[32];
    FileType type;
};

typedef struct _FileTypeFindTable{
    int size;
    const struct FileTypeFindTableItem* hash_table[48];
} FileTypeFindTable;

static const struct FileTypeFindTableItem shell_script = {
    .file_suffix = "sh",
    .file_type_name = "script file",
    .index_name = "shell_script",
    .type = SCRIPT_FILE
};

static const struct FileTypeFindTableItem python_script = {
    .file_suffix = "py",
    .file_type_name = "script file",
    .index_name = "python_script",
    .type = SCRIPT_FILE
};

static const struct FileTypeFindTableItem model_file = {
    .file_suffix = "model",
    .file_type_name = "model file",
    .index_name = "model_file",
    .type = SCRIPT_FILE
};

static const struct FileTypeFindTableItem bin_file = {
    .file_suffix = "bin",
    .file_type_name = "binary file",
    .index_name = "bin_file",
    .type = BINARY_FILE
};

static const struct FileTypeFindTableItem json_file = {
    .file_suffix = "json",
    .file_type_name = "config file",
    .index_name = "json_file",
    .type = CONFIG_FILE
};

static const struct FileTypeFindTableItem markdown_file = {
    .file_suffix = "md",
    .file_type_name = "text file",
    .index_name = "markdown_file",
    .type = TEXT_FILE
};

static const struct FileTypeFindTableItem c_file = {
    .file_suffix = "c",
    .file_type_name = "text file",
    .index_name = "c_file",
    .type = TEXT_FILE
};

static const struct FileTypeFindTableItem cpp_file = {
    .file_suffix = "cpp",
    .file_type_name = "text file",
    .index_name = "cpp_file",
    .type = TEXT_FILE
};

static const struct FileTypeFindTableItem header_file = {
    .file_suffix = "h",
    .file_type_name = "text file",
    .index_name = "header_file",
    .type = TEXT_FILE
};

static const struct FileTypeFindTableItem unknown_file = {
    .file_suffix = "",
    .file_type_name = "others type",  
    .index_name = "unknown_file",
    .type = FAIL
};

static const struct FileTypeFindTableItem win_executable_file = {
    .file_suffix = "exe",
    .file_type_name = "executable files",
    .index_name = "win_executable_file",
    .type = EXE_FILE
};

static const struct FileTypeFindTableItem executable_file = {
    .file_suffix = "",
    .file_type_name = "executable files",
    .index_name = "executable_file",
    .type = EXE_FILE
};

static FileTypeFindTable file_type_find_table = {
    .size = 47,
    .hash_table = {NULL, NULL, NULL, NULL, NULL, &c_file, NULL, NULL, NULL, NULL, 
    &header_file, NULL, &model_file, NULL, NULL, NULL, NULL, NULL, NULL, &json_file, 
    NULL, &markdown_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    NULL, &shell_script, &bin_file, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
    &win_executable_file, &cpp_file, NULL, NULL, NULL, &python_script, NULL, &unknown_file}
};

char* get_hash_result(int argc,char* argv[]);

#endif