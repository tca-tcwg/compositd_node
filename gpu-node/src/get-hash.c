#include "get-hash.h"

size_t fsize(const char* file_name){
    size_t len;
    FILE* fp;

    if((fp = fopen(file_name, "rb")) == NULL){
        fprintf(stderr,"File %s does not exist.\n", file_name);
        return 0;
    }
    fseek(fp, 0, SEEK_END);
    len = ftell(fp);
    fclose(fp);
    return len;
}

char bin2char(unsigned char u){
    return (u > 9) ? ('a' + u - 10) : ('0' + u); 
}

void bin2hex(unsigned char* bin_buffer, char* hex_buffer, int len){
    for(int i = 0; i < len; ++i){
        hex_buffer[i << 1] = bin2char(bin_buffer[i] >> 4);
        hex_buffer[(i << 1) + 1] = bin2char(bin_buffer[i] & 0xF);
    }
    hex_buffer[len << 1] = 0;
}

int get_file_hash(const char* file_name, unsigned char* hash_result, unsigned int* hash_size){
    FILE *fp;
    unsigned char buffer[HASH_BLOCK_SIZE];
    size_t read_num;
    EVP_MD_CTX* hash_ctx = NULL;
    int ret = 0;

    fp = fopen(file_name, "rb");
    if(!fp){
        fprintf(stderr,"File %s does not exist.\n", file_name);
        ret = 1;
        goto err;
    }

    hash_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(hash_ctx, EVP_sm3(), NULL)) {
        fprintf(stderr,"Failed to init hash ctx.\n");
        ret = 2;
        goto err;
    }
    while(read_num = fread(buffer, 1, HASH_BLOCK_SIZE, fp)){
        if(!EVP_DigestUpdate(hash_ctx, buffer, read_num)){
            fprintf(stderr,"Failed to update hash ctx.\n");
            ret = 3;
            goto err;
        }
    }
    if (!EVP_DigestFinal_ex(hash_ctx, hash_result, hash_size)) {
        fprintf(stderr,"Failed to finish hash ctx.\n");
        ret = 4;
        goto err;
    }

err:
    if(hash_ctx)
        EVP_MD_CTX_free(hash_ctx);
    return ret;
}

void remove_enter(char* string){
    for(int i = 0; string[i]; ++i){
        if(string[i] == '\n'){
            string[i] = 0;
            break;
        }
    }
}

int get_file_info(FileNode* file, char* out_buffer){
    char file_size[20];
    char order[] = "BKMGT";
    int i;
    double size = (double)file->size;

    if(sprintf(out_buffer, "{\"name\":\"%s\",\"hash\":\"%s\",\"type\":\"%s\",\"size\":\"",
    file->name, file->hash, FileTypeName[file->type]) >= HASH_RESULT_BUFFER_SIZE - 20){
        fprintf(stderr,"The data length exceeds the buffer range.");
        return -1;
    }
    for(i = 0, size = (double)file->size; size >= 1000; ++i, size /= 0x400);
    if(i > 0)
        sprintf(file_size, "%.2f%c\"}", size, order[i]);
    else
        sprintf(file_size, "%luB\"}", file->size);
    strcat(out_buffer, file_size);
    return 0;
}

const char* get_file_suffix(const char* file_name){
    for(int i = strlen(file_name) - 1; i >= 0; --i)
        if(file_name[i] == '.')
            return file_name + i + 1;
    return NULL;
}

int file_is_efi(const char* file_name){
    FILE* fd; 
    unsigned char buffer[16];
    int i;

    fd = fopen(file_name, "rb");
    if(fd){
        fread(buffer, 1, 16, fd);
        for(i = 0; i < 16; ++i)
            if(buffer[i] != elf_magic[i])
                return 0;
        return 1;
    }
    return -1;
}

int find_table_hash(const char* key, int mod){
    int i, sum;

    sum = 0;
    for(i = 0 ; key[i]; ++i)
        sum += (int)key[i];
    return sum % mod;
}

// Table can not be full!
FileType get_file_type(const char* file_name){
    int hash;
    const char* file_suffix = get_file_suffix(file_name);

    if(file_is_efi(file_name) == 1){
        if(file_suffix)
            return ELF_FILE;
        else
            return EXE_FILE;
    };
    if(!file_suffix)
        return FAIL;
    hash = find_table_hash(file_suffix, file_type_find_table.size);
    while(file_type_find_table.hash_table[hash]){
        if(strcmp(file_suffix, file_type_find_table.hash_table[hash]->file_suffix) == 0)
            return file_type_find_table.hash_table[hash]->type;
        hash++;
        hash %= file_type_find_table.size;
    }
    return file_type_find_table.hash_table[file_type_find_table.size]->type;
}

void get_time_of_today(char* out_buffer){
    time_t time_val;
    struct tm* time_p;
    time(&time_val);
    time_p = gmtime(&time_val);
    sprintf(out_buffer, "%d.%02d.%02d %02d:%02d:%02d", 
    time_p->tm_year + 1900, time_p->tm_mon + 1, time_p->tm_mday,
    time_p->tm_hour, time_p->tm_min, time_p->tm_sec);
}

void insert_node(FileList* list, FileNode* newnode){
    newnode->next = list->head;
    list->head = newnode;
    list->len++;
}

void free_list(FileList* list){
    while(list->head){
        list->p = list->head->next;
        free(list->head);
        list->head = list->p;
    }
    free(list);
}

void add_file(FileList* list, const char* file_name){
    FileNode* newnode;
    int len;
    unsigned char buffer[SM3_HASH_LEN];

    newnode = (FileNode*)malloc(sizeof(FileNode));
    if(get_file_hash(file_name, buffer, &(newnode->hash_size)) != 0 || newnode->hash_size != SM3_HASH_LEN){
        fprintf(stderr,"Error during calculate the hash of %s\n", file_name);
        free(newnode);
        return;
    }
    bin2hex(buffer, newnode->hash, newnode->hash_size);
    memcpy(newnode->name, file_name, strlen(file_name) + 1);
    newnode->type = get_file_type(file_name);
    newnode->size = fsize(file_name);
    insert_node(list, newnode);
}

void output_result(FileList* list, char* result, int size){
    char time_stamp[30];
    char buffer[HASH_RESULT_BUFFER_SIZE];
    char file_info_buffer[HASH_RESULT_BUFFER_SIZE];
    EVP_MD_CTX* hash_ctx = NULL;
    unsigned int hash_size;

    memset(result, 0x00, size);
    strcat(result, "{\n");
    get_time_of_today(time_stamp);
    sprintf(buffer, "    \"time-stamp\" : \"%s\",\n", time_stamp);
    strcat(result, buffer);
    strcat(result, "    \"measurement\":[\n");

    hash_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(hash_ctx, EVP_sm3(), NULL)) {
        fprintf(stderr,"Failed to init hash ctx.\n");
        EVP_MD_CTX_free(hash_ctx);
        return;
    }

    for(list->p = list->head; list->p; list->p=list->p->next){
        if(get_file_info(list->p, file_info_buffer) < 0)
            continue;
        if(!EVP_DigestUpdate(hash_ctx, list->p->hash, list->p->hash_size)){
            fprintf(stderr,"Failed to update hash ctx.\n");
            EVP_MD_CTX_free(hash_ctx);
            return;
        }
        if(list->p->next)
            sprintf(buffer, "    %s,\n", file_info_buffer);
        else
            sprintf(buffer, "    %s],\n", file_info_buffer);
        strcat(result, buffer);
    }
    if (!EVP_DigestFinal_ex(hash_ctx, (unsigned char*)buffer, &hash_size)) {
        fprintf(stderr,"Failed to finish hash ctx.\n");
        EVP_MD_CTX_free(hash_ctx);
        return;
    }
    bin2hex((unsigned char*)buffer, file_info_buffer, hash_size);
    sprintf(buffer, "    \"total_hash\" : \"%s\"\n}", file_info_buffer);
    strcat(result, buffer);
    EVP_MD_CTX_free(hash_ctx);
}

char* get_hash_result(int argc,char* argv[]){
    FileList* file_list;
    char* result;
    char cmd_buffer[HASH_CMD_BUFFER_SIZE];
    char output_buffer[HASH_RESULT_BUFFER_SIZE];
    int i;
    FILE* ifstream;

    file_list = (FileList*)malloc(sizeof(FileList));
    for(i = 0; i < argc; ++i){
        if(sprintf(cmd_buffer, "find %s", argv[i]) >= HASH_CMD_BUFFER_SIZE){
            fprintf(stderr,"The data length exceeds the buffer range. File : %s\n", argv[i]);
            continue;
        }
        if(NULL == (ifstream = popen(cmd_buffer,"r"))){     
            fprintf(stderr,"execute command failed: %s", strerror(errno));      
            continue;      
        }
        while(NULL != fgets(output_buffer, HASH_RESULT_BUFFER_SIZE, ifstream)){
            remove_enter(output_buffer);
            add_file(file_list, output_buffer);
        }
        pclose(ifstream);
    }
    
    result = (char*)malloc(JSON_RESULT_BUFFER_SIZE);
    if(!result){
        free_list(file_list);
        return NULL;
    }
    output_result(file_list, result, JSON_RESULT_BUFFER_SIZE);
    free_list(file_list);
    return result;
}