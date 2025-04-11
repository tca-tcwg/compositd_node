#include "tpm.h"
using json = nlohmann::json;

static const char alphaTable[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_";
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};

char *base64_encode(const uint8_t *data,
                    int input_length,
                    int *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = (char*)malloc(*output_length + 1);
    memset(encoded_data, 0, *output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t octet_a = i < input_length ? (uint8_t)data[i++] : 0;
        uint32_t octet_b = i < input_length ? (uint8_t)data[i++] : 0;
        uint32_t octet_c = i < input_length ? (uint8_t)data[i++] : 0;

        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}

int* get_back_index(const char* s, int len){
    int* ret = (int*)malloc(len * sizeof(int));
    int k;
    ret[0] = -1;
    for(int i = 1; i < len; i++){
        k = ret[i - 1];
        while(k != -1 && s[i] != s[k + 1])
            k = ret[k];
        if(s[i] == s[k + 1])
            ret[i] = k + 1;
        else
            ret[i] = -1;
    }
    return ret;
}

int find_sub_str_pos(const char* str, const char* sub_str){
    int i = 0;
    int sub_str_len = strlen(sub_str);
    int* back_index = get_back_index(sub_str, sub_str_len);
    for(int p = 0; str[p] != 0; p++){
        if(str[p] != sub_str[i])
            i = back_index[i];
        i++;
        if(i >= sub_str_len){
            free(back_index);
            return p + 1;
        }
    }
    free(back_index);
    return -1;
}

void strcat_value_line(char* str, const char* substr){
    int p = strlen(str);
    int p2 = 0;
    while(substr[p2] && substr[p2] != ':')
        p2++;
    while(substr[p2] == '\"' || substr[p2] == ':' || substr[p2] == ' ')
        p2++;
    while(substr[p2] && substr[p2] != '\n'){
        str[p] = substr[p2];
        p++;
        p2++;
    };
    str[p] = 0;
    while(str[p] == ' ' || str[p] == 0 || str[p] == '\"'){
        str[p] = 0;
        p--;
    }
}

int get_formula_value(const char* data, const char* key, char* dst){

    int pos = 0, pos_delta;
    pos_delta = find_sub_str_pos(data, key);
    if(pos_delta < 0)
        return pos_delta;
    pos += pos_delta;

    pos_delta = find_sub_str_pos(data + pos, "value");
    if(pos_delta < 0)
        return pos_delta;
    pos += pos_delta;
    strcat_value_line(dst, data + pos);
    return pos;
}

char* bin2hex(const unsigned char* buffer, int len){
    char* hex_str = (char*)malloc(2 * len + 1);
    for(int i = 0; i < len; ++i)
        sprintf(hex_str + 2 * i, "%02x", buffer[i]);
    hex_str[2 * len] = 0;
    return hex_str;
}

TPMinstance::TPMinstance(){
    tpm_status = DEAD;
    memset(version, 0x00, 10);
    memset(id, 0x00, 20);
    memset(sequence, 0x00, 10);
}

TPMinstance::~TPMinstance(void){
    if(psw)
        free(psw);
    if(ek_psw)
        free(ek_psw);
    if(ak_psw)
        free(ak_psw);
    if(ek_handle)
        free(ek_handle);
    if(ek_cert)
        free(ek_cert);
}

int TPMinstance::get_tpm_info(){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    int pos = 0, pos_delta;
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_getcap properties-fixed");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    pos_delta = get_formula_value(result + pos, "TPM2_PT_FAMILY_INDICATOR", version);
    if(pos_delta < 0)
        goto err;
    pos += pos_delta;

    pos_delta = get_formula_value(result + pos, "TPM2_PT_REVISION", sequence);
    if(pos_delta < 0)
        goto err;
    pos += pos_delta;

    pos_delta = 0;
    do{
        pos += pos_delta;
        pos_delta = get_formula_value(result + pos, "TPM2_PT_VENDOR_STRING", id);
    } while(pos_delta > 0);
    pos_delta = 0;

err:
    if(ret || pos_delta < 0)
        fprintf(stderr, "Get TPM Info Failed ! Error : %d\n", ret);
    return ret;
}

int TPMinstance::set_ek_cert(){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    int pos = 0, pos_delta, i = 0;
    char ek_cert_size[10];
    unsigned char ek_cert_buffer[4096];
    int buffer_len;
    FILE *fp = NULL;

    char nv_index[] = "0x1C0000A"; // For ECC_P256
    // "RSA_2048" "0x1C00002";
    // "ECC_P256" "0x1C0000A";
    // "ECC_P384" "0x1C00016";
    // "ECC_SM2"  "0x1C0001A";

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_getcap handles-nv-index");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    pos_delta = find_sub_str_pos(result, nv_index);
    if(pos_delta < 0){
        snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_nvdefine -C p -a \"ppwrite|writedefine|ppread|ownerread|authread|no_da|platformcreate\" -s 1000 %s", nv_index);
        ret = execmd(cmd, result, TPM_RESULT_BUFFER);
        if(ret)
            goto err;
        snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_nvwrite -i %s -C p %s", EK_CET_LOAD_PATH, nv_index);
        ret = execmd(cmd, result, TPM_RESULT_BUFFER);
        if(ret)
            goto err;
        snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
        ret = execmd(cmd, result, TPM_RESULT_BUFFER);
        if(ret)
            goto err;
    }

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_nvreadpublic %s", nv_index);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
        if(ret)
            goto err;
    
    pos_delta = find_sub_str_pos(result, "0x1c0000a");
    if(pos_delta < 0){
        ret = -1;
        goto err;
    }
    pos += pos_delta;
    pos_delta = find_sub_str_pos(result + pos, "size");
    if(pos_delta < 0){
        ret = -1;
        goto err;
    }
    pos += pos_delta;

    pos_delta = 0;
    while(result[pos + pos_delta] != ':')
        pos_delta++;
    while(result[pos + pos_delta] == ':' || result[pos + pos_delta] == ' ')
        pos_delta++;
    while(result[pos + pos_delta + i] != '\n' && result[pos + pos_delta + i] != 0){
        ek_cert_size[i] = result[pos + pos_delta + i];
        i++;
    }
    ek_cert_size[i] = 0;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_nvread -C o -P %s -s %s -o %s %s", psw, ek_cert_size, EK_CET_OUTPUT_PATH, nv_index);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    fp = fopen(EK_CET_OUTPUT_PATH, "rb");
    buffer_len = fread(ek_cert_buffer, 1, 4096, fp);
    fclose(fp);
    ek_cert = bin2hex(ek_cert_buffer, buffer_len);
err:
    if(ret || pos_delta < 0)
        fprintf(stderr, "Set EK_Cert Failed ! Error : %d\n", ret);
    return ret;
}

void TPMinstance::gen_psw(){
    if(psw)
        free(psw);
    if(ek_psw)
        free(ek_psw);
    if(ak_psw)
        free(ak_psw);
    psw = (char*)malloc(TPM_PSW_LENGTH + 1);
    ek_psw = (char*)malloc(TPM_PSW_LENGTH + 1);
    ak_psw = (char*)malloc(TPM_PSW_LENGTH + 1);
    for(int i = 0; i < TPM_PSW_LENGTH; ++i){
        psw[i] = alphaTable[rand() % 63];
        ek_psw[i] = alphaTable[rand() % 63];
        ak_psw[i] = alphaTable[rand() % 63];
    }
    ak_psw[TPM_PSW_LENGTH] = 0;
    ek_psw[TPM_PSW_LENGTH] = 0; 
    psw[TPM_PSW_LENGTH] = 0;
}

int TPMinstance::execmd(char *command, char *output, int outputSize) {
    FILE *fp;
    int ret;
    char cmd[TPM_CMD_BUFFER_LEN];
    int cmd_len = 0;
    if(tpm_tcti == SIM)
        cmd_len = snprintf(cmd, TPM_CMD_BUFFER_LEN, "%s %s", command, "--tcti=mssim");
    else
        cmd_len = snprintf(cmd, TPM_CMD_BUFFER_LEN, "%s", command);
    if(cmd_len >= TPM_CMD_BUFFER_LEN){
        fprintf(stderr, "TPM cmd buffer out of size !\n");
        return -2;
    }
    // printf("%s\n", cmd);
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen");
        return -1; 
    }

    int bytesRead = fread(output, 1, outputSize - 1, fp);
    output[bytesRead] = 0;
    ret = pclose(fp);
    if(ret)
        fprintf(stderr, "Error while do: %s\n", cmd);
    return ret; 
}

int TPMinstance::set_psw(){
    srand((unsigned)time(NULL));
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    gen_psw();

    printf("Clear saved session.\n");  
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -s");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_clear -c p");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    printf("Set passsword \n");      
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_changeauth -c o %s", psw);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_changeauth -c e %s", ek_psw);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

err:
    if(ret)
        fprintf(stderr, "Set PSW failed ! Error : %d\n", ret);
    return ret;
}

int TPMinstance::set_ek(){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    char* p;

    printf("Generate ek\n");
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_createek -c - -G ecc -u %s -w %s -P %s", EK_PUB_PATH, psw, ek_psw);
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    p = strtok(result,":");
    p = strtok(NULL,":");

    ek_handle = (char*)malloc(strlen(p) - 1);
    memcpy(ek_handle, p + 1, strlen(p) - 2);
    ek_handle[strlen(p) - 2] = 0;
    
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

err:
    if(ret)
        fprintf(stderr, "Set EK failed ! Error : %d\n", ret);
    return ret;
}

int TPMinstance::set_ak(){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];

    printf("Generate ak\n");
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_createak -C %s -c %s -P %s -p %s -G %s -g %s -s %s -u %s", ek_handle, AK_CTX_PATH, ek_psw, ak_psw, ASYM_ALG, HASH_ALG, SIGN_ALG, AK_PUB_PATH);
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_evictcontrol -P %s -C o -c %s %s", psw, AK_CTX_PATH, AK_HANDLE);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
err:
    if(ret)
        fprintf(stderr, "Set AK failed ! Error : %d\n", ret);
    return ret;
}

void TPMinstance::write2file(){
    std::ofstream outfile;
    std::ifstream inputfile("../tpm/platinfo.json");

    json platinfo = json::parse(inputfile);
    platinfo["ak_pubkey"]["tpm"]["x_point"] = ak_pub_x;
    platinfo["ak_pubkey"]["tpm"]["y_point"] = ak_pub_y;
    platinfo["ak_pubkey"]["tpm"]["x_size"] = 64;
    platinfo["ak_pubkey"]["tpm"]["y_size"] = 64;

    platinfo["data"]["tpm"]["tpm_version"] = version;
    platinfo["data"]["tpm"]["tpm_id"] = id;
    platinfo["data"]["tpm"]["sequence"] = sequence;
    platinfo["data"]["tpm"]["ekcert_size"] = strlen(ek_cert) >> 1;
    platinfo["data"]["tpm"]["ekcert"] = ek_cert;
    platinfo["data"]["tpm"]["ek_pub"]["x_size"] = 64;
    platinfo["data"]["tpm"]["ek_pub"]["y_size"] = 64;
    platinfo["data"]["tpm"]["ek_pub"]["x_point"] = ek_pub_x;
    platinfo["data"]["tpm"]["ek_pub"]["y_point"] = ek_pub_y;
    outfile.open("../tpm/platinfo.json", std::ios::out | std::ios::trunc);
    outfile << platinfo.dump(2) << std::endl;
    outfile.close();

    inputfile.close();
    inputfile.open("../tpm/nodedat.json");
    json nodedat = json::parse(inputfile);
    nodedat["tpm_psw"] = psw;
    nodedat["ek_psw"] = ek_psw;
    nodedat["ak_psw"] = ak_psw;
    nodedat["ek_handle"] = ek_handle;
    outfile.open("../tpm/nodedat.json", std::ios::out | std::ios::trunc);
    outfile << nodedat.dump(2) << std::endl;
    outfile.close();
}

int TPMinstance::load_key(){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    int pos = 0;

    printf("Load EK.\n");
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_readpublic -c %s", ek_handle);
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    pos = find_sub_str_pos(result, "x:");
    if(pos >= 0){
        memcpy(ek_pub_x, result + pos + 1, 64);
        ek_pub_x[64] = 0;
    }
    else
        goto err;
    pos = find_sub_str_pos(result, "y:");
    if(pos >= 0){
        memcpy(ek_pub_y, result + pos + 1, 64);
        ek_pub_y[64] = 0;
    }
    else
        goto err;
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    printf("Load AK.\n");
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_readpublic -c %s", AK_HANDLE);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    pos = find_sub_str_pos(result, "x:");
    if(pos >= 0){
        memcpy(ak_pub_x, result + pos + 1, 64);
        ak_pub_x[64] = 0;
    }
    else
        goto err;
    pos = find_sub_str_pos(result, "y:");
    if(pos >= 0){
        memcpy(ak_pub_y, result + pos + 1, 64);
        ak_pub_y[64] = 0;
    }
    else
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
err:
    return ret;
}

int TPMinstance::change_pcr_alg(){
    char cmd[TPM_CMD_BUFFER_LEN];
    char result[TPM_RESULT_BUFFER];
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_pcrallocate sha384:none+sm3_256:all");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    err:
        return ret;
}

void TPMinstance::tpm_init(int tcti){
    if(tcti)
        tpm_tcti = PHYSICAL;
    else
        tpm_tcti = SIM;
    srand((unsigned)time(NULL));
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    int reset = 0;

    std::ifstream inputfile("../tpm/nodedat.json");
    std::string tpm_psw_str;
    std::string ek_psw_str;
    std::string ak_psw_str;
    std::string ek_handle_str;
    json nodedat = json::parse(inputfile);
    inputfile.close();

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_startup -c");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    try{
        nodedat["tpm_psw"].get_to(tpm_psw_str);
        nodedat["ek_psw"].get_to(ek_psw_str);
        nodedat["ak_psw"].get_to(ak_psw_str);
        nodedat["ek_handle"].get_to(ek_handle_str);
    }
    catch(...){
        reset = 1;
    }

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_getcap handles-persistent");
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;
    if(find_sub_str_pos(result, ek_handle_str.c_str()) < 0)
        reset = 1;
    if(find_sub_str_pos(result, AK_HANDLE) < 0)
        reset = 1;

    if(!reset && tpm_psw_str.length() && ek_psw_str.length() && ak_psw_str.length() && ek_handle_str.length()){
        psw = (char*)malloc(tpm_psw_str.length() + 1);
        memset(psw, 0x00, tpm_psw_str.length() + 1);
        memcpy(psw, tpm_psw_str.c_str(), tpm_psw_str.length());

        ak_psw = (char*)malloc(ak_psw_str.length() + 1);
        memset(ak_psw, 0x00, ak_psw_str.length() + 1);
        memcpy(ak_psw, ak_psw_str.c_str(), ak_psw_str.length());

        ek_psw = (char*)malloc(ek_psw_str.length() + 1);
        memset(ek_psw, 0x00, ek_psw_str.length() + 1);
        memcpy(ek_psw, ek_psw_str.c_str(), ek_psw_str.length());

        ek_handle = (char*)malloc(ek_handle_str.length() + 1);
        memset(ek_handle, 0x00, ek_handle_str.length() + 1);
        memcpy(ek_handle, ek_handle_str.c_str(), ek_handle_str.length());

    }
    else{
        ret = set_psw();
        if(ret)
            goto err;
        ret = set_ek();
        if(ret)
            goto err;
        ret = set_ak();
        if(ret)
            goto err;
    }
        
    // if(reset || access(AK_CTX_PATH, R_OK) != 0){
    //     printf("No accessed ak, set AK.\n");
    //     ret = set_ak();
    //     if(ret)
    //         goto err;
    // }
    // else{
    //     snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_getcap handles-persistent");
    //     ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    //     if(ret)
    //         goto err;
    //     if(find_sub_str_pos(result, AK_HANDLE) < 0){
    //         printf("Flushing old ak handle.\n");
    //         snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_evictcontrol -P %s -C o -c %s %s", psw, AK_CTX_PATH, AK_HANDLE);
    //         ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    //         if(ret)
    //             goto err;
    //     }
    // }

    ret = set_ek_cert();
    if(ret)
        goto err;
    ret = load_key();
    if(ret)
        goto err;
    ret = get_tpm_info();
    if(ret)
        goto err;

    write2file();
    ret = change_pcr_alg();
    if(ret)
        goto err;
    printf("TPM init success.\n");
    tpm_status = ALIVE;
    return;
err:
    fprintf(stderr, "TPM Init failed ! Error : %d\n", ret);
    fprintf(stderr, "Error Info: %s\n", result);
}

char* TPMinstance::get_random_number(unsigned length_by_byte){
    if(tpm_status != ALIVE){
        fprintf(stderr, "TPM is not alive.");
        return NULL;
    }
    if(length_by_byte == 0){
        fprintf(stderr, "The random number length should be a positive value!");
        return NULL;
    }
    char* result = (char*)malloc(length_by_byte * 2 + 1);
    char cmd[TPM_CMD_BUFFER_LEN];
    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_getrandom --hex %u", length_by_byte);
    int ret = execmd(cmd, result, length_by_byte * 2 + 1);
    if(ret){
        fprintf(stderr, "Generating random number failed. Error: %d\n", ret);
        free(result);
        result = NULL;
    }
    return result;
}

int TPMinstance::create_quote(const char *mask,const char *nonce, char **quote){
    char result[TPM_RESULT_BUFFER];
    char cmd[TPM_CMD_BUFFER_LEN];
    FILE *fp = NULL;
    unsigned char buffer[4096];
    int buffer_len, sig_len, pcrs_len, msg_len;
    char *str_buffer, *sig_base64_buffer, *pcrs_base64_buffer, *msg_base64_buffer;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_flushcontext -t");
    int ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    snprintf(cmd, TPM_CMD_BUFFER_LEN, "tpm2_quote -c %s -p %s -g %s -l %s:%s -q %s -s %s -o %s -m %s --scheme=sm2", 
    AK_HANDLE, ak_psw, HASH_ALG, HASH_ALG, mask, nonce, TPM_TMP_SIG_PATH, TPM_TMP_PCRS_PATH, TPM_TMP_MSG_PATH);
    ret = execmd(cmd, result, TPM_RESULT_BUFFER);
    if(ret)
        goto err;

    fp = fopen(TPM_TMP_SIG_PATH, "rb");
    buffer_len = fread(buffer, 1, 4096, fp);
    fclose(fp);
    str_buffer = bin2hex(buffer, buffer_len);
    sig_base64_buffer = base64_encode((uint8_t*)str_buffer, strlen(str_buffer), &sig_len);
    free(str_buffer);

    fp = fopen(TPM_TMP_PCRS_PATH, "rb");
    buffer_len = fread(buffer, 1, 4096, fp);
    fclose(fp);
    str_buffer = bin2hex(buffer, buffer_len);
    pcrs_base64_buffer = base64_encode((uint8_t*)str_buffer, strlen(str_buffer), &pcrs_len);
    
    free(str_buffer);

    fp = fopen(TPM_TMP_MSG_PATH, "rb");
    buffer_len = fread(buffer, 1, 4096, fp);
    fclose(fp);
    str_buffer = bin2hex(buffer, buffer_len);
    msg_base64_buffer = base64_encode((uint8_t*)str_buffer, strlen(str_buffer), &msg_len);
    free(str_buffer);

    *quote = (char*)malloc(sig_len + pcrs_len + msg_len + 10);
    snprintf(*quote, sig_len + pcrs_len + msg_len + 3, "%s:%s:%s", sig_base64_buffer, msg_base64_buffer, pcrs_base64_buffer);
    free(sig_base64_buffer);
    free(pcrs_base64_buffer);
    free(msg_base64_buffer);

err:
    return ret;
}