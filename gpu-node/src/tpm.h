#ifndef __TPM_HPP__
#define __TPM_HPP__
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <hv/json.hpp>

#define TPM_CMD_BUFFER_LEN 512
#define TPM_RESULT_BUFFER (1 << 12)
#define TPM_PSW_LENGTH 20
#define EK_PUB_PATH "../tpm/tpm_ek.pub"
#define AK_CTX_PATH "../tpm/tpm_ak.ctx"
#define AK_PUB_PATH "../tpm/tpm_ak.pub"
#define EK_CET_LOAD_PATH "../tpm/NTZ_Z32H_330_ek_cert_ECC.bin"
#define EK_CET_OUTPUT_PATH "../tpm/ek_cert.bin"
#define TPM_TMP_SIG_PATH "../tpm/quote.sig"
#define TPM_TMP_PCRS_PATH "../tpm/quote.pcrs"
#define TPM_TMP_MSG_PATH "../tpm/quote.msg"

#define HASH_ALG "sm3_256"
#define ASYM_ALG "ecc_sm2_p256"
#define SIGN_ALG "sm2"
// #define SIGN_ALG "ecdsa"

#define AK_HANDLE "0x81010002"

typedef enum __TPMStatus{
    DEAD = 0,
    ALIVE
} TPMStatus;

typedef enum __TPMTCTI{
    SIM = 0,
    PHYSICAL
} TPMTCTI;

class TPMinstance{
public:
    TPMinstance();
    ~TPMinstance();
    void tpm_init(int tcti);
    char* get_random_number(unsigned length_by_byte);
    int create_quote(const char *mask,const char *nonce, char **quote);
    void write2file();
private:
    int execmd(char *command, char *output, int outputSize);
    void gen_psw();
    int set_psw();
    int set_ek();
    int set_ak();
    int set_ek_cert();
    int get_tpm_info();
    int load_key();
    int change_pcr_alg();
    char ak_pub_x[65];
    char ak_pub_y[65];
    char ek_pub_x[65];
    char ek_pub_y[65];
    char version[10];
    char id[20];
    char sequence[10];
    char* psw = NULL;
    char* ek_psw = NULL;
    char* ak_psw = NULL;
    char* ek_handle = NULL;
    char* ek_cert = NULL;
    TPMStatus tpm_status;
    TPMTCTI tpm_tcti;
};

static int mod_table[] = {0, 2, 1};

char *base64_encode(const uint8_t *data, int input_length, int *output_length);

#endif