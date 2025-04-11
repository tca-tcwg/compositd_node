#include "action.hpp"
#include "command_error.h"
#include "bin-hex.hpp"
#include "router.hpp"
#include "get_system_info.hpp"

#include <string>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <hv/json.hpp>
#include <hv/requests.h>
#include <unistd.h>  
#include <stdlib.h>
#include <stdio.h>
#include <openssl/evp.h>
using json = nlohmann::json;

#define ADDRESS_BUFFER 128
#define SEV_RANDOM_NUMBER_LENGEH 64
#define TPM_RANDOM_NUMBER_LENGEH 32

extern NetworkConfig global_net_config;

// #include <openssl/evp.h>
int get_buffer_hash(const unsigned char* buffer, unsigned char* hash_result, unsigned int* hash_size){
    EVP_MD_CTX* hash_ctx = NULL;
    int ret = 0;

    hash_ctx = EVP_MD_CTX_new();
    if (!EVP_DigestInit_ex(hash_ctx, EVP_sha256(), NULL)) {
        ret = 2;
        goto err;
    }
    if(!EVP_DigestUpdate(hash_ctx, buffer, SEV_RANDOM_NUMBER_LENGEH)){ // 64
        ret = 3;
        goto err;
    }
    if (!EVP_DigestFinal_ex(hash_ctx, hash_result, hash_size)) {
        ret = 4;
        goto err;
    }

err:
    if(hash_ctx)
        EVP_MD_CTX_free(hash_ctx);
    return ret;
}

char* get_tpm_rn_from_bin(const unsigned char* snp_rn_bin){
    unsigned int hash_len;
    unsigned char hash[TPM_RANDOM_NUMBER_LENGEH]; // 32
    get_buffer_hash(snp_rn_bin, hash, &hash_len);
    return bin2hex(hash, TPM_RANDOM_NUMBER_LENGEH);
}

char* get_tpm_rn_from_hex(const char* snp_rn_hex){
    int rn_len;
    unsigned char* snp_rn_bin = hex2bin(snp_rn_hex, &rn_len);
    if(rn_len != SEV_RANDOM_NUMBER_LENGEH){
        delete [] snp_rn_bin;
        return NULL;
    }
    unsigned char hash[TPM_RANDOM_NUMBER_LENGEH]; // 32
    unsigned int hash_len;

    // printf("Bin:");
    // for(int i = 0; i < rn_len; ++i)
    //     printf("%02x", snp_rn_bin[i]);
    // printf("\n");

    get_buffer_hash(snp_rn_bin, hash, &hash_len);

    // printf("Hash:");
    // for(int i = 0; i < TPM_RANDOM_NUMBER_LENGEH; ++i)
    //     printf("%02x", hash[i]);
    // printf("\n");

    delete [] snp_rn_bin;
    return bin2hex(hash, TPM_RANDOM_NUMBER_LENGEH);
}

int snp_node_register(std::string register_data){
    int ret = RC_SUCCESS;
    char soc_address[ADDRESS_BUFFER];
    json resp;
    json node_date;
    int node_status;
    std::ofstream outfile;
    std::ifstream inputfile;
    // std::cout << register_data << std::endl;
    if(snprintf(soc_address, ADDRESS_BUFFER, "https://%s:%d/instances/agent/register", global_net_config.soc_ip.c_str(), global_net_config.soc_port) >= ADDRESS_BUFFER){
        return RC_REGISTER_SGX_COLLECT_FAIL;
    }
    http_headers headers;
    headers["Content-Type"] = "application/json";
    auto r = requests::post(soc_address, register_data.c_str(), headers);
    if(r == NULL){
        printf("NULL!");
        ret = RC_REGISTER_NODE_CONNECT_SOC_FAIL;
        goto err;
    }

    try{
        printf("%d %s\r\n", r->status_code, r->status_message());
        std::cout << r->body << std::endl;
        resp = json::parse(r->body);
        resp["node_status"].get_to(node_status);
    }
    catch(...){
        ret = RC_REGISTER_NODE_CONNECT_SOC_FAIL;
        goto err;
    }
    
    if (node_status == RC_SUCCESS || node_status == RC_REGISTER_NODE_REGISTER_SUCCEED){
        node_date["uuid"] = resp["uuid"];
        node_date["ak_cert"] = resp["ak_cert"];
        node_date["ak_cert_size"] = resp["ak_cert_size"];
        node_date["master_secret"] = resp["master_secret"];
    }
    else{
        ret = node_status;
        inputfile.open("../information/nodedat.json");
        if(!inputfile.is_open()){
            ret = RC_REGISTER_NODE_EXECUTE_FAIL;
        }
        else{
            node_date = json::parse(inputfile);
            inputfile.close();
        }
    }
    node_date["node_status"] = node_status;
    outfile.open("../information/nodedat.json", std::ios::out | std::ios::trunc);
    outfile << node_date.dump(2) << std::endl;
    outfile.close();

err:
    return ret;
};

int snp_node_attestation(){
    json challenge_resp;
    char as_address[ADDRESS_BUFFER];
    char gpu_address[ADDRESS_BUFFER];
    std::ifstream inputfile("../information/nodedat.json");
    json node_data = json::parse(inputfile);
    inputfile.close();
    std::string uuid;
    node_data["uuid"].get_to(uuid);

    snprintf(as_address, ADDRESS_BUFFER, "https://%s:%d/attestation/challenge?type=%d&uuid=%s", 
    global_net_config.as_ip.c_str(), global_net_config.as_port, 7, uuid.c_str());
    auto r = requests::get(as_address);
    if(r == NULL){
        printf("NULL response when get random number\n");
        return RC_ATTEST_CONNECT_AS_FAIL;
    }

    std::string snp_rn;
    std::string mask;
    try{
        printf("%d %s\r\n", r->status_code, r->status_message());
        std::cout << r->body << std::endl;
        challenge_resp = json::parse(r->body);
        // resp["as_exec_status"].get_to(node_status);
        challenge_resp["nonce"].get_to(snp_rn);
        challenge_resp["mask"].get_to(mask);
    }
    catch(...){
        return RC_ATTEST_AS_DEAL_CHALLENGE_FAIL;
    }

    int rn_len;
    std::ofstream random_file("../information/attestation-random-number.bin", std::ios::binary);
    unsigned char* rn_bin = hex2bin(snp_rn.c_str() ,&rn_len);
    if(rn_len != SEV_RANDOM_NUMBER_LENGEH){
        printf("Bad random number\n");
        return RC_ATTEST_AS_DEAL_CHALLENGE_FAIL;
    }
    random_file.write((char*)rn_bin, SEV_RANDOM_NUMBER_LENGEH);
    random_file.close();
    // printf("RN : %s\n", bin2hex(rn_bin, SEV_RANDOM_NUMBER_LENGEH));
    delete []rn_bin;
    char cmd_buffer[1024];
    execmd("/home/vonsky/.cargo/bin/snpguest report ../information/attestation-report.bin ../information/attestation-random-number.bin", cmd_buffer);

    int ret, node_status;
    json gpu_resp;
    char* tpm_rn =  get_tpm_rn_from_hex(snp_rn.c_str());
    // printf("TPM nonce : %s\n", tpm_rn);
    http_headers headers;
    headers["Content-Type"] = "application/json";
    json gpu_attestation_data = {
        {"nonce", tpm_rn}, 
        {"nonce_size", TPM_RANDOM_NUMBER_LENGEH}, 
        {"mask", mask}
    };
    delete [] tpm_rn;
    snprintf(gpu_address, ADDRESS_BUFFER, "https://%s:%d/quote", 
    global_net_config.gpu_ip.c_str(), global_net_config.gpu_port);
    auto r2 = requests::post(gpu_address, gpu_attestation_data.dump(2).c_str(), headers);
    if(r2 == NULL){
        printf("NULL!");
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    }
    try{
        printf("%d %s\r\n", r2->status_code, r2->status_message());
        // std::cout << r2->body << std::endl;
        gpu_resp = json::parse(r2->body);
        gpu_resp["status"].get_to(node_status);
        if(node_status)
            return RC_ATTEST_NODE_EXECUTE_FAIL;
    }
    catch(...){
        return RC_ATTEST_NODE_EXECUTE_FAIL;
    }

    inputfile.open("../information/system-info.json");
    json sys_info = json::parse(inputfile);
    inputfile.close();
    std::string snp_ak_cert;
    std::string tpm_ak_cert;

    node_data["ak_cert"]["snp"].get_to(snp_ak_cert);
    node_data["ak_cert"]["tpm"].get_to(tpm_ak_cert);

    json attestation_data = {
        {"ak_cert" , {
            {"snp", {
                {"ak_cert", snp_ak_cert},
                {"ak_cert_size", snp_ak_cert.length()}
                }},
            {"tpm", {
                {"ak_cert", tpm_ak_cert},
                {"ak_cert_size", tpm_ak_cert.length()}
            }}
        }},
        {"ak_pubkey" , {
            {"tpm", gpu_resp["ak_pubkey"]},
            {"snp", sys_info["ak"]}
        }},
        {"evidence" , gpu_resp["evidence"]},
        {"type" , 7},
        {"uuid" , node_data["uuid"]}
    };
    int snp_quote_size;
    char* snp_quote = file2hex("../information/attestation-report.bin", &snp_quote_size);
    std::cout << snp_quote << std::endl;
    attestation_data["evidence"]["snp"] = {
        {"quote" , snp_quote},
        {"quote_size" , snp_quote_size}
    };
    delete []snp_quote;
    // std::cout << attestation_data.dump(2) << std::endl;

    memset(as_address, 0, ADDRESS_BUFFER);
    snprintf(as_address, ADDRESS_BUFFER, "https://%s:%d/attestation/quote", global_net_config.as_ip.c_str(), global_net_config.as_port);
    json verify_resp;
    printf("send quote to as\n");
    auto r3 = requests::post(as_address, attestation_data.dump(2), headers);
    if(r3 == NULL){
        printf("NULL response when verify quote\n");
        return RC_ATTEST_CONNECT_AS_FAIL;
    }
    try{
        printf("%d %s\r\n", r3->status_code, r3->status_message());
        // std::cout << r3->body << std::endl;
        verify_resp = json::parse(r3->body);
        verify_resp["as_exec_status"].get_to(node_status);
    }
    catch(...){
        return RC_ATTEST_AS_VERIFY_FAIL;
    }

    if(node_status != RC_SUCCESS)
        return node_status;

    std::string token;
    verify_resp["token"].get_to(token);
    node_data["token"] = token;
    std::ofstream output_file("../information/nodedat.json", std::ios::out | std::ios::trunc);
    output_file << node_data.dump(2) << std::endl;
    output_file.close();

    output_file.open("/home/vonsky/dat/token");
    output_file << token << std::endl;
    output_file.close();

    return RC_SUCCESS;
}